"""
Shared utilities for CrowdStrike MCP Server.
Credential loading, response formatting, composite ID parsing, and input sanitization.
"""

import json
import os
import re
import sys
from typing import Dict, List, Optional, Union
from urllib.parse import parse_qs, unquote, urlparse

from crowdstrike_mcp.response_store import ResponseStore, build_truncation_notice

# Large response handling
LARGE_RESPONSE_THRESHOLD = int(os.environ.get("MCP_LARGE_RESPONSE_THRESHOLD", "20000"))


# Control character pattern (everything except printable ASCII + common whitespace)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_input(value: str, max_length: int = 255) -> str:
    """Sanitize user-provided input for safe use in API calls.

    - Strips leading/trailing whitespace
    - Removes control characters (keeps newlines, tabs)
    - Strips excessive quotes
    - Truncates to *max_length* characters

    Args:
        value: Raw input string.
        max_length: Maximum allowed length (default 255).

    Returns:
        Cleaned string.
    """
    if not isinstance(value, str):
        return str(value)[:max_length]

    value = value.strip()
    value = _CONTROL_CHAR_RE.sub("", value)
    # Strip wrapping quotes (single or double) that can confuse FQL filters
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        value = value[1:-1]
    return value[:max_length]


def load_credentials(config_path: Optional[str] = None) -> Optional[Dict[str, str]]:
    """Load CrowdStrike Falcon API credentials.

    Looks for credentials at the provided path or defaults to
    ~/.config/falcon/credentials.json
    """
    if not config_path:
        config_path = os.path.expanduser("~/.config/falcon/credentials.json")

    try:
        with open(config_path, "r") as f:
            config = json.load(f)
        return config
    except Exception as e:
        print(f"Error loading credentials from {config_path}: {e}", file=sys.stderr)
        return None


def _is_large_payload(data: dict) -> bool:
    """True if structured data is big enough to warrant storing.

    Lets compact-summary tools (small text, large data — e.g. ngsiem_query) keep
    a recoverable ref while trivially small responses skip the store entirely.
    """
    try:
        return len(json.dumps(data, default=str)) > LARGE_RESPONSE_THRESHOLD
    except (TypeError, ValueError):
        return True  # unserializable → keep it rather than silently drop


def format_text_response(
    text: str,
    tool_name: str = "",
    raw: bool = False,
    structured_data: dict | None = None,
    metadata: dict | None = None,
    force_store: bool = False,
) -> Union[str, List[Dict[str, str]]]:
    """Format a text string as an MCP-compatible response.

    When ``structured_data`` is provided, the raw dict is stored in ResponseStore
    for later field-level extraction via get_stored_response, and large payloads
    are summarized with a ref_id footer.

    Args:
        text: Response text to format.
        tool_name: Tool name, used for ResponseStore bookkeeping.
        raw: If ``True``, return a plain string (for FastMCP compatibility).
             If ``False`` (default), return ``[{"type": "text", "text": ...}]``.
        structured_data: Raw structured dict from the tool (opt-in).
        metadata: Query context, filters, alert ID, etc. for the store.
        force_store: Store ``structured_data`` even when the response is small,
            so a ref_id is always available (e.g. ngsiem_query, where a 1-event
            result may still carry a long ``@rawstring`` the caller needs in full).
    """
    # Only persist when something is actually large: either the rendered text
    # (so the model can recover the truncated tail) or the structured payload
    # itself (compact-summary tools like ngsiem_query keep text small but carry
    # large data). Trivially small responses must not consume buffer slots —
    # unless the caller forces it via force_store.
    text_large = len(text) > LARGE_RESPONSE_THRESHOLD
    ref_id = None
    if structured_data is not None and (force_store or text_large or _is_large_payload(structured_data)):
        ref_id = ResponseStore.store(structured_data, tool_name, metadata)

    if not text_large:
        if ref_id:
            text = f"{text}\n\n[Structured data available: {ref_id}]"
        return text if raw else [{"type": "text", "text": text}]

    # Text exceeds threshold — prefer the structured (in-memory) path.
    summary = _extract_summary(text)
    if ref_id:
        stored = ResponseStore.get(ref_id)
        result = build_truncation_notice(
            summary=summary,
            text_len=len(text),
            ref_id=ref_id,
            record_count=stored.record_count if stored else 0,
            tool_name=tool_name,
            metadata=metadata,
        )
    else:
        # Caller didn't provide structured_data — return a summary with no disk write.
        # Large responses without structured_data are a bug in the calling tool; surface
        # it loudly so it gets fixed rather than silently spilling sensitive bytes.
        parts = [
            summary,
            "",
            f"--- RESPONSE TRUNCATED ({len(text):,} chars, no structured_data) ---",
            f"Tool '{tool_name or 'unknown'}' returned a response larger than "
            f"{LARGE_RESPONSE_THRESHOLD:,} chars without calling format_text_response "
            "with structured_data=. The tail has been dropped. Add structured_data= to "
            "the tool's format_text_response call to enable get_stored_response lookup.",
        ]
        result = "\n".join(parts)

    return result if raw else [{"type": "text", "text": result}]


def _extract_summary(text: str, max_lines: int = 40) -> str:
    """Extract a useful summary from a large MCP response.

    Keeps header/metadata lines and the first data block, truncates bulk
    event/behavior JSON that makes up the majority of large responses.
    """
    lines = text.split("\n")
    summary_lines = []
    data_blocks_seen = 0
    in_data_block = False

    for line in lines:
        # Detect start of bulk data sections
        if any(marker in line for marker in ["```json", "#### Event ", "#### Behavior "]):
            data_blocks_seen += 1
            if data_blocks_seen > 1:
                break
            # Keep the first data block marker
            in_data_block = "```json" in line

        summary_lines.append(line)

        # End of first json block
        if in_data_block and line.strip() == "```" and len(summary_lines) > 1:
            in_data_block = False

        if len(summary_lines) >= max_lines:
            break

    return "\n".join(summary_lines)


def format_error_response(error: str) -> List[Dict[str, str]]:
    """Format an error message as an MCP-compatible response list."""
    return [{"type": "text", "text": f"Error: {error}"}]


# Mapping of composite ID product prefixes to human-readable names
PRODUCT_PREFIX_MAP = {
    "ind": "endpoint",
    "ngsiem": "ngsiem",
    "fcs": "cloud_security",
    "ldt": "identity",
    "thirdparty": "thirdparty",
}

PRODUCT_DISPLAY_NAMES = {
    "endpoint": "Endpoint (EDR)",
    "ngsiem": "NG-SIEM",
    "cloud_security": "Falcon Cloud Security",
    "identity": "Identity Protection",
    "thirdparty": "Third-Party Integration",
}

# Mapping from user-friendly product filter to FQL product values
PRODUCT_FQL_MAP = {
    "endpoint": ["ind"],
    "ngsiem": ["ngsiem"],
    "cloud_security": ["fcs"],
    "identity": ["ldt"],
    "thirdparty": ["thirdparty"],
}


def extract_detection_id(raw_input: str) -> str:
    """Extract a composite detection ID from a raw string.

    Accepts:
      - Full composite ID: CID:product:sub:id
      - Falcon console URL: https://falcon.../unified-detections/CID:product:sub:id?...
      - URL with detection_id query param: ...?detection_id=CID:product:sub:id
    """
    raw_input = raw_input.strip()

    # If it looks like a URL, parse out the composite ID
    if raw_input.startswith("http://") or raw_input.startswith("https://"):
        parsed = urlparse(raw_input)

        # Check query params first (e.g., ?detection_id=...)
        params = parse_qs(parsed.query)
        if "detection_id" in params:
            return unquote(params["detection_id"][0])

        # Extract from path — composite ID is the last path segment
        # e.g., /unified-detections/CID:ngsiem:CID:alertID
        path = unquote(parsed.path).rstrip("/")
        last_segment = path.rsplit("/", 1)[-1] if "/" in path else path
        # Validate it looks like a composite ID (contains colons with known prefix)
        if ":" in last_segment:
            parts = last_segment.split(":")
            if len(parts) >= 3 and parts[1] in PRODUCT_PREFIX_MAP:
                return last_segment

    return raw_input


def parse_composite_id(composite_id: str) -> Dict[str, str]:
    """Parse a CrowdStrike composite detection ID to extract product type and trigger info.

    Composite ID formats:
      - Endpoint:       cust_id:ind:sub_id:detect_id
      - NGSIEM:         cust_id:ngsiem:cust_id:indicator_id
      - Cloud Security: cust_id:fcs:ioa-212:uuid
      - Identity:       cust_id:ldt:sub_id:detect_id
      - Third-Party:    cust_id:thirdparty:cust_id:alert_id

    Returns dict with keys: product_prefix, product_type, product_name, parts,
                            target_process_id, trigger_format
    """
    parts = composite_id.split(":")

    if len(parts) < 3:
        return {
            "product_prefix": "unknown",
            "product_type": "unknown",
            "product_name": "Unknown",
            "parts": parts,
            "target_process_id": None,
            "trigger_format": "unknown: unrecognized product type",
        }

    prefix = parts[1]
    # Handle fcs sub-types like "fcs" from "cust_id:fcs:ioa-212:uuid"
    product_type = PRODUCT_PREFIX_MAP.get(prefix, "unknown")
    product_name = PRODUCT_DISPLAY_NAMES.get(product_type, "Unknown")

    # Extract triggering process ID for endpoint (ind:) alerts.
    # Suffix format: <TargetProcessId>-<offset>-<trigger_id>
    target_process_id = None
    if product_type == "endpoint" and len(parts) >= 4:
        suffix = parts[-1]
        if suffix.count("-") >= 2:
            target_process_id = suffix.split("-")[0]
            trigger_format = "ind:suffix=<pid>-<offset>-<trigger_id>"
        else:
            trigger_format = "ind: suffix malformed — expected <pid>-<offset>-<trigger_id>"
    elif product_type == "ngsiem":
        trigger_format = "ngsiem: format unknown — investigate old alerts for pattern"
    elif product_type == "thirdparty":
        trigger_format = "thirdparty: no single triggering event concept"
    elif product_type == "cloud_security":
        trigger_format = "fcs: format unknown — investigate old alerts for pattern"
    elif product_type == "identity":
        trigger_format = "ldt: format unknown — investigate old alerts for pattern"
    else:
        trigger_format = "unknown: unrecognized product type"

    return {
        "product_prefix": prefix,
        "product_type": product_type,
        "product_name": product_name,
        "parts": parts,
        "target_process_id": target_process_id,
        "trigger_format": trigger_format,
    }
