"""
Response Store Module — structured data retrieval for truncated MCP responses.

Tools:
  get_stored_response    — Query stored structured data by ref_id with field extraction
  list_stored_responses  — List all stored response references
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Annotated, Optional

from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.response_store import ResponseStore, select_records
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

# Common key fields for record_key lookup, in priority order
_KEY_FIELDS = [
    "composite_id",
    "@id",
    "detection_id",
    "id",
    "TargetProcessId",  # endpoint behavior records (ProcessRollup2)
    "user.name",
    "UserName",
    "user_name",
    "ComputerName",
    "hostname",
    "source.ip",
]


_INDEX_RE = re.compile(r"\[(-?\d+)\]")


def _split_segment(segment: str):
    """Split a path segment into its key and any trailing ``[n]`` indices.

    ``"usernames[3]"`` -> ``("usernames", [3])``; ``"matrix[1][2]"`` ->
    ``("matrix", [1, 2])``; ``"name"`` -> ``("name", [])``.
    """
    bracket = segment.find("[")
    if bracket == -1:
        return segment, []
    key = segment[:bracket]
    indices = [int(m) for m in _INDEX_RE.findall(segment[bracket:])]
    return key, indices


def _get_nested(d: dict, dot_path: str):
    """Resolve a dotted field path against a record.

    Supports flat dotted keys (as produced by ``ngsiem_query``), nested dicts
    (as produced by ``alert_analysis``), and bracket indexing into list values:

      * First tries a literal key lookup (``d["source.ip"]``) — this handles
        CQL-style flat records where the dot is part of the key name.
      * Falls back to splitting on ``.`` and walking the nested dict, honoring
        ``[n]`` list indices on each segment (e.g. ``Ngsiem.event.usernames[3]``
        or ``events[1].name``).

    Returns ``None`` on miss (absent key or out-of-range/non-list index).
    """
    if not isinstance(d, dict):
        return None
    # Literal-key lookup first: handles flat dotted keys like "source.ip".
    if dot_path in d:
        return d[dot_path]
    # Otherwise walk the nested dict, applying any [n] indices per segment.
    current = d
    for segment in dot_path.split("."):
        key, indices = _split_segment(segment)
        if key:
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
        for idx in indices:
            if isinstance(current, list) and -len(current) <= idx < len(current):
                current = current[idx]
            else:
                return None
    return current


def _stringify_record(record) -> str:
    """Recursively stringify a record for text search."""
    if isinstance(record, dict):
        return " ".join(_stringify_record(v) for v in record.values())
    if isinstance(record, list):
        return " ".join(_stringify_record(v) for v in record)
    return str(record)


class ResponseStoreModule(BaseModule):
    """Provides tools to query stored structured data from truncated responses."""

    def __init__(self, client):
        super().__init__(client)
        self._log("Initialized")

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.get_stored_response,
            name="get_stored_response",
            description=(
                "Query stored structured data from a previous tool response. "
                "Use ref_id from truncation notices to extract fields, search records, "
                "or retrieve specific records without leaving the MCP tool loop.\n\n"
                "Field-path note: field paths differ between tools. "
                "`ngsiem_query` stores events with flat dotted keys "
                "(e.g., `source.ip`, `Vendor.userIdentity.arn`), while "
                "`alert_analysis` stores events as nested dicts under "
                "`Ngsiem.event.*` (e.g., `Ngsiem.event.source_ips`, "
                "`Ngsiem.event.usernames`). When unsure, call with "
                "`record_index=0` first to discover the schema, or call with "
                "just `ref_id` to see a metadata overview including the "
                "available top-level keys.\n\n"
                "Array indexing: a field path may index into a list value with "
                "`[n]` (0-based, negatives allowed), e.g. "
                "`Ngsiem.event.usernames[3]` or `events[0].name`.\n\n"
                "Paging: large fields/search results are returned one page at a "
                "time within a safe size budget. Each page prints a notice like "
                "`[page: records 0-41 of 200 ...; next offset=42]`; pass that "
                "`offset` to fetch the next page. Nothing is silently dropped."
            ),
        )
        self._add_tool(
            server,
            self.list_stored_responses,
            name="list_stored_responses",
            description="List all stored response references with metadata summaries.",
        )

    async def get_stored_response(
        self,
        ref_id: Annotated[str, "Reference ID from truncation notice (e.g., 'resp_001')"],
        record_index: Annotated[Optional[int], "Return specific record by 0-based index"] = None,
        record_key: Annotated[Optional[str], "Find record by natural key (scans common ID fields)"] = None,
        fields: Annotated[Optional[str], "Comma-separated dot-path fields to extract"] = None,
        search: Annotated[Optional[str], "Case-insensitive text search across record values"] = None,
        max_results: Annotated[int, "Cap returned records per page (default: 20)"] = 20,
        offset: Annotated[int, "0-based record offset for paging large results (use the 'next offset' from a page notice)"] = 0,
    ) -> str:
        """Query stored structured data by reference ID."""
        max_results = max(1, max_results)
        offset = max(0, offset)
        stored = ResponseStore.get(ref_id)
        if not stored:
            available = ResponseStore.list_refs()
            if available:
                ref_list = ", ".join(r["ref_id"] for r in available)
                return format_text_response(
                    f"Reference '{ref_id}' not found. Available: {ref_list}",
                    raw=True,
                )
            return format_text_response(
                f"Reference '{ref_id}' not found. No stored responses available.",
                raw=True,
            )

        data = stored.data
        # Single primary record collection — avoids conflating heterogeneous
        # top-level lists (e.g. ngsiem_query's events vs field_projection).
        flat = select_records(data)

        # ref_id only → metadata overview
        if record_index is None and record_key is None and fields is None and search is None:
            return format_text_response(self._format_metadata(stored), raw=True)

        # record_index → specific record
        if record_index is not None:
            if not flat:
                return format_text_response(f"No records found in {ref_id}.", raw=True)
            if record_index < 0 or record_index >= len(flat):
                return format_text_response(
                    f"Index {record_index} out of range (0-{len(flat) - 1}).",
                    raw=True,
                )
            record = flat[record_index]
            if fields:
                record = self._project_fields(record, fields)
            # A specific record is returned verbatim — even when large — so a full
            # @rawstring stays retrievable. Bypasses the large-response drop guard.
            return json.dumps(record, indent=2, default=str)

        # record_key → find by natural key
        if record_key is not None:
            match = self._find_by_key(flat, record_key)
            if match is None:
                available_keys = self._available_keys(flat[0] if flat else {})
                return format_text_response(
                    f"No record matching key '{record_key}'. Available key fields: {available_keys}",
                    raw=True,
                )
            if fields:
                match = self._project_fields(match, fields)
            return json.dumps(match, indent=2, default=str)

        # search → text search (size-aware paged)
        if search is not None:
            all_matches = [r for r in flat if search.lower() in _stringify_record(r).lower()]
            if not all_matches:
                return format_text_response(
                    f"No records matching '{search}' in {ref_id}.",
                    raw=True,
                )
            result_set = [self._project_fields(m, fields) for m in all_matches] if fields else all_matches
            return self._emit_page(result_set, offset=offset, max_results=max_results, ref_id=ref_id)

        # fields only → extract from all records (size-aware paged)
        if fields:
            projected_all = [self._project_fields(r, fields) for r in flat]
            window = projected_all[offset : offset + max_results]
            if window and self._all_projections_null(window):
                # Surface a discoverable warning instead of silently returning
                # a list of all-null dicts. Helps callers recover when field
                # paths don't match the underlying record shape (e.g., CQL
                # field names on alert_analysis-stored data).
                top_keys = self._top_level_keys(flat)
                warning_lines = [
                    "Warning: all requested fields returned null for every record.",
                    f"Requested fields: {fields}",
                    f"Available top-level keys: [{', '.join(top_keys) if top_keys else '(none)'}]",
                    "Tip: call get_stored_response(ref_id=..., record_index=0) to inspect the actual schema.",
                    "",
                    "Projected data (all nulls):",
                    json.dumps(window, indent=2, default=str),
                ]
                return "\n".join(warning_lines)
            return self._emit_page(projected_all, offset=offset, max_results=max_results, ref_id=ref_id)

        return format_text_response(self._format_metadata(stored), raw=True)

    # get_stored_response is the retrieval surface: keep each multi-record page
    # comfortably under the large-response threshold so its own output is never
    # re-truncated by format_text_response's forgot-to-store guard.
    _PAGE_BYTE_BUDGET = 15000

    @classmethod
    def _fit_page(cls, records: list, offset: int, max_results: int) -> tuple[list, int, int]:
        """Return (page, start, end): the largest prefix of records[offset:offset+max_results]
        whose serialized size stays within the page budget. Always yields at least
        one record when the window is non-empty, so a single oversized record still
        comes back rather than vanishing.
        """
        total = len(records)
        start = min(max(0, offset), total)
        window = records[start : start + max_results]
        page: list = []
        size = 2  # for the enclosing [] brackets
        for rec in window:
            rec_size = len(json.dumps(rec, indent=2, default=str)) + 2
            if page and size + rec_size > cls._PAGE_BYTE_BUDGET:
                break
            page.append(rec)
            size += rec_size
        return page, start, start + len(page)

    def _emit_page(self, records: list, *, offset: int, max_results: int, ref_id: str) -> str:
        """Render a size-bounded page of records with an actionable paging notice."""
        total = len(records)
        if offset >= total and total > 0:
            return f"[page: offset {offset} is past the end ({total} records) of {ref_id}]"
        page, start, end = self._fit_page(records, offset, max_results)
        body = json.dumps(page, indent=2, default=str)
        if start == 0 and end == total:
            return body  # complete result in one page — no notice needed
        if end < total:
            notice = f"[page: records {start}–{end - 1} of {total} in {ref_id}; next offset={end}]"
        else:
            notice = f"[page: records {start}–{end - 1} of {total} in {ref_id}; end of results]"
        return f"{notice}\n{body}"

    async def list_stored_responses(self) -> str:
        """List all stored response references."""
        refs = ResponseStore.list_refs()
        if not refs:
            return format_text_response("No stored responses.", raw=True)

        lines = ["Stored Responses:", ""]
        for r in refs:
            meta_str = ""
            if r.get("metadata"):
                meta_parts = [f"{k}={v}" for k, v in r["metadata"].items() if v]
                meta_str = f" ({', '.join(meta_parts)})" if meta_parts else ""
            lines.append(f"  {r['ref_id']}: {r['tool_name']} | {r['record_count']} records | {r['timestamp']}{meta_str}")
        return format_text_response("\n".join(lines), raw=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _top_level_keys(records: list[dict]) -> list[str]:
        """Union of top-level keys across all dict records, preserving first-seen order."""
        seen: dict[str, None] = {}
        for r in records:
            if isinstance(r, dict):
                for k in r.keys():
                    seen.setdefault(k, None)
        return list(seen.keys())

    @classmethod
    def _schema_hint(cls, records: list[dict]) -> list[str]:
        """Build a schema hint listing top-level keys and one level of nested subkeys.

        For each top-level key seen across records:
          * If its value is a dict in any record, list the subkeys as
            ``parent.child`` entries.
          * Otherwise, list just the top-level key name.

        Intended to help callers discover the actual field paths in stored data
        without needing to fetch a full record first.
        """
        top_keys = cls._top_level_keys(records)
        if not top_keys:
            return []
        # Collect nested subkeys: {parent_key: ordered-list of subkeys}
        nested: dict[str, dict[str, None]] = {k: {} for k in top_keys}
        for r in records:
            if not isinstance(r, dict):
                continue
            for k, v in r.items():
                if isinstance(v, dict):
                    for sk in v.keys():
                        nested[k].setdefault(sk, None)
        entries: list[str] = []
        for k in top_keys:
            subs = list(nested.get(k, {}).keys())
            if subs:
                entries.extend(f"{k}.{sk}" for sk in subs)
            else:
                entries.append(k)
        return entries

    @classmethod
    def _format_metadata(cls, stored) -> str:
        """Format metadata overview for a stored response."""
        lines = [
            f"Stored Response: {stored.ref_id}",
            f"Tool: {stored.tool_name}",
            f"Timestamp: {stored.timestamp.isoformat()}",
            f"Records: {stored.record_count}",
        ]
        if stored.metadata:
            for k, v in stored.metadata.items():
                if v:
                    lines.append(f"{k}: {v}")

        # Schema hint: surface discoverable field paths so callers don't have
        # to pull a full record just to learn what fields exist.
        flat_records = select_records(stored.data)
        schema_entries = cls._schema_hint(flat_records)
        if schema_entries:
            top_keys = cls._top_level_keys(flat_records)
            lines.extend(
                [
                    "",
                    f"Top-level keys: {', '.join(top_keys)}",
                    f"Available fields: {', '.join(schema_entries)}",
                ]
            )

        lines.extend(
            [
                "",
                "Use parameters to query this data:",
                f'  get_stored_response(ref_id="{stored.ref_id}", fields="field1,field2")',
                f'  get_stored_response(ref_id="{stored.ref_id}", search="keyword")',
                f'  get_stored_response(ref_id="{stored.ref_id}", record_index=0)',
            ]
        )
        return "\n".join(lines)

    @staticmethod
    def _project_fields(record: dict, fields_str: str) -> dict:
        """Extract dot-path fields from a record."""
        field_list = [f.strip() for f in fields_str.split(",") if f.strip()]
        result = {}
        for f in field_list:
            result[f] = _get_nested(record, f)
        return result

    @staticmethod
    def _all_projections_null(projections: list[dict]) -> bool:
        """Return True iff every value across every projected record is None.

        Used to decide whether to surface the all-null warning: if a field
        extraction yields only None values, the caller almost certainly used
        wrong field paths (the common case is CQL-style flat keys against
        alert_analysis-stored nested data).
        """
        if not projections:
            return False
        for proj in projections:
            if not isinstance(proj, dict):
                return False
            for v in proj.values():
                if v is not None:
                    return False
        return True

    @staticmethod
    def _find_by_key(records: list[dict], key_value: str) -> dict | None:
        """Find a record where any common key field matches the value."""
        for record in records:
            for kf in _KEY_FIELDS:
                val = _get_nested(record, kf)
                if val is not None and str(val) == key_value:
                    return record
        return None

    @staticmethod
    def _available_keys(record: dict) -> str:
        """List key fields available in a record."""
        found = []
        for kf in _KEY_FIELDS:
            val = _get_nested(record, kf)
            if val is not None:
                found.append(f"{kf}={val}")
        return ", ".join(found) if found else "(none)"
