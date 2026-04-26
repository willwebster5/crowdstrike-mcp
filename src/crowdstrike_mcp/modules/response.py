"""
Response Module — host containment actions with Tier 2 safety model.

Tools:
  host_contain           — Network-isolate a host (two-call confirmation)
  host_lift_containment  — Lift network isolation (two-call confirmation)

Safety model:
  1. Pre-flight: resolve target, check state, check exclusions
  2. Confirmation: first call returns preview, second call (confirm=True) executes
  3. Audit: every action logged to ~/.config/falcon/containment_audit.log
"""

from __future__ import annotations

import fnmatch
import json
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Annotated, Optional

from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from fastmcp import FastMCP

try:
    from falconpy import Hosts

    HOSTS_AVAILABLE = True
except ImportError:
    HOSTS_AVAILABLE = False

# Default exclusion tags — hosts with these tags cannot be contained via MCP
DEFAULT_EXCLUDED_TAGS = [
    "SensorGroupingTags/Critical-Infrastructure",
    "SensorGroupingTags/Do-Not-Contain",
]

# Default excluded hostname patterns
DEFAULT_EXCLUDED_HOSTNAME_PATTERNS = [
    "DC-*",
    "PKI-*",
    "SCCM-*",
]


class ResponseModule(BaseModule):
    """Host containment response actions with safety controls."""

    def __init__(self, client):
        super().__init__(client)
        if not HOSTS_AVAILABLE:
            raise ImportError("falconpy.Hosts not available. Ensure crowdstrike-falconpy >= 1.6.0 is installed.")

        # Audit log path
        self._audit_log_path = os.path.expanduser("~/.config/falcon/containment_audit.log")

        # Load exclusion config (falls back to defaults)
        self._exclusions = self._load_exclusions()
        self._log("Initialized")

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.host_contain,
            name="host_contain",
            description=(
                "TIER 2: Network-isolate a host. First call returns a preview "
                "with device details. Call again with confirm=True to execute. "
                "Respects do-not-contain exclusion list."
            ),
            tier="write",
        )
        self._add_tool(
            server,
            self.host_lift_containment,
            name="host_lift_containment",
            description=("TIER 2: Lift network isolation from a contained host. First call returns a preview. Call again with confirm=True to execute."),
            tier="write",
        )

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    async def host_contain(
        self,
        device_id: Annotated[str, "Device ID to contain (from host_lookup)"],
        reason: Annotated[str, "Reason for containment (logged for audit)"],
        case_id: Annotated[Optional[str], "Case ID to link this action to"] = None,
        confirm: Annotated[bool, "Must be True to execute. First call without confirm returns a preview."] = False,
    ) -> str:
        """Network-isolate a host with two-call confirmation safety model."""
        # Step 1: Resolve device
        device = self._get_device(device_id)
        if not device:
            return format_text_response(
                f"Device not found: {device_id}. Verify the device_id via host_lookup.",
                raw=True,
            )

        # Step 2: Check current state
        containment_status = device.get("containment_status", "normal")
        if containment_status == "contained":
            return format_text_response(
                f"Host {device.get('hostname', device_id)} is already contained. No action taken.",
                raw=True,
            )

        # Step 3: Check exclusions (even on preview, to fail fast)
        exclusion_reason = self._check_exclusions(device)
        if exclusion_reason:
            return format_text_response(
                f"CONTAINMENT REFUSED: {exclusion_reason}\n\n"
                f"Host: {device.get('hostname', 'Unknown')} ({device_id})\n"
                f"This host is excluded from MCP-initiated containment.\n"
                f"Use the Falcon console for manual override if necessary.",
                raw=True,
            )

        # Step 4: Preview or execute
        if not confirm:
            return format_text_response(self._format_contain_preview(device, reason, case_id), raw=True)

        # Step 5: Execute containment
        return self._execute_containment(device, "contain", reason, case_id)

    async def host_lift_containment(
        self,
        device_id: Annotated[str, "Device ID to lift containment for"],
        reason: Annotated[str, "Reason for lifting containment (logged for audit)"],
        case_id: Annotated[Optional[str], "Case ID to link this action to"] = None,
        confirm: Annotated[bool, "Must be True to execute. First call without confirm returns a preview."] = False,
    ) -> str:
        """Lift network isolation with two-call confirmation safety model."""
        # Step 1: Resolve device
        device = self._get_device(device_id)
        if not device:
            return format_text_response(
                f"Device not found: {device_id}. Verify the device_id via host_lookup.",
                raw=True,
            )

        # Step 2: Check current state
        containment_status = device.get("containment_status", "normal")
        if containment_status != "contained":
            return format_text_response(
                f"Host {device.get('hostname', device_id)} is not contained (status: {containment_status}). No action taken.",
                raw=True,
            )

        # Step 3: Preview or execute
        if not confirm:
            return format_text_response(self._format_lift_preview(device, reason, case_id), raw=True)

        # Step 4: Execute lift
        return self._execute_containment(device, "lift_containment", reason, case_id)

    # ------------------------------------------------------------------
    # Internal methods
    # ------------------------------------------------------------------

    def _get_device(self, device_id: str) -> Optional[dict]:
        """Fetch device details by ID. Returns None if not found."""
        try:
            hosts = self._service(Hosts)
            response = hosts.get_device_details(ids=[device_id])
            if response["status_code"] != 200:
                return None
            resources = response.get("body", {}).get("resources", [])
            return resources[0] if resources else None
        except Exception:
            return None

    def _check_exclusions(self, device: dict) -> Optional[str]:
        """Check if a device is excluded from containment. Returns reason or None."""
        hostname = device.get("hostname", "")
        tags = device.get("tags", [])
        device_id = device.get("device_id", "")

        # Check excluded device IDs
        excluded_ids = self._exclusions.get("excluded_device_ids", [])
        if device_id in excluded_ids:
            return f"Device ID {device_id} is in the exclusion list"

        # Check excluded hostname patterns
        for pattern in self._exclusions.get("excluded_hostname_patterns", DEFAULT_EXCLUDED_HOSTNAME_PATTERNS):
            if fnmatch.fnmatch(hostname, pattern):
                return f"Hostname '{hostname}' matches exclusion pattern '{pattern}'"

        # Check excluded tags
        excluded_tags = self._exclusions.get("excluded_tags", DEFAULT_EXCLUDED_TAGS)
        for tag in tags:
            if tag in excluded_tags:
                return f"Host has excluded tag: {tag}"

        return None

    def _format_contain_preview(self, device: dict, reason: str, case_id: Optional[str]) -> str:
        """Format the containment preview prompt."""
        hostname = device.get("hostname", "Unknown")
        device_id = device.get("device_id", "Unknown")
        platform = device.get("platform_name", "Unknown")
        os_ver = device.get("os_version", "")
        last_seen = device.get("last_seen", "Unknown")
        tags = device.get("tags", [])
        status = device.get("containment_status", "normal")

        lines = [
            "CONTAINMENT REQUEST",
            "=" * 40,
            f"Host: {hostname} ({platform} {os_ver})",
            f"Device ID: {device_id}",
            f"Last Seen: {last_seen}",
            f"Current Status: {status}",
        ]
        if tags:
            lines.append(f"Tags: {', '.join(tags)}")
        lines.append("")
        lines.append(f"Reason: {reason}")
        if case_id:
            lines.append(f"Case: {case_id}")
        lines.append("")
        lines.append(
            "This will isolate the host from all network access except "
            "CrowdStrike cloud communication. The host will remain online "
            "but unable to reach any internal or external resources."
        )
        lines.append("")
        lines.append("To proceed, call host_contain again with confirm=True.")
        return "\n".join(lines)

    def _format_lift_preview(self, device: dict, reason: str, case_id: Optional[str]) -> str:
        """Format the lift containment preview prompt."""
        hostname = device.get("hostname", "Unknown")
        device_id = device.get("device_id", "Unknown")
        platform = device.get("platform_name", "Unknown")
        last_seen = device.get("last_seen", "Unknown")
        status = device.get("containment_status", "normal")

        lines = [
            "LIFT CONTAINMENT REQUEST",
            "=" * 40,
            f"Host: {hostname} ({platform})",
            f"Device ID: {device_id}",
            f"Last Seen: {last_seen}",
            f"Current Status: {status}",
        ]
        lines.append("")
        lines.append(f"Reason: {reason}")
        if case_id:
            lines.append(f"Case: {case_id}")
        lines.append("")
        lines.append("This will restore full network access to the host. Ensure the threat has been remediated before lifting containment.")
        lines.append("")
        lines.append("To proceed, call host_lift_containment again with confirm=True.")
        return "\n".join(lines)

    def _execute_containment(self, device: dict, action_name: str, reason: str, case_id: Optional[str]) -> str:
        """Execute a containment action (contain or lift_containment)."""
        device_id = device.get("device_id", "")
        hostname = device.get("hostname", "Unknown")

        try:
            hosts = self._service(Hosts)
            response = hosts.perform_action(
                action_name=action_name,
                ids=[device_id],
            )

            status_code = response.get("status_code", 0)
            success = 200 <= status_code < 300

            # Log the action regardless of outcome
            self._write_audit_log(
                action=action_name,
                device_id=device_id,
                hostname=hostname,
                reason=reason,
                case_id=case_id,
                success=success,
                status_code=status_code,
            )

            if not success:
                error_msg = format_api_error(response, f"Failed to {action_name}", operation="perform_action")
                return format_text_response(error_msg, raw=True)

            verb = "contained" if action_name == "contain" else "containment lifted"
            lines = [
                f"Host {hostname} ({device_id}) has been {verb}.",
                f"Reason: {reason}",
            ]
            if case_id:
                lines.append(f"Case: {case_id}")
            lines.append(f"Audit entry written to: {self._audit_log_path}")
            return format_text_response("\n".join(lines), raw=True)

        except Exception as e:
            return format_text_response(f"Containment action failed: {str(e)}", raw=True)

    def _write_audit_log(
        self,
        action: str,
        device_id: str,
        hostname: str,
        reason: str,
        case_id: Optional[str],
        success: bool,
        status_code: int,
    ) -> None:
        """Append an audit entry to the containment log file."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": f"host_{action}" if not action.startswith("host_") else action,
            "action": action.replace("lift_", "lift_") if "lift" in action else action,
            "target": {
                "device_id": device_id,
                "hostname": hostname,
            },
            "reason": reason,
            "case_id": case_id,
            "result": "success" if success else "failure",
            "api_response_code": status_code,
        }

        try:
            os.makedirs(os.path.dirname(self._audit_log_path), exist_ok=True)
            with open(self._audit_log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError as e:
            self._log(f"Failed to write audit log: {e}")

    def _load_exclusions(self) -> dict:
        """Load containment exclusion config from file or return defaults."""
        config_path = os.path.expanduser("~/.config/falcon/containment_exclusions.json")
        try:
            with open(config_path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {
                "excluded_device_ids": [],
                "excluded_hostname_patterns": DEFAULT_EXCLUDED_HOSTNAME_PATTERNS,
                "excluded_tags": DEFAULT_EXCLUDED_TAGS,
            }
