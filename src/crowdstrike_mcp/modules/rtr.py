"""
Real-Time Response Module — read-only active-responder subset.

Tools:
  rtr_init_session                 — Open a session against a host
  rtr_list_sessions                — List session metadata for given session IDs
  rtr_pulse_session                — Keep-alive ping (resets 10-min idle timeout)
  rtr_execute_command              — Run an allowlisted active-responder command
  rtr_check_command_status         — Poll a submitted command; return stdout/stderr
  rtr_list_files                   — List files pulled via `get`
  rtr_get_extracted_file_contents  — Download a pulled file (7z, password: infected)

Safety model:
  1. Hardcoded base-command allowlist enforced at the MCP layer before every
     execute call. Env var `CROWDSTRIKE_MCP_RTR_EXTRA_ALLOWED` adds to the list;
     hard-deny verbs (cp, mv, rm, put, runscript, kill, mkdir) always reject.
  2. Every execute invocation writes a JSON line to
     ~/.config/falcon/rtr_audit.log with session_id, device_id, base_command,
     command_string, cloud_request_id, result, status_code.
  3. Admin tier (real_time_response_admin) is entirely out of scope.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Annotated, Optional

from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

try:
    from falconpy import RealTimeResponse

    RTR_AVAILABLE = True
except ImportError:
    RTR_AVAILABLE = False


# Hardcoded base-command allowlist (FR03 §Safety & Scope).
DEFAULT_ALLOWED_BASE_COMMANDS = {
    "ls",
    "ps",
    "reg query",
    "get",
    "cat",
    "env",
    "ipconfig",
    "netstat",
    "cd",
    "pwd",
    "filehash",
    "eventlog view",
    "zip",
    "mount",
    "users",
    "history",
    "memdump",
}

# Always-denied verbs (override anything added via the env var).
HARD_DENIED_BASE_COMMANDS = {
    "cp",
    "mv",
    "rm",
    "put",
    "runscript",
    "kill",
    "mkdir",
}


class RTRModule(BaseModule):
    """Real-Time Response — read-only session + command subset."""

    def __init__(self, client):
        super().__init__(client)
        if not RTR_AVAILABLE:
            raise ImportError("falconpy.RealTimeResponse not available. Ensure crowdstrike-falconpy >= 1.6.1 is installed.")

        # Load allowlist (hardcoded default + optional env-var extras, minus deny list).
        self._allowlist = self._load_allowlist()

        # Audit + download paths — tests override these on the fixture instance.
        self._audit_log_path = os.path.expanduser("~/.config/falcon/rtr_audit.log")
        self._download_dir = os.path.expanduser("~/.config/falcon/rtr_downloads")

        self._log(f"Initialized. Allowlist size: {len(self._allowlist)}")

    def register_resources(self, server: FastMCP) -> None:
        from crowdstrike_mcp.resources.fql_guides import RTR_COMMANDS_GUIDE

        def _rtr_commands_guide():
            return RTR_COMMANDS_GUIDE

        server.resource(
            "falcon://rtr/commands",
            name="RTR Command Allowlist & Usage",
            description="Documentation: allowlisted base commands and RTR triage flow",
        )(_rtr_commands_guide)
        self.resources.append("falcon://rtr/commands")

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.rtr_init_session,
            name="rtr_init_session",
            description=(
                "Open an RTR session on a host so you can run allowlisted "
                "evidence-collection commands against it. Returns a session_id "
                "needed by rtr_execute_command and friends. Sessions auto-expire "
                "after 10 minutes idle."
            ),
        )
        self._add_tool(
            server,
            self.rtr_list_sessions,
            name="rtr_list_sessions",
            description=(
                "Look up metadata for RTR session IDs you've opened "
                "(device_id, pwd, created/updated timestamps). Only returns "
                "sessions owned by the calling user."
            ),
        )
        self._add_tool(
            server,
            self.rtr_pulse_session,
            name="rtr_pulse_session",
            description=(
                "Keep an RTR session alive (resets the 10-minute idle timeout). "
                "Use during long-running triage where you're waiting on analyst "
                "review between commands."
            ),
        )
        self._add_tool(
            server,
            self.rtr_execute_command,
            name="rtr_execute_command",
            description=(
                "Run a read-only active-responder command on a host (ls, ps, "
                "reg query, get, cat, netstat, ...). Base command must be "
                "in the allowlist. See falcon://rtr/commands. Returns a "
                "cloud_request_id — poll rtr_check_command_status for output. "
                "Every invocation (including rejections) is written to "
                "~/.config/falcon/rtr_audit.log."
            ),
        )
        self._add_tool(
            server,
            self.rtr_check_command_status,
            name="rtr_check_command_status",
            description=(
                "Poll a cloud_request_id returned by rtr_execute_command until "
                "complete:true, then return stdout/stderr. RTR commands are "
                "async; first check usually returns complete:false — poll again."
            ),
        )
        self._add_tool(
            server,
            self.rtr_list_files,
            name="rtr_list_files",
            description=(
                "List files pulled into an RTR session via `get`. Returns "
                "name, sha256, and size. Pair with rtr_get_extracted_file_contents "
                "to download the 7z archive."
            ),
        )
        self._add_tool(
            server,
            self.rtr_get_extracted_file_contents,
            name="rtr_get_extracted_file_contents",
            description=(
                "Download a file pulled via `get` to a local 7z archive "
                "(saved under ~/.config/falcon/rtr_downloads/<sha256>.7z). "
                "Password: `infected`. Use rtr_list_files to find the sha256 first."
            ),
        )

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    async def rtr_init_session(
        self,
        device_id: Annotated[str, "Falcon device/agent ID to open a session on (from host_lookup)"],
        queue_offline: Annotated[bool, "If the host is offline, queue the session and run on next check-in"] = False,
    ) -> str:
        """Open an RTR session against a host so commands can be run on it."""
        result = self._init_session(device_id=device_id, queue_offline=queue_offline)
        if not result.get("success"):
            return format_text_response(f"Failed to init RTR session: {result.get('error')}", raw=True)
        s = result["session"]
        lines = [
            f"RTR session opened on {s.get('device_id', device_id)}",
            f"  session_id: {s.get('session_id', '?')}",
        ]
        if s.get("pwd"):
            lines.append(f"  pwd: {s['pwd']}")
        if s.get("created_at"):
            lines.append(f"  created_at: {s['created_at']}")
        lines.append("")
        lines.append(
            "Session auto-expires after 10 minutes idle. Use rtr_pulse_session to keep it alive; use rtr_execute_command to run allowlisted commands."
        )
        return format_text_response("\n".join(lines), raw=True)

    async def rtr_list_sessions(
        self,
        ids: Annotated[list[str], "RTR session IDs to look up (returns only sessions owned by the calling user)"],
    ) -> str:
        """List metadata for one or more RTR session IDs."""
        result = self._list_sessions(ids)
        if not result.get("success"):
            return format_text_response(f"Failed to list RTR sessions: {result.get('error')}", raw=True)
        sessions = result["sessions"]
        lines = [f"RTR Sessions: {len(sessions)} records", ""]
        if not sessions:
            lines.append("No sessions returned (ids may be unknown or owned by another user).")
        else:
            for i, s in enumerate(sessions, 1):
                lines.append(f"{i}. {s.get('id', '?')} on {s.get('device_id', '?')}")
                if s.get("pwd"):
                    lines.append(f"   pwd: {s['pwd']}")
                if s.get("created_at") or s.get("updated_at"):
                    lines.append(f"   created: {s.get('created_at', '?')} | updated: {s.get('updated_at', '?')}")
                lines.append("")
        return format_text_response("\n".join(lines), raw=True)

    async def rtr_pulse_session(
        self,
        session_id: Annotated[str, "RTR session ID to keep alive"],
    ) -> str:
        """Refresh a session's idle timeout (otherwise expires after 10 min)."""
        result = self._pulse_session(session_id)
        if not result.get("success"):
            return format_text_response(f"Failed to pulse RTR session: {result.get('error')}", raw=True)
        s = result["session"]
        return format_text_response(
            f"Session {s.get('session_id', session_id)} refreshed on {s.get('device_id', '?')}",
            raw=True,
        )

    async def rtr_execute_command(
        self,
        session_id: Annotated[str, "RTR session ID (from rtr_init_session)"],
        device_id: Annotated[str, "Device ID the session is bound to"],
        base_command: Annotated[
            str,
            "Base command (first token only). Must be in the allowlist — see falcon://rtr/commands.",
        ],
        command_string: Annotated[
            str,
            "Full command as typed. Must start with base_command. Example: 'ls C:\\\\Users'",
        ],
    ) -> str:
        """Run an allowlisted read-only active-responder command on a host."""
        # Allowlist check happens before any falconpy call; failures are still audited.
        validation_error = self._validate_command(base_command, command_string)
        if validation_error:
            self._write_audit_log(
                tool="rtr_execute_command",
                session_id=session_id,
                device_id=device_id,
                base_command=base_command,
                command_string=command_string,
                cloud_request_id=None,
                success=False,
                status_code=0,
            )
            return format_text_response(f"Failed: {validation_error}", raw=True)

        result = self._execute_command(
            session_id=session_id,
            device_id=device_id,
            base_command=base_command,
            command_string=command_string,
        )
        if not result.get("success"):
            return format_text_response(f"Failed to execute RTR command: {result.get('error')}", raw=True)
        r = result["resource"]
        lines = [
            "RTR command submitted.",
            f"  cloud_request_id: {r.get('cloud_request_id', '?')}",
            f"  session_id: {r.get('session_id', session_id)}",
        ]
        if r.get("queued_command_offline"):
            lines.append("  queued_command_offline: True (will run on next check-in)")
        lines.append("")
        lines.append("Poll rtr_check_command_status(cloud_request_id, session_id) for output.")
        return format_text_response("\n".join(lines), raw=True)

    async def rtr_check_command_status(
        self,
        cloud_request_id: Annotated[str, "Cloud request ID returned by rtr_execute_command"],
        session_id: Annotated[str, "RTR session ID the command ran in"],
    ) -> str:
        """Poll a submitted RTR command for completion + stdout/stderr."""
        result = self._check_command_status(cloud_request_id=cloud_request_id, session_id=session_id)
        if not result.get("success"):
            return format_text_response(f"Failed to check RTR command status: {result.get('error')}", raw=True)
        r = result["resource"]
        complete = bool(r.get("complete", False))
        stdout = r.get("stdout", "") or ""
        stderr = r.get("stderr", "") or ""
        header = "RTR command complete" if complete else "RTR command pending (not complete)"
        lines = [header, f"  cloud_request_id: {cloud_request_id}", ""]
        if stdout:
            lines.append("--- stdout ---")
            lines.append(stdout)
        if stderr:
            lines.append("--- stderr ---")
            lines.append(stderr)
        if not stdout and not stderr:
            lines.append("(no output yet)")
        return format_text_response(
            "\n".join(lines),
            tool_name="rtr_check_command_status",
            raw=True,
            structured_data={"resource": r},
            metadata={"cloud_request_id": cloud_request_id, "session_id": session_id},
        )

    async def rtr_list_files(
        self,
        session_id: Annotated[str, "RTR session ID"],
    ) -> str:
        """List files pulled via `get` in this session."""
        result = self._list_files(session_id)
        if not result.get("success"):
            return format_text_response(f"Failed to list RTR session files: {result.get('error')}", raw=True)
        files = result["files"]
        lines = [f"RTR Session Files: {len(files)} records", ""]
        if not files:
            lines.append("No files have been pulled in this session. Use `get <path>` first.")
        else:
            for i, f in enumerate(files, 1):
                lines.append(f"{i}. **{f.get('name', '?')}** — sha256: {f.get('sha256', '?')}")
                lines.append(f"   size: {f.get('size', '?')} | created: {f.get('created_at', '?')}")
                lines.append("")
        return format_text_response("\n".join(lines), raw=True)

    async def rtr_get_extracted_file_contents(
        self,
        session_id: Annotated[str, "RTR session ID the file was pulled in"],
        sha256: Annotated[str, "SHA256 of the pulled file (from rtr_list_files)"],
        filename: Annotated[
            Optional[str],
            "Optional filename hint passed to the API (archive-internal name)",
        ] = None,
    ) -> str:
        """Download a pulled file to a local 7z (password `infected`)."""
        result = self._get_extracted_file_contents(session_id=session_id, sha256=sha256, filename=filename)
        if not result.get("success"):
            return format_text_response(f"Failed to get extracted file contents: {result.get('error')}", raw=True)
        path = result["path"]
        size = result["size"]
        lines = [
            f"Downloaded {size} bytes to {path}",
            "",
            "The archive is a 7zip file password-protected with the password `infected` "
            "(standard CrowdStrike RTR convention). Extract with `7z x -pinfected <path>`.",
        ]
        return format_text_response("\n".join(lines), raw=True)

    # ------------------------------------------------------------------
    # Internal helpers (one per tool)
    # ------------------------------------------------------------------

    def _init_session(self, device_id: str, queue_offline: bool):
        if not device_id:
            return {"success": False, "error": "device_id is required"}
        try:
            svc = self._service(RealTimeResponse)
            r = svc.init_session(device_id=device_id, queue_offline=queue_offline)
            status = r.get("status_code", 0)
            if not (200 <= status < 300):
                return {
                    "success": False,
                    "error": format_api_error(r, "Failed to init RTR session", operation="RTR_InitSession"),
                }
            resources = r.get("body", {}).get("resources", [])
            session = resources[0] if resources else {}
            return {"success": True, "session": session}
        except Exception as e:
            return {"success": False, "error": f"Error initializing RTR session: {e}"}

    def _list_sessions(self, ids):
        if not ids:
            return {"success": False, "error": "ids list is required"}
        try:
            svc = self._service(RealTimeResponse)
            r = svc.list_sessions(ids=ids)
            if r["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(r, "Failed to list RTR sessions", operation="RTR_ListSessions"),
                }
            return {"success": True, "sessions": r.get("body", {}).get("resources", [])}
        except Exception as e:
            return {"success": False, "error": f"Error listing RTR sessions: {e}"}

    def _pulse_session(self, session_id: str):
        if not session_id:
            return {"success": False, "error": "session_id is required"}
        # Resolve device_id via list_sessions (pulse_session requires device_id).
        try:
            svc = self._service(RealTimeResponse)
            lookup = svc.list_sessions(ids=[session_id])
            if lookup["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(lookup, "Failed to look up session", operation="RTR_ListSessions"),
                }
            resources = lookup.get("body", {}).get("resources", [])
            if not resources:
                return {
                    "success": False,
                    "error": f"Session {session_id} not found (may have expired or is owned by another user)",
                }
            device_id = resources[0].get("device_id")
            if not device_id:
                return {"success": False, "error": f"Session {session_id} has no device_id"}

            r = svc.pulse_session(device_id=device_id)
            if not (200 <= r.get("status_code", 0) < 300):
                return {
                    "success": False,
                    "error": format_api_error(r, "Failed to pulse RTR session", operation="RTR_PulseSession"),
                }
            pulsed = r.get("body", {}).get("resources", [])
            return {
                "success": True,
                "session": pulsed[0] if pulsed else {"session_id": session_id, "device_id": device_id},
            }
        except Exception as e:
            return {"success": False, "error": f"Error pulsing RTR session: {e}"}

    def _execute_command(
        self,
        session_id: str,
        device_id: str,
        base_command: str,
        command_string: str,
    ):
        if not session_id or not device_id:
            return {"success": False, "error": "session_id and device_id are required"}
        try:
            svc = self._service(RealTimeResponse)
            r = svc.execute_active_responder_command(
                session_id=session_id,
                device_id=device_id,
                base_command=base_command,
                command_string=command_string,
            )
            status = r.get("status_code", 0)
            resources = r.get("body", {}).get("resources", [])
            resource = resources[0] if resources else {}
            cloud_request_id = resource.get("cloud_request_id")
            success = 200 <= status < 300
            self._write_audit_log(
                tool="rtr_execute_command",
                session_id=session_id,
                device_id=device_id,
                base_command=base_command,
                command_string=command_string,
                cloud_request_id=cloud_request_id,
                success=success,
                status_code=status,
            )
            if not success:
                return {
                    "success": False,
                    "error": format_api_error(
                        r,
                        "Failed to execute RTR command",
                        operation="RTR_ExecuteActiveResponderCommand",
                    ),
                }
            return {"success": True, "resource": resource}
        except Exception as e:
            self._write_audit_log(
                tool="rtr_execute_command",
                session_id=session_id,
                device_id=device_id,
                base_command=base_command,
                command_string=command_string,
                cloud_request_id=None,
                success=False,
                status_code=0,
            )
            return {"success": False, "error": f"Error executing RTR command: {e}"}

    def _check_command_status(self, cloud_request_id: str, session_id: str):
        if not cloud_request_id:
            return {"success": False, "error": "cloud_request_id is required"}
        if not session_id:
            return {"success": False, "error": "session_id is required"}
        try:
            svc = self._service(RealTimeResponse)
            r = svc.check_active_responder_command_status(cloud_request_id=cloud_request_id, session_id=session_id)
            if r["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(
                        r,
                        "Failed to check RTR command status",
                        operation="RTR_CheckActiveResponderCommandStatus",
                    ),
                }
            resources = r.get("body", {}).get("resources", [])
            return {"success": True, "resource": resources[0] if resources else {}}
        except Exception as e:
            return {"success": False, "error": f"Error checking RTR command status: {e}"}

    def _list_files(self, session_id: str):
        if not session_id:
            return {"success": False, "error": "session_id is required"}
        try:
            svc = self._service(RealTimeResponse)
            r = svc.list_files_v2(session_id=session_id)
            if r["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(r, "Failed to list RTR files", operation="RTR_ListFilesV2"),
                }
            return {"success": True, "files": r.get("body", {}).get("resources", [])}
        except Exception as e:
            return {"success": False, "error": f"Error listing RTR files: {e}"}

    def _get_extracted_file_contents(
        self,
        session_id: str,
        sha256: str,
        filename: Optional[str],
    ):
        if not session_id:
            return {"success": False, "error": "session_id is required"}
        if not sha256:
            return {"success": False, "error": "sha256 is required"}
        try:
            svc = self._service(RealTimeResponse)
            kwargs = {"session_id": session_id, "sha256": sha256}
            if filename:
                kwargs["filename"] = filename
            r = svc.get_extracted_file_contents(**kwargs)
            # Falconpy returns raw bytes on SUCCESS, dict on FAILURE.
            if isinstance(r, dict):
                return {
                    "success": False,
                    "error": format_api_error(
                        r,
                        "Failed to download RTR file",
                        operation="RTR_GetExtractedFileContents",
                    ),
                }
            data = bytes(r) if not isinstance(r, (bytes, bytearray)) else r
            os.makedirs(self._download_dir, exist_ok=True)
            path = os.path.join(self._download_dir, f"{sha256}.7z")
            with open(path, "wb") as f:
                f.write(data)
            return {"success": True, "path": path, "size": len(data)}
        except Exception as e:
            return {"success": False, "error": f"Error downloading RTR file: {e}"}

    # ------------------------------------------------------------------
    # Allowlist + audit helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_allowlist() -> set[str]:
        allowed = set(DEFAULT_ALLOWED_BASE_COMMANDS)
        extras_env = os.environ.get("CROWDSTRIKE_MCP_RTR_EXTRA_ALLOWED", "")
        for raw in extras_env.split(","):
            cmd = raw.strip().lower()
            if cmd:
                allowed.add(cmd)
        # Deny list always wins.
        return allowed - HARD_DENIED_BASE_COMMANDS

    def _validate_command(self, base_command: str, command_string: str) -> Optional[str]:
        """Return None if valid, else an error message."""
        bc = (base_command or "").strip().lower()
        cs = (command_string or "").strip()
        if not bc:
            return "base_command is required"
        if not cs:
            return "command_string is required"
        if bc in HARD_DENIED_BASE_COMMANDS:
            return f"base_command '{bc}' is hard-denied by this MCP"
        if bc not in self._allowlist:
            return f"base_command '{bc}' is not in the allowlist. Allowed: {sorted(self._allowlist)}"
        # command_string must start with the base_command (case-insensitive).
        if not cs.lower().startswith(bc):
            return f"command_string must start with base_command. Got base_command='{bc}', command_string='{cs}'"
        return None

    def _write_audit_log(
        self,
        tool: str,
        session_id: str,
        device_id: str,
        base_command: str,
        command_string: str,
        cloud_request_id: Optional[str],
        success: bool,
        status_code: int,
    ) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "session_id": session_id,
            "device_id": device_id,
            "base_command": base_command,
            "command_string": command_string,
            "cloud_request_id": cloud_request_id,
            "result": "success" if success else "failure",
            "api_response_code": status_code,
        }
        try:
            os.makedirs(os.path.dirname(self._audit_log_path), exist_ok=True)
            with open(self._audit_log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError as e:
            self._log(f"Failed to write audit log: {e}")
