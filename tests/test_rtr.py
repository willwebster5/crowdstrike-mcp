"""Tests for Real-Time Response (read-only) module."""

import asyncio
import json
import os
from unittest.mock import MagicMock, patch

import pytest


class TestRTRScopes:
    """Scope mappings for the 7 RTR operations exist in api_scopes."""

    @pytest.mark.parametrize(
        "op, scope",
        [
            ("RTR_InitSession", "real-time-response:write"),
            ("RTR_ListSessions", "real-time-response:read"),
            ("RTR_PulseSession", "real-time-response:write"),
            ("RTR_ExecuteActiveResponderCommand", "real-time-response:write"),
            ("RTR_CheckActiveResponderCommandStatus", "real-time-response:read"),
            ("RTR_GetExtractedFileContents", "real-time-response:read"),
            ("RTR_ListFilesV2", "real-time-response:read"),
        ],
    )
    def test_operation_has_expected_scope(self, op, scope):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes

        assert get_required_scopes(op) == [scope]


class TestRTRModuleImport:
    def test_module_imports(self):
        from crowdstrike_mcp.modules.rtr import RTRModule

        assert RTRModule is not None

    def test_module_uses_real_time_response(self, mock_client):
        with patch("crowdstrike_mcp.modules.rtr.RealTimeResponse") as MockRTR:
            MockRTR.return_value = MagicMock()
            from crowdstrike_mcp.modules.rtr import RTRModule

            module = RTRModule(mock_client)
            assert module is not None
            assert module.tools == []  # nothing registered yet


@pytest.fixture
def rtr_module(mock_client, tmp_path):
    """Create RTRModule with RealTimeResponse mocked. Audit log + download dir redirected to tmp."""
    with patch("crowdstrike_mcp.modules.rtr.RealTimeResponse") as MockRTR:
        mock_rtr = MagicMock()
        MockRTR.return_value = mock_rtr
        from crowdstrike_mcp.modules.rtr import RTRModule

        module = RTRModule(mock_client)
        module._service = lambda cls: mock_rtr
        module.falcon = mock_rtr
        # redirect side-effect paths into tmp so tests don't touch the real user config
        module._audit_log_path = str(tmp_path / "rtr_audit.log")
        module._download_dir = str(tmp_path / "rtr_downloads")
        return module


class TestRTRAllowlist:
    def test_default_allowlist_contains_read_only_verbs(self, rtr_module):
        for verb in ["ls", "ps", "reg query", "get", "cat", "pwd"]:
            assert verb in rtr_module._allowlist

    def test_default_allowlist_excludes_hard_denied(self, rtr_module):
        for verb in ["cp", "mv", "rm", "put", "runscript", "kill", "mkdir"]:
            assert verb not in rtr_module._allowlist

    def test_extras_env_var_adds_commands(self, mock_client, monkeypatch, tmp_path):
        monkeypatch.setenv("CROWDSTRIKE_MCP_RTR_EXTRA_ALLOWED", "tasklist, whoami")
        with patch("crowdstrike_mcp.modules.rtr.RealTimeResponse"):
            from crowdstrike_mcp.modules.rtr import RTRModule

            m = RTRModule(mock_client)
            assert "tasklist" in m._allowlist
            assert "whoami" in m._allowlist

    def test_extras_cannot_bypass_hard_deny(self, mock_client, monkeypatch):
        monkeypatch.setenv("CROWDSTRIKE_MCP_RTR_EXTRA_ALLOWED", "rm, put, runscript")
        with patch("crowdstrike_mcp.modules.rtr.RealTimeResponse"):
            from crowdstrike_mcp.modules.rtr import RTRModule

            m = RTRModule(mock_client)
            assert "rm" not in m._allowlist
            assert "put" not in m._allowlist
            assert "runscript" not in m._allowlist

    def test_validate_command_accepts_allowed(self, rtr_module):
        assert rtr_module._validate_command("ls", "ls C:\\Users") is None

    def test_validate_command_rejects_unlisted(self, rtr_module):
        err = rtr_module._validate_command("tasklist", "tasklist")
        assert err is not None
        assert "allowlist" in err.lower()

    def test_validate_command_rejects_hard_denied(self, rtr_module):
        err = rtr_module._validate_command("rm", "rm -rf /")
        assert err is not None
        assert "hard-denied" in err.lower()

    def test_validate_command_requires_matching_prefix(self, rtr_module):
        err = rtr_module._validate_command("ls", "ps aux")
        assert err is not None
        assert "start with" in err.lower()


class TestRTRGetCommand:
    """Issue #35: the RTR file-retrieval command is `get`, not `getfile`.

    `getfile` is not a real RTR base command, so the live API rejected it with
    HTTP 400 "Command not found". The allowlist must expose `get` instead.
    """

    def test_allowlist_contains_get(self, rtr_module):
        assert "get" in rtr_module._allowlist

    def test_allowlist_no_longer_contains_getfile(self, rtr_module):
        assert "getfile" not in rtr_module._allowlist

    def test_validate_command_accepts_get(self, rtr_module):
        assert rtr_module._validate_command("get", "get C:\\Users\\x\\evidence.exe") is None

    def test_validate_command_rejects_getfile(self, rtr_module):
        err = rtr_module._validate_command("getfile", "getfile C:\\Users\\x\\evidence.exe")
        assert err is not None
        assert "allowlist" in err.lower()


class TestRTRInitSession:
    def test_returns_session_id(self, rtr_module):
        rtr_module.falcon.init_session.return_value = {
            "status_code": 201,
            "body": {"resources": [{"session_id": "sess-abc", "device_id": "dev-123", "pwd": "/"}]},
        }
        result = asyncio.run(rtr_module.rtr_init_session(device_id="dev-123"))
        assert "sess-abc" in result
        assert "dev-123" in result

    def test_passes_device_id_and_queue_offline(self, rtr_module):
        rtr_module.falcon.init_session.return_value = {
            "status_code": 201,
            "body": {"resources": [{"session_id": "s", "device_id": "dev-123"}]},
        }
        asyncio.run(rtr_module.rtr_init_session(device_id="dev-123", queue_offline=True))
        rtr_module.falcon.init_session.assert_called_once_with(device_id="dev-123", queue_offline=True)

    def test_default_queue_offline_false(self, rtr_module):
        rtr_module.falcon.init_session.return_value = {
            "status_code": 201,
            "body": {"resources": [{"session_id": "s", "device_id": "dev-123"}]},
        }
        asyncio.run(rtr_module.rtr_init_session(device_id="dev-123"))
        kwargs = rtr_module.falcon.init_session.call_args.kwargs
        assert kwargs["queue_offline"] is False

    def test_requires_device_id(self, rtr_module):
        result = asyncio.run(rtr_module.rtr_init_session(device_id=""))
        assert "device_id" in result.lower()

    def test_handles_api_error(self, rtr_module):
        rtr_module.falcon.init_session.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(rtr_module.rtr_init_session(device_id="dev-123"))
        assert "failed" in result.lower()


class TestRTRListSessions:
    def test_returns_session_metadata(self, rtr_module):
        rtr_module.falcon.list_sessions.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "sess-1",
                        "device_id": "dev-1",
                        "created_at": "2026-04-20T00:00:00Z",
                        "updated_at": "2026-04-20T00:01:00Z",
                        "pwd": "C:\\Users",
                    }
                ]
            },
        }
        result = asyncio.run(rtr_module.rtr_list_sessions(ids=["sess-1"]))
        assert "sess-1" in result
        assert "dev-1" in result

    def test_passes_ids_to_falconpy(self, rtr_module):
        rtr_module.falcon.list_sessions.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(rtr_module.rtr_list_sessions(ids=["a", "b", "c"]))
        rtr_module.falcon.list_sessions.assert_called_once_with(ids=["a", "b", "c"])

    def test_requires_ids(self, rtr_module):
        result = asyncio.run(rtr_module.rtr_list_sessions(ids=[]))
        assert "ids" in result.lower()

    def test_handles_api_error(self, rtr_module):
        rtr_module.falcon.list_sessions.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "boom"}]},
        }
        result = asyncio.run(rtr_module.rtr_list_sessions(ids=["sess-1"]))
        assert "failed" in result.lower()


class TestRTRPulseSession:
    def test_pulses_session(self, rtr_module):
        rtr_module.falcon.list_sessions.return_value = {
            "status_code": 200,
            "body": {"resources": [{"id": "sess-abc", "device_id": "dev-123"}]},
        }
        rtr_module.falcon.pulse_session.return_value = {
            "status_code": 201,
            "body": {"resources": [{"session_id": "sess-abc", "device_id": "dev-123"}]},
        }
        result = asyncio.run(rtr_module.rtr_pulse_session(session_id="sess-abc"))
        assert "sess-abc" in result
        assert "refreshed" in result.lower() or "pulsed" in result.lower()

    def test_falconpy_called_with_device_id_from_session(self, rtr_module):
        # pulse_session needs device_id — we must resolve it first from the session
        rtr_module.falcon.list_sessions.return_value = {
            "status_code": 200,
            "body": {"resources": [{"id": "sess-abc", "device_id": "dev-xyz"}]},
        }
        rtr_module.falcon.pulse_session.return_value = {
            "status_code": 201,
            "body": {"resources": [{"session_id": "sess-abc", "device_id": "dev-xyz"}]},
        }
        asyncio.run(rtr_module.rtr_pulse_session(session_id="sess-abc"))
        rtr_module.falcon.pulse_session.assert_called_once_with(device_id="dev-xyz")

    def test_requires_session_id(self, rtr_module):
        result = asyncio.run(rtr_module.rtr_pulse_session(session_id=""))
        assert "session_id" in result.lower()

    def test_reports_when_session_not_found(self, rtr_module):
        rtr_module.falcon.list_sessions.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        result = asyncio.run(rtr_module.rtr_pulse_session(session_id="sess-missing"))
        assert "not found" in result.lower() or "unknown" in result.lower()

    def test_handles_pulse_api_error(self, rtr_module):
        rtr_module.falcon.list_sessions.return_value = {
            "status_code": 200,
            "body": {"resources": [{"id": "sess-abc", "device_id": "dev-1"}]},
        }
        rtr_module.falcon.pulse_session.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "boom"}]},
        }
        result = asyncio.run(rtr_module.rtr_pulse_session(session_id="sess-abc"))
        assert "failed" in result.lower()


class TestRTRExecuteCommand:
    def test_executes_allowed_command(self, rtr_module):
        rtr_module.falcon.execute_active_responder_command.return_value = {
            "status_code": 201,
            "body": {
                "resources": [
                    {
                        "cloud_request_id": "req-42",
                        "session_id": "sess-abc",
                        "queued_command_offline": False,
                    }
                ]
            },
        }
        result = asyncio.run(
            rtr_module.rtr_execute_command(
                session_id="sess-abc",
                device_id="dev-1",
                base_command="ls",
                command_string="ls C:\\Users",
            )
        )
        assert "req-42" in result
        rtr_module.falcon.execute_active_responder_command.assert_called_once()

    def test_rejects_unlisted_command_before_api_call(self, rtr_module):
        result = asyncio.run(
            rtr_module.rtr_execute_command(
                session_id="s",
                device_id="d",
                base_command="tasklist",
                command_string="tasklist",
            )
        )
        assert "allowlist" in result.lower()
        rtr_module.falcon.execute_active_responder_command.assert_not_called()

    def test_rejects_hard_denied_command(self, rtr_module):
        result = asyncio.run(
            rtr_module.rtr_execute_command(
                session_id="s",
                device_id="d",
                base_command="rm",
                command_string="rm -rf /",
            )
        )
        assert "hard-denied" in result.lower()
        rtr_module.falcon.execute_active_responder_command.assert_not_called()

    def test_rejects_when_command_string_does_not_start_with_base(self, rtr_module):
        result = asyncio.run(
            rtr_module.rtr_execute_command(
                session_id="s",
                device_id="d",
                base_command="ls",
                command_string="ps aux",
            )
        )
        assert "start with" in result.lower()
        rtr_module.falcon.execute_active_responder_command.assert_not_called()

    def test_writes_audit_log_on_success(self, rtr_module):
        rtr_module.falcon.execute_active_responder_command.return_value = {
            "status_code": 201,
            "body": {"resources": [{"cloud_request_id": "req-42", "session_id": "sess-abc"}]},
        }
        asyncio.run(
            rtr_module.rtr_execute_command(
                session_id="sess-abc",
                device_id="dev-1",
                base_command="ps",
                command_string="ps",
            )
        )
        assert os.path.exists(rtr_module._audit_log_path)
        with open(rtr_module._audit_log_path) as f:
            lines = f.readlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["tool"] == "rtr_execute_command"
        assert entry["session_id"] == "sess-abc"
        assert entry["device_id"] == "dev-1"
        assert entry["base_command"] == "ps"
        assert entry["command_string"] == "ps"
        assert entry["cloud_request_id"] == "req-42"
        assert entry["result"] == "success"
        assert entry["api_response_code"] == 201

    def test_writes_audit_log_on_allowlist_rejection(self, rtr_module):
        asyncio.run(
            rtr_module.rtr_execute_command(
                session_id="s",
                device_id="d",
                base_command="rm",
                command_string="rm file",
            )
        )
        assert os.path.exists(rtr_module._audit_log_path)
        with open(rtr_module._audit_log_path) as f:
            entry = json.loads(f.readlines()[0])
        assert entry["result"] == "failure"
        # 0 indicates the call never reached the API
        assert entry["api_response_code"] == 0

    def test_passes_all_args_to_falconpy(self, rtr_module):
        rtr_module.falcon.execute_active_responder_command.return_value = {
            "status_code": 201,
            "body": {"resources": [{"cloud_request_id": "r"}]},
        }
        asyncio.run(
            rtr_module.rtr_execute_command(
                session_id="sess-abc",
                device_id="dev-1",
                base_command="reg query",
                command_string="reg query HKLM\\Software",
            )
        )
        kwargs = rtr_module.falcon.execute_active_responder_command.call_args.kwargs
        assert kwargs["session_id"] == "sess-abc"
        assert kwargs["device_id"] == "dev-1"
        assert kwargs["base_command"] == "reg query"
        assert kwargs["command_string"] == "reg query HKLM\\Software"

    def test_api_error_is_reported_and_audited(self, rtr_module):
        rtr_module.falcon.execute_active_responder_command.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "boom"}]},
        }
        result = asyncio.run(
            rtr_module.rtr_execute_command(
                session_id="s",
                device_id="d",
                base_command="ps",
                command_string="ps",
            )
        )
        assert "failed" in result.lower()
        with open(rtr_module._audit_log_path) as f:
            entry = json.loads(f.readlines()[0])
        assert entry["result"] == "failure"
        assert entry["api_response_code"] == 500


class TestRTRCheckCommandStatus:
    def test_returns_stdout_when_complete(self, rtr_module):
        rtr_module.falcon.check_active_responder_command_status.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "complete": True,
                        "stdout": "PID   CMD\n1234  notepad.exe\n",
                        "stderr": "",
                        "task_id": "req-42",
                    }
                ]
            },
        }
        result = asyncio.run(rtr_module.rtr_check_command_status(cloud_request_id="req-42", session_id="sess-abc"))
        assert "notepad.exe" in result
        assert "complete" in result.lower()

    def test_reports_pending_when_not_complete(self, rtr_module):
        rtr_module.falcon.check_active_responder_command_status.return_value = {
            "status_code": 200,
            "body": {"resources": [{"complete": False, "stdout": "", "stderr": ""}]},
        }
        result = asyncio.run(rtr_module.rtr_check_command_status(cloud_request_id="req-42", session_id="sess-abc"))
        assert "pending" in result.lower() or "not complete" in result.lower()

    def test_surfaces_stderr_when_present(self, rtr_module):
        rtr_module.falcon.check_active_responder_command_status.return_value = {
            "status_code": 200,
            "body": {"resources": [{"complete": True, "stdout": "", "stderr": "Access denied"}]},
        }
        result = asyncio.run(rtr_module.rtr_check_command_status(cloud_request_id="req-42", session_id="sess-abc"))
        assert "Access denied" in result

    def test_requires_cloud_request_id(self, rtr_module):
        result = asyncio.run(rtr_module.rtr_check_command_status(cloud_request_id="", session_id="sess-abc"))
        assert "cloud_request_id" in result.lower()

    def test_requires_session_id(self, rtr_module):
        result = asyncio.run(rtr_module.rtr_check_command_status(cloud_request_id="req-42", session_id=""))
        assert "session_id" in result.lower()

    def test_passes_both_args(self, rtr_module):
        rtr_module.falcon.check_active_responder_command_status.return_value = {
            "status_code": 200,
            "body": {"resources": [{"complete": True, "stdout": "ok"}]},
        }
        asyncio.run(rtr_module.rtr_check_command_status(cloud_request_id="req-42", session_id="sess-abc"))
        kwargs = rtr_module.falcon.check_active_responder_command_status.call_args.kwargs
        assert kwargs["cloud_request_id"] == "req-42"
        assert kwargs["session_id"] == "sess-abc"

    def test_handles_api_error(self, rtr_module):
        rtr_module.falcon.check_active_responder_command_status.return_value = {
            "status_code": 404,
            "body": {"errors": [{"message": "Not found"}]},
        }
        result = asyncio.run(rtr_module.rtr_check_command_status(cloud_request_id="req-42", session_id="sess-abc"))
        assert "failed" in result.lower()


class TestRTRListFiles:
    def test_returns_file_list(self, rtr_module):
        rtr_module.falcon.list_files_v2.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "file-1",
                        "sha256": "abc123",
                        "name": "suspicious.exe",
                        "size": 12345,
                        "created_at": "2026-04-20T00:00:00Z",
                    }
                ]
            },
        }
        result = asyncio.run(rtr_module.rtr_list_files(session_id="sess-abc"))
        assert "suspicious.exe" in result
        assert "abc123" in result

    def test_passes_session_id(self, rtr_module):
        rtr_module.falcon.list_files_v2.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(rtr_module.rtr_list_files(session_id="sess-abc"))
        rtr_module.falcon.list_files_v2.assert_called_once_with(session_id="sess-abc")

    def test_requires_session_id(self, rtr_module):
        result = asyncio.run(rtr_module.rtr_list_files(session_id=""))
        assert "session_id" in result.lower()

    def test_handles_empty_results(self, rtr_module):
        rtr_module.falcon.list_files_v2.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        result = asyncio.run(rtr_module.rtr_list_files(session_id="sess-abc"))
        assert "no files" in result.lower() or "0" in result

    def test_handles_api_error(self, rtr_module):
        rtr_module.falcon.list_files_v2.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "boom"}]},
        }
        result = asyncio.run(rtr_module.rtr_list_files(session_id="sess-abc"))
        assert "failed" in result.lower()


class TestRTRGetExtractedFileContents:
    def test_saves_bytes_and_returns_path(self, rtr_module):
        # On success, falconpy returns raw bytes (7z archive), not a dict
        rtr_module.falcon.get_extracted_file_contents.return_value = b"\x37\x7a\xbc\xafFAKE_7Z"
        result = asyncio.run(rtr_module.rtr_get_extracted_file_contents(session_id="sess-abc", sha256="abc123"))
        expected_path = os.path.join(rtr_module._download_dir, "abc123.7z")
        assert expected_path in result
        assert os.path.exists(expected_path)
        with open(expected_path, "rb") as f:
            assert f.read().startswith(b"\x37\x7a\xbc\xaf")

    def test_passes_session_id_sha256_and_filename(self, rtr_module):
        rtr_module.falcon.get_extracted_file_contents.return_value = b"BYTES"
        asyncio.run(rtr_module.rtr_get_extracted_file_contents(session_id="sess-abc", sha256="abc", filename="evidence.exe"))
        kwargs = rtr_module.falcon.get_extracted_file_contents.call_args.kwargs
        assert kwargs["session_id"] == "sess-abc"
        assert kwargs["sha256"] == "abc"
        assert kwargs["filename"] == "evidence.exe"

    def test_requires_session_id(self, rtr_module):
        result = asyncio.run(rtr_module.rtr_get_extracted_file_contents(session_id="", sha256="abc"))
        assert "session_id" in result.lower()

    def test_requires_sha256(self, rtr_module):
        result = asyncio.run(rtr_module.rtr_get_extracted_file_contents(session_id="s", sha256=""))
        assert "sha256" in result.lower()

    def test_handles_failure_dict(self, rtr_module):
        rtr_module.falcon.get_extracted_file_contents.return_value = {
            "status_code": 404,
            "body": {"errors": [{"message": "Not found"}]},
        }
        result = asyncio.run(rtr_module.rtr_get_extracted_file_contents(session_id="sess-abc", sha256="abc"))
        assert "failed" in result.lower()

    def test_mentions_password_reminder(self, rtr_module):
        rtr_module.falcon.get_extracted_file_contents.return_value = b"7z-bytes"
        result = asyncio.run(rtr_module.rtr_get_extracted_file_contents(session_id="sess-abc", sha256="abc"))
        # Users must know the archive password to extract
        assert "infected" in result.lower()


class TestRTRToolRegistration:
    def test_all_seven_tools_register_as_read(self, rtr_module):
        server = MagicMock()
        server.tool.return_value = lambda fn: fn
        rtr_module.register_tools(server)
        expected = {
            "rtr_init_session",
            "rtr_list_sessions",
            "rtr_pulse_session",
            "rtr_execute_command",
            "rtr_check_command_status",
            "rtr_list_files",
            "rtr_get_extracted_file_contents",
        }
        assert expected.issubset(set(rtr_module.tools))


class TestRTRResources:
    def test_registers_commands_guide(self, rtr_module):
        server = MagicMock()
        server.resource.return_value = lambda fn: fn
        rtr_module.register_resources(server)
        assert "falcon://rtr/commands" in rtr_module.resources
