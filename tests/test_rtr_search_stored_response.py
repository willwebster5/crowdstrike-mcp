"""Regression guard for issue #34: get_stored_response(search=) must scan the
full stdout of an RTR command stored response.

rtr_check_command_status stores its result as ``{"resource": {...}}`` where the
resource carries ``stdout`` as one (possibly large) string. select_records
resolves that wrapper to a single record and _stringify_record recurses into
every value, so a case-insensitive substring search hits the stdout contents.

The original report ("No records matching" despite the keyword being present)
traces to a pre-refactor build with the removed temp-file fallback; this test
proves the current in-memory store scans RTR stdout correctly.
"""

import asyncio
import json

import pytest

from crowdstrike_mcp.modules.response_store import ResponseStoreModule
from crowdstrike_mcp.response_store import ResponseStore


@pytest.fixture
def response_store_module(mock_client):
    return ResponseStoreModule(mock_client)


def _store_rtr_ls_output(keyword: str) -> str:
    """Store an RTR ls result whose stdout embeds *keyword*, as rtr_check_command_status does."""
    stdout = (
        "Directory listing of C:\\Users\\x\\AppData\\Local\\Temp\n"
        + "\n".join(f"  file_{i}.tmp" for i in range(50))
        + f"\n  {keyword}\\\n"
        + "\n".join(f"  file_{i}.log" for i in range(50))
    )
    resource = {
        "session_id": "sess-1",
        "cloud_request_id": "crid-1",
        "complete": True,
        "base_command": "ls",
        "stdout": stdout,
        "stderr": "",
    }
    return ResponseStore.store({"resource": resource}, tool_name="rtr_check_command_status")


class TestRTRStoredResponseSearch:
    def test_search_finds_keyword_in_rtr_stdout(self, response_store_module):
        ref_id = _store_rtr_ls_output("Popup Store")
        result = asyncio.run(response_store_module.get_stored_response(ref_id=ref_id, search="Popup Store"))
        assert "No records matching" not in result
        assert "Popup Store" in result

    def test_search_is_case_insensitive_over_rtr_stdout(self, response_store_module):
        ref_id = _store_rtr_ls_output("Popup Store")
        result = asyncio.run(response_store_module.get_stored_response(ref_id=ref_id, search="popup"))
        matches = json.loads(result.split("\n", 1)[1] if result.startswith("[Showing") else result)
        assert matches  # non-empty match list
        assert "Popup Store" in json.dumps(matches)
