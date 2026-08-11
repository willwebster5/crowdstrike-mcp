"""Regression tests for tools that dropped their tail on large responses (#52).

Reported symptom: case_get on a long-running case returned

    --- RESPONSE TRUNCATED (370,047 chars, no structured_data) ---
    Tool 'unknown' returned a response larger than 20,000 chars ...

370k characters gone with no recovery path. Because structured_data was never
passed, no resp_XXX ref existed, so get_stored_response could not page it —
and the response still *looked* successful, just missing 95% of its content.
That is worse than an error: an error routes you around it.

These tests pin the three worst offenders (unbounded record lists and full
JSON dumps) to: emit a ref, name themselves in the notice, and be readable
back through get_stored_response. Passing structured_data is not enough on its
own — a payload whose records ResponseStore cannot select mints a ref that
reads back empty, so the readback is asserted rather than the ref alone.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from crowdstrike_mcp.modules.response_store import ResponseStoreModule

# Comfortably past the 20,000-char render threshold.
LONG_DESCRIPTION = "timeline entry. " * 2000


@pytest.fixture
def store_module():
    return ResponseStoreModule(MagicMock())


@pytest.fixture
def case_module(mock_client):
    with patch("crowdstrike_mcp.modules.case_management.CaseManagement") as MockCM:
        MockCM.return_value = MagicMock()
        from crowdstrike_mcp.modules.case_management import CaseManagementModule

        return CaseManagementModule(mock_client)


@pytest.fixture
def correlation_module(mock_client):
    from crowdstrike_mcp.modules.correlation import CorrelationModule

    return CorrelationModule(mock_client)


def _ref_from(text):
    import re

    match = re.search(r"resp_\d+", text)
    assert match, f"no ref_id minted; the tail is unrecoverable:\n{text[:400]}"
    return match.group(0)


class TestCaseGet:
    def test_large_case_is_recoverable(self, case_module, store_module):
        case = {"id": "c1", "name": "Long Campaign", "status": "open", "severity": 50, "description": LONG_DESCRIPTION}
        case_module._get_cases = lambda ids: {"success": True, "count": 1, "cases": [case]}

        out = asyncio.run(case_module.case_get(case_ids=["c1"]))

        assert "no structured_data" not in out
        assert "Tool 'unknown'" not in out
        assert "case_get" in out  # the notice names the tool it came from

        back = asyncio.run(store_module.get_stored_response(ref_id=_ref_from(out), record_index=0))
        assert "Long Campaign" in back
        assert LONG_DESCRIPTION[:50] in back  # the dropped tail is actually there

    def test_small_case_is_unchanged(self, case_module):
        case_module._get_cases = lambda ids: {"success": True, "count": 1, "cases": [{"id": "c1", "name": "Small"}]}
        out = asyncio.run(case_module.case_get(case_ids=["c1"]))
        assert "Small" in out
        assert "TRUNCATED" not in out

    def test_failure_path_still_reports_the_error(self, case_module):
        case_module._get_cases = lambda ids: {"success": False, "error": "boom"}
        out = asyncio.run(case_module.case_get(case_ids=["c1"]))
        assert "Failed to get cases" in out
        assert "boom" in out


class TestCaseQuery:
    def test_large_result_set_is_recoverable(self, case_module, store_module):
        cases = [
            {
                "id": f"c{i}",
                "name": f"Case {i}",
                "status": "open",
                "severity_name": "High",
                "created_on": "t",
                "description": "d" * 300,
            }
            for i in range(200)
        ]
        case_module._query_cases = lambda **kw: {"success": True, "count": len(cases), "total_available": len(cases), "cases": cases}

        out = asyncio.run(case_module.case_query())

        assert "no structured_data" not in out
        back = asyncio.run(store_module.get_stored_response(ref_id=_ref_from(out), record_index=199))
        assert "Case 199" in back


class TestCorrelationExportRule:
    def test_large_export_is_recoverable(self, correlation_module, store_module):
        export = {"metadata": {"name": "Big Rule", "id": "r1"}, "search": {"filter": LONG_DESCRIPTION}}
        correlation_module._export_rule = lambda rid: {"success": True, "export": export}

        out = asyncio.run(correlation_module.correlation_export_rule(rule_id="r1"))

        assert "no structured_data" not in out
        back = asyncio.run(store_module.get_stored_response(ref_id=_ref_from(out), record_index=0))
        assert "Big Rule" in back
