"""Regression tests for CQL syntax-error passthrough (issue #51).

Root cause: LogScale returns a syntax error as HTTP 400 with a ``text/plain``
body carrying named error codes and caret markers under the offending column.
falconpy parses every body as JSON; the ``JSONDecodeError`` handler reads "not
JSON" as "no content" and substitutes its own "No content was received for this
request." string without ever touching ``response.text``. Every CQL syntax
error therefore surfaced identically and pointed at the wrong causes.

These tests pin: the raw diagnostic is recovered and preferred, the generic
remediation checklist is suppressed when a real diagnostic exists, caret
alignment survives verbatim, the happy path pays no extra round trip, and a
raced 200 does not orphan the query job it just created.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

DIAGNOSTIC = (
    "Function calls are not supported in filter expressions.\n"
    "See https://library.humio.com/... (Error: FunctionCallsNotSupportedInFilterExpressions)\n"
    ' 1: #repo="base_sensor" | NOT (in(field="x", values=["a"]))\n'
    "                               ^^"
)

# What falconpy hands us in place of the real thing.
FABRICATED = {"errors": [{"message": "No content was received for this request."}], "resources": []}


@pytest.fixture
def ngsiem_module(mock_client):
    # A bare MagicMock answers `_deferred` truthily, which makes _get_auth()
    # raise "credentials were not supplied" — the raw-recovery path swallows
    # that and returns None, so every mechanics test would pass vacuously.
    mock_client._deferred = False
    mock_client.auth_object.base_url = "https://api.us-2.crowdstrike.com"
    mock_client.auth_object.token_value = "tok"
    with patch("crowdstrike_mcp.modules.ngsiem.NGSIEM") as MockNGSIEM:
        mock_falcon = MagicMock()
        MockNGSIEM.return_value = mock_falcon
        from crowdstrike_mcp.modules.ngsiem import NGSIEMModule

        module = NGSIEMModule(mock_client)
        module._service = lambda cls: mock_falcon
        module.falcon = mock_falcon
        return module


def _reject(mock_falcon, status=400, resources=None):
    mock_falcon.start_search.return_value = {
        "status_code": status,
        "resources": FABRICATED if resources is None else resources,
    }


class TestDiagnosticRecovery:
    def test_raw_diagnostic_replaces_falconpy_fabrication(self, ngsiem_module):
        _reject(ngsiem_module.falcon)
        with patch.object(type(ngsiem_module), "_raw_start_search_error", return_value=DIAGNOSTIC):
            result = ngsiem_module._execute_query("bad |")

        assert result["success"] is False
        assert result["syntax_diagnostic"] is True
        assert "FunctionCallsNotSupportedInFilterExpressions" in result["error"]
        assert "No content was received" not in result["error"]

    def test_caret_alignment_survives_verbatim(self, ngsiem_module):
        _reject(ngsiem_module.falcon)
        with patch.object(type(ngsiem_module), "_raw_start_search_error", return_value=DIAGNOSTIC):
            out = asyncio.run(ngsiem_module.ngsiem_query(query="bad |"))

        # The caret line is aligned to source columns; any reflowing destroys it.
        assert "                               ^^" in out

    def test_generic_checklist_suppressed_when_diagnostic_present(self, ngsiem_module):
        _reject(ngsiem_module.falcon)
        with patch.object(type(ngsiem_module), "_raw_start_search_error", return_value=DIAGNOSTIC):
            out = asyncio.run(ngsiem_module.ngsiem_query(query="bad |"))

        # The checklist points at connectivity and time ranges — wrong causes,
        # and they compete with the exact answer we now have.
        assert "Time range is reasonable" not in out
        assert "Try simpler queries first" not in out
        assert "CQL syntax error" in out

    def test_generic_checklist_retained_when_no_diagnostic(self, ngsiem_module):
        _reject(ngsiem_module.falcon, resources={"errors": [{"message": "something else"}]})
        with patch.object(type(ngsiem_module), "_raw_start_search_error", return_value=None):
            out = asyncio.run(ngsiem_module.ngsiem_query(query="bad |"))

        assert "something else" in out
        assert "Try simpler queries first" in out

    def test_non_400_never_attempts_recovery(self, ngsiem_module):
        """403/500 return parseable JSON; don't pay for a duplicate round trip."""
        _reject(ngsiem_module.falcon, status=403, resources={"errors": [{"message": "access denied"}]})
        with patch.object(type(ngsiem_module), "_raw_start_search_error") as raw:
            result = ngsiem_module._execute_query("bad |")

        raw.assert_not_called()
        assert "access denied" in result["error"]

    def test_happy_path_never_attempts_recovery(self, ngsiem_module):
        ngsiem_module.falcon.start_search.return_value = {"status_code": 200, "resources": {"id": "SID-1"}}
        ngsiem_module.falcon.get_search_status.return_value = {
            "status_code": 200,
            "body": {"done": True, "cancelled": False, "events": []},
        }
        with patch.object(type(ngsiem_module), "_raw_start_search_error") as raw:
            result = ngsiem_module._execute_query("| head(1)")

        raw.assert_not_called()
        assert result["success"] is True


class TestRawRecoveryMechanics:
    def test_sends_untimestamped_query_so_line_numbers_match(self, ngsiem_module):
        """The injected '// MCP Query' audit comment shifts every line by one.

        LogScale reports the offending LINE, so sending the timestamped copy
        makes every reported line number off-by-one against what the caller
        wrote.
        """
        _reject(ngsiem_module.falcon)
        posted = {}

        def fake_post(url, **kwargs):
            posted.update(kwargs.get("json") or {})
            return MagicMock(status_code=400, text=DIAGNOSTIC)

        with patch("requests.post", side_effect=fake_post):
            ngsiem_module._execute_query('#repo="base_sensor" | head(1)')

        assert posted["queryString"] == '#repo="base_sensor" | head(1)'
        assert "MCP Query" not in posted["queryString"]

    def test_transport_failure_never_raises(self, ngsiem_module):
        """Diagnostics are best-effort — a broken bypass must not mask the verdict."""
        _reject(ngsiem_module.falcon)
        with patch("requests.post", side_effect=OSError("connection refused")):
            result = ngsiem_module._execute_query("bad |")

        assert result["success"] is False
        assert "No content was received" in result["error"]  # falls back to the parsed envelope

    def test_empty_body_falls_back_to_parsed_envelope(self, ngsiem_module):
        _reject(ngsiem_module.falcon, resources={"errors": [{"message": "parsed message"}]})
        with patch("requests.post", return_value=MagicMock(status_code=400, text="   ")):
            result = ngsiem_module._execute_query("bad |")

        assert "parsed message" in result["error"]
        assert result.get("syntax_diagnostic") is not True

    def test_raced_200_stops_the_job_it_created(self, ngsiem_module):
        """A transient failure means the bypass creates a REAL query job.

        The primary path stops the job it starts; this path must too, or the
        recovery attempt silently orphans a LogScale query job every time it
        races.
        """
        _reject(ngsiem_module.falcon)
        ok = MagicMock(status_code=200)
        ok.json.return_value = {"id": "raced-job-1"}

        with patch("requests.post", return_value=ok):
            assert ngsiem_module._raw_start_search_error("search-all", "| head(1)", {"start": "1d"}) is None

        ngsiem_module.falcon.stop_search.assert_called_once_with(repository="search-all", id="raced-job-1")

    def test_raced_200_without_parseable_id_does_not_raise(self, ngsiem_module):
        ok = MagicMock(status_code=200)
        ok.json.side_effect = ValueError("not json")

        with patch("requests.post", return_value=ok):
            assert ngsiem_module._raw_start_search_error("search-all", "| head(1)", {"start": "1d"}) is None

        ngsiem_module.falcon.stop_search.assert_not_called()

    def test_absolute_window_end_is_forwarded(self, ngsiem_module):
        posted = {}

        def fake_post(url, **kwargs):
            posted.update(kwargs.get("json") or {})
            return MagicMock(status_code=400, text=DIAGNOSTIC)

        with patch("requests.post", side_effect=fake_post):
            ngsiem_module._raw_start_search_error("search-all", "q", {"start": "100", "end": "200"})

        assert posted["start"] == "100"
        assert posted["end"] == "200"
        assert posted["isLive"] is False
