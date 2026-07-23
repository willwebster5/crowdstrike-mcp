"""Tests for the configurable ngsiem_query inline row cap (report item #2, 2026-07-23).

Inline results were hard-capped at 10 rows, making wide/tall groupBy output hard
to read. The cap is now settable per call (display_rows) and via the
FALCON_MCP_NGSIEM_DISPLAY_ROWS env var, with a safely raised default. The full
result set remains retrievable via get_stored_response regardless.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def ngsiem_module(mock_client):
    with patch("crowdstrike_mcp.modules.ngsiem.NGSIEM") as MockNGSIEM:
        mock_falcon = MagicMock()
        MockNGSIEM.return_value = mock_falcon
        from crowdstrike_mcp.modules.ngsiem import NGSIEMModule

        module = NGSIEMModule(mock_client)
        module._service = lambda cls: mock_falcon
        module.falcon = mock_falcon
        return module


def _wire(mock_falcon, n):
    events = [{"cnt": str(i)} for i in range(n)]
    mock_falcon.start_search.return_value = {"status_code": 200, "resources": {"id": "SID-1"}}
    mock_falcon.get_search_status.return_value = {
        "status_code": 200,
        "body": {"done": True, "cancelled": False, "events": events},
    }


class TestDefaultCap:
    def test_default_shows_up_to_50_rows(self, ngsiem_module):
        _wire(ngsiem_module.falcon, 60)
        out = asyncio.run(ngsiem_module.ngsiem_query("#repo=x", max_results=1000))
        assert "#50:" in out
        assert "#51:" not in out
        assert "... and 10 more results" in out

    def test_no_more_line_when_under_cap(self, ngsiem_module):
        _wire(ngsiem_module.falcon, 5)
        out = asyncio.run(ngsiem_module.ngsiem_query("#repo=x"))
        assert "#5:" in out
        assert "more results" not in out


class TestPerCallOverride:
    def test_display_rows_limits_inline_rows(self, ngsiem_module):
        _wire(ngsiem_module.falcon, 60)
        out = asyncio.run(ngsiem_module.ngsiem_query("#repo=x", max_results=1000, display_rows=5))
        assert "#5:" in out
        assert "#6:" not in out
        assert "... and 55 more results" in out

    def test_display_rows_zero_clamps_to_at_least_one(self, ngsiem_module):
        _wire(ngsiem_module.falcon, 3)
        out = asyncio.run(ngsiem_module.ngsiem_query("#repo=x", display_rows=0))
        assert "#1:" in out
        assert "#2:" not in out


class TestEnvOverride:
    def test_env_var_sets_default(self, ngsiem_module, monkeypatch):
        monkeypatch.setenv("FALCON_MCP_NGSIEM_DISPLAY_ROWS", "3")
        _wire(ngsiem_module.falcon, 10)
        out = asyncio.run(ngsiem_module.ngsiem_query("#repo=x"))
        assert "#3:" in out
        assert "#4:" not in out
        assert "... and 7 more results" in out
