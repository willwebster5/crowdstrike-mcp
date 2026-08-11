"""List tools must report the real total and be able to page past `limit`.

Two gaps, both surfaced by a caller reasonably asking "why are only 2 parsers
returned?" after a `limit=2` call:

1. The header rendered the FETCHED count only — "Parsers (2 results)" — which is
   indistinguishable from "there are 2 parsers". The tenant has 304. The API
   sends meta.pagination.total alongside every page and we discarded it.

2. No `offset` parameter existed, so anything past `limit` (cap 1000) was
   unreachable. Fine at 304; not fine as a contract, and it is the same shape as
   the truncation defects: a tool that quietly shows a prefix.

Verified live against US-2: offset paging reaches all 304 parsers in 4 pages,
all distinct.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

TOOLS = [
    ("ngsiem_list_saved_queries", "list_saved_queries"),
    ("ngsiem_list_lookup_files", "list_lookup_files"),
    ("ngsiem_list_dashboards", "list_dashboards"),
    ("ngsiem_list_parsers", "list_parsers"),
]


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


def _page(api, records, total):
    api.return_value = {
        "status_code": 200,
        "body": {"resources": records, "meta": {"pagination": {"total": total}}},
    }


class TestTotalIsReported:
    @pytest.mark.parametrize("tool,api_name", TOOLS, ids=[t[0] for t in TOOLS])
    def test_header_reports_the_api_total_not_just_the_page(self, ngsiem_module, tool, api_name):
        api = getattr(ngsiem_module.falcon, api_name)
        _page(api, [{"id": "a"}, {"id": "b"}], total=304)

        out = asyncio.run(getattr(ngsiem_module, tool)(limit=2))

        assert "2 returned (of 304 total)" in out

    def test_more_available_hint_gives_the_next_offset(self, ngsiem_module):
        _page(ngsiem_module.falcon.list_parsers, [{"id": f"p{i}"} for i in range(100)], total=304)
        out = asyncio.run(ngsiem_module.ngsiem_list_parsers(limit=100))
        assert "re-call with offset=100" in out

    def test_no_hint_on_the_final_page(self, ngsiem_module):
        _page(ngsiem_module.falcon.list_parsers, [{"id": f"p{i}"} for i in range(4)], total=304)
        out = asyncio.run(ngsiem_module.ngsiem_list_parsers(limit=100, offset=300))
        assert "re-call with offset" not in out

    def test_no_hint_when_everything_fits(self, ngsiem_module):
        _page(ngsiem_module.falcon.list_parsers, [{"id": "a"}], total=1)
        out = asyncio.run(ngsiem_module.ngsiem_list_parsers())
        assert "re-call with offset" not in out

    def test_falls_back_gracefully_when_the_api_omits_pagination(self, ngsiem_module):
        ngsiem_module.falcon.list_parsers.return_value = {"status_code": 200, "body": {"resources": [{"id": "a"}]}}
        out = asyncio.run(ngsiem_module.ngsiem_list_parsers())
        assert "1 result" in out
        assert "total" not in out.splitlines()[0]


class TestOffsetIsSentAndClamped:
    @pytest.mark.parametrize("tool,api_name", TOOLS, ids=[t[0] for t in TOOLS])
    def test_offset_reaches_the_wire(self, ngsiem_module, tool, api_name):
        api = getattr(ngsiem_module.falcon, api_name)
        _page(api, [], total=0)
        asyncio.run(getattr(ngsiem_module, tool)(offset=200))
        assert api.call_args.kwargs["offset"] == 200

    @pytest.mark.parametrize("tool,api_name", TOOLS, ids=[t[0] for t in TOOLS])
    def test_default_offset_is_zero(self, ngsiem_module, tool, api_name):
        api = getattr(ngsiem_module.falcon, api_name)
        _page(api, [], total=0)
        asyncio.run(getattr(ngsiem_module, tool)())
        assert api.call_args.kwargs["offset"] == 0

    def test_negative_offset_is_clamped(self, ngsiem_module):
        _page(ngsiem_module.falcon.list_parsers, [], total=0)
        asyncio.run(ngsiem_module.ngsiem_list_parsers(offset=-5))
        assert ngsiem_module.falcon.list_parsers.call_args.kwargs["offset"] == 0

    def test_offset_is_echoed_in_the_header(self, ngsiem_module):
        _page(ngsiem_module.falcon.list_parsers, [{"id": "a"}], total=304)
        out = asyncio.run(ngsiem_module.ngsiem_list_parsers(offset=200))
        assert "Offset: 200" in out
