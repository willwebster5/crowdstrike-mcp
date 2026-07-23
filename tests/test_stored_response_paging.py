"""Tests for get_stored_response size-aware paging + offset (session 2026-07-23).

A large stored slice (e.g. a 200-row groupBy) previously tripped
format_text_response's forgot-to-store guard: the tail was silently dropped and
the caller got a developer-facing message ("no structured_data", Tool 'unknown').
There was also no way to page past the first max_results rows.

get_stored_response now bounds each page to a safe byte budget, exposes an
`offset` cursor, and never routes its own output through the drop guard.
"""

import asyncio
import json
import re

import pytest

from crowdstrike_mcp.modules.response_store import ResponseStoreModule
from crowdstrike_mcp.response_store import ResponseStore


@pytest.fixture
def module(mock_client):
    return ResponseStoreModule(mock_client)


def _store_rows(n):
    rows = [{"Vendor": f"vendor{i}", "module": f"mod{i}", "dataset": f"ds{i}", "repo": f"repo{i}", "cnt": str(i)} for i in range(n)]
    return ResponseStore.store({"events": rows}, tool_name="ngsiem_query"), rows


def _body_json(out):
    """Strip a leading [page: ...] notice line if present, then parse JSON."""
    if out.startswith("[page:"):
        out = out.split("\n", 1)[1]
    return json.loads(out)


class TestNoTailDropOrLeak:
    def test_large_slice_does_not_leak_internal_guard(self, module):
        ref, _ = _store_rows(200)
        out = asyncio.run(module.get_stored_response(ref_id=ref, fields="Vendor,module,dataset,repo,cnt", max_results=200))
        assert "no structured_data" not in out
        assert "tail has been dropped" not in out
        assert "Tool 'unknown'" not in out
        assert len(out) < 20000  # stays under the large-response threshold

    def test_notice_reports_next_offset(self, module):
        ref, _ = _store_rows(200)
        out = asyncio.run(module.get_stored_response(ref_id=ref, fields="Vendor,module,dataset,repo,cnt", max_results=200))
        assert "next offset=" in out


class TestOffsetPaging:
    def test_offset_returns_later_records(self, module):
        ref, _ = _store_rows(50)
        out = asyncio.run(module.get_stored_response(ref_id=ref, fields="cnt", max_results=10, offset=10))
        page = _body_json(out)
        assert len(page) == 10
        assert page[0]["cnt"] == "10"

    def test_all_records_reachable_via_paging(self, module):
        ref, _ = _store_rows(200)
        seen, offset = [], 0
        for _ in range(100):  # safety bound
            out = asyncio.run(module.get_stored_response(ref_id=ref, fields="Vendor,module,dataset,repo,cnt", max_results=500, offset=offset))
            seen.extend(int(r["cnt"]) for r in _body_json(out))
            m = re.search(r"next offset=(\d+)", out)
            if not m:
                break
            offset = int(m.group(1))
        assert sorted(seen) == list(range(200))  # nothing dropped

    def test_offset_past_end_is_clear(self, module):
        ref, _ = _store_rows(10)
        out = asyncio.run(module.get_stored_response(ref_id=ref, fields="cnt", offset=999))
        assert "past the end" in out.lower() or _body_json(out) == []


class TestSingleRecordVerbatim:
    def test_large_single_record_returned_in_full(self, module):
        big = "A" * 30000
        ref = ResponseStore.store({"events": [{"@rawstring": big}]}, tool_name="ngsiem_query")
        out = asyncio.run(module.get_stored_response(ref_id=ref, record_index=0, fields="@rawstring"))
        assert "tail has been dropped" not in out
        assert big in out  # full value present, not dropped


class TestSearchPaging:
    def test_search_pages_with_offset(self, module):
        rows = [{"cnt": str(i), "kind": "hit"} for i in range(100)]
        ref = ResponseStore.store({"events": rows}, tool_name="ngsiem_query")
        p0 = _body_json(asyncio.run(module.get_stored_response(ref_id=ref, search="hit", max_results=10, offset=0)))
        assert len(p0) == 10 and p0[0]["cnt"] == "0"
        p1 = _body_json(asyncio.run(module.get_stored_response(ref_id=ref, search="hit", max_results=10, offset=10)))
        assert p1[0]["cnt"] == "10"


class TestExistingBehaviorPreserved:
    def test_small_result_returns_plain_json(self, module):
        ref, _ = _store_rows(3)
        out = asyncio.run(module.get_stored_response(ref_id=ref, fields="cnt"))
        # no paging notice for a complete small page
        assert not out.startswith("[page:")
        assert [r["cnt"] for r in json.loads(out)] == ["0", "1", "2"]
