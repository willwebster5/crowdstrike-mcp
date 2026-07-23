"""Tests for response-store follow-up issues #28–#32.

* #28 (M1) — primary record selection: heterogeneous top-level lists are no
  longer conflated in count or indexing.
* #29 (M2) — get_stored_response surfaces a "showing N of M" notice when the
  result set is capped by max_results.
* #30 (M3) — truncation-notice building is extracted into a dedicated, testable
  helper, and the footer record-key hint is driven by a generic metadata field.
* #31 (L2) — entries expire by TTL and a session's partition can be cleared.
* #32 (L3) — single-record dict payloads count as 1 record and are indexable.
"""

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest

from crowdstrike_mcp.modules.response_store import ResponseStoreModule
from crowdstrike_mcp.response_store import (
    ResponseStore,
    build_truncation_notice,
    reset_response_session,
    set_response_session,
)
from crowdstrike_mcp.utils import LARGE_RESPONSE_THRESHOLD, format_text_response


@pytest.fixture(autouse=True)
def clean_store():
    ResponseStore._reset()
    yield
    ResponseStore._reset()


@pytest.fixture
def module(mock_client):
    return ResponseStoreModule(mock_client)


# --- #28 — primary record selection ----------------------------------------


class TestPrimaryRecordSelection:
    def test_count_ignores_secondary_lists(self):
        # ngsiem_query shape: events are records; field_projection is metadata.
        ref = ResponseStore.store(
            {"events": [{"a": 1}, {"a": 2}], "field_projection": ["a", "b", "c"]},
            tool_name="ngsiem_query",
        )
        assert ResponseStore.get(ref).record_count == 2

    def test_index_returns_record_not_secondary_list_item(self, module):
        ref = ResponseStore.store(
            {"events": [{"a": 1}, {"a": 2}], "field_projection": ["a", "b", "c"]},
            tool_name="ngsiem_query",
        )
        out = asyncio.run(module.get_stored_response(ref_id=ref, record_index=0))
        assert json.loads(out) == {"a": 1}

    def test_known_primary_key_preferred_over_id_list(self, module):
        # idp shape: investigations are records, entity_ids is a string list.
        ref = ResponseStore.store(
            {"entity_ids": ["e1", "e2", "e3"], "investigations": [{"entity": "alice"}]},
            tool_name="identity_investigate_entity",
        )
        out = asyncio.run(module.get_stored_response(ref_id=ref, record_index=0))
        assert json.loads(out) == {"entity": "alice"}


# --- #32 — single-record dict payloads -------------------------------------


class TestSingleRecordPayload:
    def test_dict_payload_counts_as_one_record(self):
        ref = ResponseStore.store({"record": {"id": "X", "name": "foo"}}, tool_name="ngsiem_get_parser")
        assert ResponseStore.get(ref).record_count == 1

    def test_dict_payload_is_indexable(self, module):
        ref = ResponseStore.store({"record": {"id": "X", "name": "foo"}}, tool_name="ngsiem_get_parser")
        out = asyncio.run(module.get_stored_response(ref_id=ref, record_index=0))
        assert json.loads(out) == {"id": "X", "name": "foo"}


# --- #29 — cap notice ------------------------------------------------------


class TestCapNotice:
    def _store_many(self, n=30):
        return ResponseStore.store({"records": [{"v": i} for i in range(n)]}, tool_name="t")

    def test_fields_capped_shows_notice(self, module):
        ref = self._store_many(30)
        out = asyncio.run(module.get_stored_response(ref_id=ref, fields="v", max_results=5))
        assert "of 30" in out
        assert "next offset=5" in out

    def test_fields_uncapped_no_notice(self, module):
        ref = self._store_many(3)
        out = asyncio.run(module.get_stored_response(ref_id=ref, fields="v", max_results=20))
        assert "of 3" not in out
        # still valid JSON when not capped
        json.loads(out)

    def test_search_capped_shows_notice(self, module):
        ref = ResponseStore.store({"records": [{"v": "match"} for _ in range(30)]}, tool_name="t")
        out = asyncio.run(module.get_stored_response(ref_id=ref, search="match", max_results=5))
        assert "of 30" in out
        assert "next offset=5" in out


# --- #31 — TTL + clear_session ---------------------------------------------


class TestTtlAndClear:
    def test_expired_entry_not_returned(self):
        ref = ResponseStore.store({"records": [{"a": 1}]}, tool_name="t")
        sr = ResponseStore.get(ref)
        assert sr is not None
        # Backdate beyond TTL.
        sr.timestamp = datetime.now(timezone.utc) - timedelta(seconds=ResponseStore._ttl_seconds + 10)
        assert ResponseStore.get(ref) is None
        assert ResponseStore.list_refs() == []

    def test_clear_session_drops_partition(self):
        ref = ResponseStore.store({"records": [{"a": 1}]}, tool_name="t")
        assert ResponseStore.get(ref) is not None
        ResponseStore.clear_session("local")  # default test session
        assert ResponseStore.get(ref) is None

    def test_evicting_stale_auth_client_clears_its_store_partition(self):
        from crowdstrike_mcp.common import session_auth

        key = "sess-xyz"
        tok = set_response_session(key)
        ResponseStore.store({"records": [{"a": 1}]}, tool_name="t")
        reset_response_session(tok)

        session_auth._client_cache[key] = (object(), 0.0)  # ts=0 → stale
        try:
            session_auth._evict_stale()
            tok = set_response_session(key)
            try:
                assert ResponseStore.list_refs() == []  # partition dropped with the auth session
            finally:
                reset_response_session(tok)
        finally:
            session_auth._client_cache.pop(key, None)


# --- #30 — extracted notice helper + generic record-key hint ----------------


class TestTruncationNoticeHelper:
    def test_helper_builds_notice_with_ref_and_hints(self):
        notice = build_truncation_notice(
            summary="SUMMARY",
            text_len=50000,
            ref_id="resp_007",
            record_count=42,
            tool_name="ngsiem_query",
            metadata={"query": "#x"},
        )
        assert "resp_007" in notice
        assert "get_stored_response" in notice
        assert "SUMMARY" in notice

    def test_generic_record_key_metadata_drives_hint(self):
        big = "x" * (LARGE_RESPONSE_THRESHOLD + 1)
        out = format_text_response(
            big,
            tool_name="ngsiem_query",
            raw=True,
            structured_data={"records": [{"id": "42"}]},
            metadata={"record_key": "42"},
        )
        assert 'record_key="42"' in out
