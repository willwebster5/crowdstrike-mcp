"""Eviction tombstones: evicted refs keep tool/metadata so errors can guide regeneration."""

from datetime import timedelta

from crowdstrike_mcp.response_store import (
    ResponseStore,
    make_session_key,
    reset_response_session,
    set_response_session,
)


def _expire(ref_id):
    """Rewind a stored entry past the TTL (test-only internal access)."""
    entry = ResponseStore._sessions["local"][ref_id]
    entry.timestamp -= timedelta(seconds=ResponseStore._ttl_seconds + 1)


class TestTtlTombstone:
    def test_ttl_expiry_leaves_tombstone(self):
        ref = ResponseStore.store({"events": [{"a": 1}]}, "ngsiem_query", {"query": "#type=x"})
        _expire(ref)
        assert ResponseStore.get(ref) is None
        tomb = ResponseStore.get_tombstone(ref)
        assert tomb["reason"] == "ttl"
        assert tomb["tool_name"] == "ngsiem_query"
        assert tomb["metadata"] == {"query": "#type=x"}
        assert tomb["evicted_at"] is not None


class TestLruTombstone:
    def test_lru_displacement_leaves_tombstone(self):
        first = ResponseStore.store({"events": []}, "get_alerts", {"filter": "f"})
        for _ in range(ResponseStore._max_entries):
            ResponseStore.store({"events": []}, "ngsiem_query", {})
        assert ResponseStore.get(first) is None
        tomb = ResponseStore.get_tombstone(first)
        assert tomb["reason"] == "lru"
        assert tomb["tool_name"] == "get_alerts"


class TestTombstoneLifecycle:
    def test_unknown_ref_has_no_tombstone(self):
        assert ResponseStore.get_tombstone("resp_999") is None

    def test_live_ref_has_no_tombstone(self):
        ref = ResponseStore.store({"events": []}, "ngsiem_query", {})
        assert ResponseStore.get_tombstone(ref) is None

    def test_cap_drops_oldest_tombstones(self):
        refs = []
        for _ in range(ResponseStore._tombstone_cap + 10 + ResponseStore._max_entries):
            refs.append(ResponseStore.store({"events": []}, "ngsiem_query", {}))
        evicted = refs[: -ResponseStore._max_entries]
        capped_out = evicted[: -ResponseStore._tombstone_cap]
        kept = evicted[-ResponseStore._tombstone_cap :]
        assert all(ResponseStore.get_tombstone(r) is None for r in capped_out)
        assert all(ResponseStore.get_tombstone(r) is not None for r in kept)

    def test_clear_session_wipes_tombstones(self):
        token = set_response_session("cred123")
        try:
            ref = ResponseStore.store({"events": []}, "ngsiem_query", {})
            _entry = ResponseStore._sessions["cred123"][ref]
            _entry.timestamp -= timedelta(seconds=ResponseStore._ttl_seconds + 1)
            ResponseStore.get(ref)  # trigger TTL tombstone
            assert ResponseStore.get_tombstone(ref) is not None
            ResponseStore.clear_session("cred123")
            assert ResponseStore.get_tombstone(ref) is None
        finally:
            reset_response_session(token)

    def test_clear_credential_sessions_wipes_connection_tombstones(self):
        sk = make_session_key("cred456", "conn-1")
        token = set_response_session(sk)
        try:
            ref = ResponseStore.store({"events": []}, "ngsiem_query", {})
            entry = ResponseStore._sessions[sk][ref]
            entry.timestamp -= timedelta(seconds=ResponseStore._ttl_seconds + 1)
            ResponseStore.get(ref)
            assert ResponseStore.get_tombstone(ref) is not None
            ResponseStore.clear_credential_sessions("cred456")
            assert ResponseStore.get_tombstone(ref) is None
        finally:
            reset_response_session(token)
