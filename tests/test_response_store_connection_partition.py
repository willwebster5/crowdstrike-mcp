"""Per-connection partitioning of the response store.

When one user drives the hosted server from several projects at once, every
project authenticates with the *same* Falcon credentials, so a credential-only
partition collapses them into one shared store: shared 50-entry LRU budget,
shared ref_id namespace, and cross-project visibility via list_stored_responses.

These tests pin the finer-grained contract: the store partitions by
credential *and* MCP connection (the ``mcp-session-id`` header) when a stable
connection id is available, and falls back to the credential-only key for
stdio / SSE / stateless transports that have none.
"""

import asyncio
import hashlib
from unittest.mock import MagicMock

import pytest

from crowdstrike_mcp.common import session_auth
from crowdstrike_mcp.response_store import (
    ResponseStore,
    make_session_key,
    reset_response_session,
    set_response_session,
)


def _cred_key(client_id="id", secret="secret", base_url="US1") -> str:
    return hashlib.sha256(f"{client_id}:{secret}:{base_url}".encode()).hexdigest()


class TestSessionKeyDerivation:
    def test_connection_id_yields_per_connection_key(self):
        cred = _cred_key()
        key = make_session_key(cred, "conn-A")
        assert key != cred
        assert key.startswith(cred)
        assert "conn-A" in key

    def test_missing_connection_id_falls_back_to_credential_key(self):
        cred = _cred_key()
        assert make_session_key(cred, None) == cred

    def test_distinct_connections_yield_distinct_keys(self):
        cred = _cred_key()
        assert make_session_key(cred, "conn-A") != make_session_key(cred, "conn-B")


class TestConnectionIsolation:
    def test_sibling_connections_cannot_read_each_others_refs(self):
        cred = _cred_key()

        tok_a = set_response_session(make_session_key(cred, "conn-A"))
        ref_a = ResponseStore.store({"records": [{"who": "A"}]}, tool_name="t")
        reset_response_session(tok_a)

        tok_b = set_response_session(make_session_key(cred, "conn-B"))
        try:
            # Same surface ref_id (each partition counts from 1), isolated data.
            assert ref_a == "resp_001"
            assert ResponseStore.get("resp_001") is None  # B has stored nothing
            assert ResponseStore.list_refs() == []
        finally:
            reset_response_session(tok_b)

    def test_each_connection_has_its_own_ref_namespace(self):
        cred = _cred_key()

        tok_a = set_response_session(make_session_key(cred, "conn-A"))
        ResponseStore.store({"records": [{"who": "A"}]}, tool_name="t")
        reset_response_session(tok_a)

        tok_b = set_response_session(make_session_key(cred, "conn-B"))
        try:
            ref_b = ResponseStore.store({"records": [{"who": "B"}]}, tool_name="t")
            assert ref_b == "resp_001"  # counts from 1, not resp_002
            got = ResponseStore.get("resp_001")
            assert got is not None
            assert got.data == {"records": [{"who": "B"}]}
        finally:
            reset_response_session(tok_b)

    def test_lru_churn_in_one_connection_does_not_evict_a_siblings_ref(self):
        """The motivating bug: one project's high-volume churn used to evict
        another project's ref (shared 50-entry budget). Per-connection budgets
        must keep a quiet connection's ref alive under a noisy sibling."""
        cred = _cred_key()

        tok_a = set_response_session(make_session_key(cred, "conn-A"))
        ResponseStore.store({"records": [{"who": "A"}]}, tool_name="t")
        reset_response_session(tok_a)

        # Connection B stores well beyond the shared cap's worth of entries.
        tok_b = set_response_session(make_session_key(cred, "conn-B"))
        for _ in range(ResponseStore._max_entries + 20):
            ResponseStore.store({"records": [{"who": "B"}]}, tool_name="t")
        reset_response_session(tok_b)

        tok_a = set_response_session(make_session_key(cred, "conn-A"))
        try:
            survivor = ResponseStore.get("resp_001")
            assert survivor is not None  # untouched by B's churn
            assert survivor.data == {"records": [{"who": "A"}]}
        finally:
            reset_response_session(tok_a)


class TestCredentialWideCleanup:
    def test_clears_base_and_all_connection_subpartitions(self):
        cred = _cred_key()
        other = _cred_key(client_id="other")

        # Base (fallback) partition + connection sub-partitions for `cred`,
        # including a connection id that itself contains the key separator.
        conns = (None, "conn-A", "conn-B", "weird|id")
        for conn in conns:
            tok = set_response_session(make_session_key(cred, conn))
            ResponseStore.store({"records": [{"x": 1}]}, tool_name="t")
            reset_response_session(tok)

        # An unrelated credential's partition must survive.
        tok = set_response_session(other)
        ResponseStore.store({"records": [{"x": 1}]}, tool_name="t")
        reset_response_session(tok)

        ResponseStore.clear_credential_sessions(cred)

        for conn in conns:
            tok = set_response_session(make_session_key(cred, conn))
            try:
                assert ResponseStore.list_refs() == []
            finally:
                reset_response_session(tok)

        tok = set_response_session(other)
        try:
            assert len(ResponseStore.list_refs()) == 1  # untouched
        finally:
            reset_response_session(tok)


class TestMiddlewareWiring:
    """Drive the ASGI middleware and capture the store partition it binds."""

    @staticmethod
    def _scope(headers: dict[str, str]):
        return {
            "type": "http",
            "headers": [(k.encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()],
        }

    @pytest.fixture
    def patched_falcon(self, monkeypatch):
        """Stub OAuth so the middleware authenticates without network."""
        fake_cls = MagicMock()
        fake_cls.return_value.authenticate.return_value = None
        monkeypatch.setattr(session_auth, "FalconClient", fake_cls)
        session_auth._client_cache.clear()
        yield
        session_auth._client_cache.clear()

    def _run(self, headers):
        """Invoke the middleware; return the store session key bound during the request."""
        from crowdstrike_mcp import response_store as rs

        captured = {}

        async def app(scope, receive, send):
            captured["session"] = rs._session_id.get()

        async def receive():
            return {"type": "http.request"}

        async def send(msg):
            return None

        async def drive():
            mw = session_auth.session_auth_middleware(app)
            await mw(self._scope(headers), receive, send)

        asyncio.run(drive())
        return captured["session"]

    def test_binds_per_connection_partition_from_mcp_session_id(self, patched_falcon):
        creds = {
            "x-falcon-client-id": "id",
            "x-falcon-client-secret": "secret",
            "x-falcon-base-url": "US1",
        }
        cred = _cred_key()

        sess_a = self._run({**creds, "mcp-session-id": "conn-A"})
        sess_b = self._run({**creds, "mcp-session-id": "conn-B"})

        assert sess_a == make_session_key(cred, "conn-A")
        assert sess_b == make_session_key(cred, "conn-B")
        assert sess_a != sess_b

    def test_falls_back_to_credential_partition_without_session_id(self, patched_falcon):
        creds = {
            "x-falcon-client-id": "id",
            "x-falcon-client-secret": "secret",
            "x-falcon-base-url": "US1",
        }
        sess = self._run(creds)
        assert sess == _cred_key()

    def test_empty_session_id_header_falls_back_to_credential_partition(self, patched_falcon):
        creds = {
            "x-falcon-client-id": "id",
            "x-falcon-client-secret": "secret",
            "x-falcon-base-url": "US1",
        }
        sess = self._run({**creds, "mcp-session-id": ""})
        assert sess == _cred_key()
