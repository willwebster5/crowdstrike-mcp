"""FalconClient must stay correct once tool calls run on real concurrent threads.

Follow-up to PR #57 (fix/blocking-io-wedges-server): offloading every tool call
onto its own worker thread (modules/base.py::_offloaded) made several pieces of
shared state genuinely concurrently-reachable for the first time. Before that
fix, the blocked event loop meant only one tool call's body ever executed at a
time, so these were all latent.
"""

import threading
import time
from unittest.mock import patch

import pytest

from crowdstrike_mcp.client import FalconClient, _ThreadSafeOAuth2


@pytest.fixture(autouse=True)
def _falcon_env(monkeypatch):
    monkeypatch.setenv("FALCON_CLIENT_ID", "i" * 32)
    monkeypatch.setenv("FALCON_CLIENT_SECRET", "s" * 40)
    monkeypatch.setenv("FALCON_BASE_URL", "US2")
    monkeypatch.delenv("FALCON_MCP_HTTP_TIMEOUT", raising=False)


class TestNonFiniteTimeoutRejected:
    """math.isfinite must catch NaN/Inf — `value <= 0` alone does not."""

    @pytest.mark.parametrize("bad", ["nan", "inf", "-inf", "Infinity"])
    def test_nan_and_inf_fall_back_to_default(self, monkeypatch, bad):
        monkeypatch.setenv("FALCON_MCP_HTTP_TIMEOUT", bad)
        timeout = FalconClient().auth_object.timeout
        assert isinstance(timeout, (int, float))
        import math

        assert math.isfinite(timeout)
        assert timeout > 0

    def test_inf_would_otherwise_reach_socket_settimeout(self):
        """Documents why this matters: settimeout(inf) doesn't degrade, it raises."""
        import socket

        s = socket.socket()
        with pytest.raises(OverflowError):
            s.settimeout(float("inf"))
        with pytest.raises(ValueError):
            s.settimeout(float("nan"))


class TestSharedAuthObjectIsThreadSafe:
    def test_auth_object_is_the_locking_subclass(self):
        auth = FalconClient().auth_object
        assert isinstance(auth, _ThreadSafeOAuth2)
        assert hasattr(auth, "_refresh_lock")

    def test_auth_headers_reentering_into_login_does_not_deadlock(self):
        """auth_headers calls self.login() internally when stale — same thread,
        same lock. A plain (non-reentrant) Lock would deadlock here."""
        auth = FalconClient().auth_object
        auth.token_expiration = 0
        auth.token_value = "stale-token"
        auth._login_handler = lambda *a, **kw: {"status_code": 201}

        result = {}

        def worker():
            result["headers"] = auth.auth_headers

        t = threading.Thread(target=worker)
        t.start()
        t.join(timeout=5)
        assert not t.is_alive(), "auth_headers -> login() reentry deadlocked"
        assert "headers" in result

    def test_concurrent_refreshes_are_serialized_not_lost(self):
        """Two threads racing a stale-token refresh must not corrupt shared state.

        Simulates falconpy's real check-then-act (token_stale -> login()) with an
        artificial delay inside the login handler so both threads are guaranteed
        to be mid-refresh at once absent the lock.
        """
        auth = FalconClient().auth_object
        auth.token_expiration = 0
        auth.token_value = "stale-token"

        call_count = {"n": 0}
        overlap_detected = {"flag": False}
        in_progress = {"flag": False}

        def slow_login_handler(*a, **kw):
            if in_progress["flag"]:
                overlap_detected["flag"] = True
            in_progress["flag"] = True
            call_count["n"] += 1
            import time

            time.sleep(0.05)
            in_progress["flag"] = False
            return {"status_code": 201}

        auth._login_handler = slow_login_handler

        threads = [threading.Thread(target=lambda: auth.auth_headers) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
            assert not t.is_alive()

        assert not overlap_detected["flag"], "two threads executed login() concurrently despite the lock"


class TestAuthObjectLazyInitIsRaceFree:
    def test_concurrent_first_access_yields_a_single_instance(self):
        """Two threads racing the very first auth_object access must not each
        construct their own OAuth2 client — the loser's would be silently
        discarded while some caller might already hold a reference to it.

        The construction itself is normally too fast for 8 threads to reliably
        interleave inside the check-then-act window in a single test run, so a
        small delay is injected into _ThreadSafeOAuth2.__init__ (patching the
        real symbol client.py calls) purely to widen that window and make the
        race deterministic — without the lock this reliably produces 8 distinct
        instances; with it, exactly 1.
        """
        client = FalconClient()
        seen = []
        barrier = threading.Barrier(8)
        real_init = _ThreadSafeOAuth2.__init__

        def slow_init(self, *a, **kw):
            time.sleep(0.02)
            real_init(self, *a, **kw)

        def worker():
            barrier.wait()
            seen.append(client.auth_object)

        with patch.object(_ThreadSafeOAuth2, "__init__", slow_init):
            threads = [threading.Thread(target=worker) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)
                assert not t.is_alive()

        assert len(seen) == 8
        assert len({id(a) for a in seen}) == 1, "concurrent first access produced more than one OAuth2 instance"
