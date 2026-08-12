"""The server must survive a slow or stalled Falcon call.

Both properties here are the root cause of the 2026-08-12 report, in which a
long-lived server stopped answering *every* tool — search and non-search alike —
with no error, until the client's 30-minute idle timeout killed it.

1. A tool call must not block the asyncio event loop. Every tool is registered as
   ``async def`` but the body is synchronous falconpy/``requests`` I/O, so the
   whole call ran to completion without a single yield. One in-flight call
   therefore starved all ~60 other tools on the process, which is why a
   non-search tool (``ngsiem_list_lookup_files``) hung identically to a search
   and correctly ruled out the queryjob poll loop as the culprit.

2. Every outbound call must carry an explicit timeout. falconpy defaults to
   ``timeout=None`` — no timeout at all — so a socket that goes quiet never
   returns. Combined with (1) that turns a transient network stall into a
   permanently wedged process: the loop is never given back.
"""

import asyncio
import threading
import time
from unittest.mock import MagicMock

import pytest

from crowdstrike_mcp.client import FalconClient
from crowdstrike_mcp.modules.ngsiem import NGSIEMModule


def _blocking_ngsiem_tools(client, block_seconds: float):
    """Register NGSIEM's tools with Falcon calls that block for ``block_seconds``.

    Tools are exercised through ``register_tools`` rather than by calling the
    methods directly, because the offload is applied centrally at registration —
    that is the path the running server actually uses.
    """
    from mcp.server.fastmcp import FastMCP

    module = NGSIEMModule(client)
    api = MagicMock()
    api.start_search.return_value = {"status_code": 200, "resources": {"id": "search-1"}}

    def slow_status(**_kwargs):
        time.sleep(block_seconds)
        return {"status_code": 200, "body": {"done": True, "events": []}}

    api.get_search_status.side_effect = slow_status
    api.list_lookup_files.return_value = {"status_code": 200, "body": {"resources": [], "meta": {}}}
    module._service = lambda cls: api

    server = FastMCP("test")
    registered: dict = {}
    server.tool = lambda **kw: (lambda fn: registered.setdefault(kw["name"], fn) or fn)
    module.register_tools(server)
    return registered


class TestEventLoopStaysResponsive:
    """A slow Falcon call must not starve the rest of the server."""

    def test_a_slow_query_does_not_block_the_event_loop(self, mock_client):
        """The loop must keep scheduling other work while a query is in flight.

        Measured with a heartbeat coroutine: if the handler hogs the loop it
        cannot tick at all. Before the fix this recorded exactly 0 ticks.
        """
        tools = _blocking_ngsiem_tools(mock_client, block_seconds=0.5)

        async def scenario():
            ticks = 0
            stop = False

            async def heartbeat():
                nonlocal ticks
                while not stop:
                    ticks += 1
                    await asyncio.sleep(0.01)

            beat = asyncio.create_task(heartbeat())
            await asyncio.sleep(0.05)  # let the heartbeat establish itself
            before = ticks
            await tools["ngsiem_query"](query="head(1)", time_range="5m")
            during = ticks - before
            stop = True
            beat.cancel()
            return during

        ticks_during_query = asyncio.run(scenario())
        assert ticks_during_query > 5, (
            f"event loop was blocked for the whole query: only {ticks_during_query} "
            "heartbeat ticks fired while it ran"
        )

    def test_an_unrelated_tool_is_served_while_a_query_is_stalled(self, mock_client):
        """A stalled search must not hold up a different, trivial tool.

        This is the report's decisive observation: ``ngsiem_list_lookup_files``
        never touches queryjobs, yet it hung exactly like a search.
        """
        tools = _blocking_ngsiem_tools(mock_client, block_seconds=1.0)

        async def scenario():
            search = asyncio.create_task(tools["ngsiem_query"](query="head(1)", time_range="5m"))
            await asyncio.sleep(0.05)
            started = time.monotonic()
            await tools["ngsiem_list_lookup_files"]()
            latency = time.monotonic() - started
            await search
            return latency

        latency = asyncio.run(scenario())
        assert latency < 0.5, f"the unrelated tool waited {latency:.2f}s behind the stalled search"


class TestEveryFalconCallHasATimeout:
    """A stalled socket must raise, not hang forever."""

    def test_shared_auth_object_is_built_with_an_explicit_timeout(self, monkeypatch):
        """falconpy defaults to timeout=None; the shared client must override it."""
        monkeypatch.setenv("FALCON_CLIENT_ID", "i" * 32)
        monkeypatch.setenv("FALCON_CLIENT_SECRET", "s" * 40)
        monkeypatch.setenv("FALCON_BASE_URL", "US2")
        monkeypatch.delenv("FALCON_MCP_HTTP_TIMEOUT", raising=False)

        auth = FalconClient().auth_object
        assert auth.timeout is not None, "no timeout set — a quiet socket hangs the process forever"

    def test_the_timeout_reaches_every_service_class(self, monkeypatch):
        """Service classes are built from the shared auth object, so it must carry the timeout."""
        from falconpy import NGSIEM

        monkeypatch.setenv("FALCON_CLIENT_ID", "i" * 32)
        monkeypatch.setenv("FALCON_CLIENT_SECRET", "s" * 40)
        monkeypatch.setenv("FALCON_BASE_URL", "US2")
        monkeypatch.delenv("FALCON_MCP_HTTP_TIMEOUT", raising=False)

        auth = FalconClient().auth_object
        assert auth.timeout is not None
        assert NGSIEM(auth_object=auth).timeout == auth.timeout

    def test_the_timeout_is_operator_tunable(self, monkeypatch):
        """A long hunt must be able to raise the ceiling without a code change."""
        monkeypatch.setenv("FALCON_CLIENT_ID", "i" * 32)
        monkeypatch.setenv("FALCON_CLIENT_SECRET", "s" * 40)
        monkeypatch.setenv("FALCON_BASE_URL", "US2")
        monkeypatch.setenv("FALCON_MCP_HTTP_TIMEOUT", "42")

        assert FalconClient().auth_object.timeout == 42

    @pytest.mark.parametrize("bad", ["0", "-5", "not-a-number", ""])
    def test_a_junk_timeout_falls_back_to_the_default_rather_than_disabling_it(self, monkeypatch, bad):
        """A misconfigured knob must never resolve to 'no timeout'.

        Zero/negative/unparseable all have to degrade to the default. Letting any
        of them through as None reinstates the original bug via configuration.
        """
        monkeypatch.setenv("FALCON_CLIENT_ID", "i" * 32)
        monkeypatch.setenv("FALCON_CLIENT_SECRET", "s" * 40)
        monkeypatch.setenv("FALCON_BASE_URL", "US2")
        monkeypatch.setenv("FALCON_MCP_HTTP_TIMEOUT", bad)

        timeout = FalconClient().auth_object.timeout
        assert isinstance(timeout, (int, float)) and timeout > 0


class TestToolRegistrationOffloads:
    """The offload is applied centrally, so a new tool cannot forget it."""

    def test_registered_tools_run_off_the_event_loop(self, mock_client):
        """_add_tool must hand the server a wrapper that leaves the loop free."""
        from mcp.server.fastmcp import FastMCP

        module = NGSIEMModule(mock_client)
        server = FastMCP("test")
        registered = {}

        def capture(**kwargs):
            def decorator(fn):
                registered[kwargs["name"]] = fn
                return fn

            return decorator

        server.tool = capture

        loop_thread = None

        async def probe():
            nonlocal loop_thread
            loop_thread = threading.get_ident()

        module._add_tool(server, probe, "probe")
        assert "probe" in registered

        main_thread = threading.get_ident()
        asyncio.run(registered["probe"]())
        assert loop_thread is not None, "the registered tool never ran"
        assert loop_thread != main_thread, "the tool body ran on the event loop thread"

    def test_published_schemas_survive_the_wrapper_end_to_end(self, mock_client):
        """The offload must be invisible in the published MCP contract.

        Modules use ``from __future__ import annotations``, so FastMCP evaluates
        each annotation against ``func.__globals__`` — an attribute bound to the
        defining module that ``functools.wraps`` cannot copy. Getting this wrong
        resolves every tool's schema against ``base.py``'s namespace. It raised
        here, but the same mistake in a different shape publishes a tool with an
        empty input schema and no error at all.
        """
        from mcp.server.fastmcp import FastMCP

        from crowdstrike_mcp.registry import get_available_modules

        server = FastMCP("test")
        for module in get_available_modules(mock_client, allow_writes=True):
            module.register_tools(server)

        tools = {t.name: t for t in asyncio.run(server.list_tools())}
        assert len(tools) > 60, "modules failed to register"

        params = tools["ngsiem_query"].inputSchema.get("properties") or {}
        assert "query" in params and "time_range" in params and "max_results" in params
        assert params["query"]["type"] == "string"
        assert params["max_results"]["default"] == 100

    def test_the_wrapper_preserves_the_tool_signature(self, mock_client):
        """FastMCP builds each tool's JSON schema from the signature.

        A wrapper that swallows it into *args/**kwargs would silently publish
        every tool with an empty input schema.
        """
        import inspect

        from mcp.server.fastmcp import FastMCP

        module = NGSIEMModule(mock_client)
        server = FastMCP("test")
        registered = {}
        server.tool = lambda **kw: (lambda fn: registered.setdefault(kw["name"], fn) or fn)

        async def probe(repository: str, limit: int = 10) -> dict:
            """Docstring must survive too."""
            return {}

        module._add_tool(server, probe, "probe")
        sig = inspect.signature(registered["probe"])
        assert list(sig.parameters) == ["repository", "limit"]
        assert sig.parameters["limit"].default == 10
        assert registered["probe"].__doc__ == "Docstring must survive too."
