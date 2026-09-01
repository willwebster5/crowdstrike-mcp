"""
BaseModule — abstract base class for all MCP tool modules.

Each module:
  - Receives a shared ``FalconClient`` instance
  - Registers its tools (and optionally resources) with a FastMCP server
  - Creates FalconPy service classes using ``self.client.auth_object``
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import sys
import weakref
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from typing import TYPE_CHECKING, Callable

from mcp.types import ToolAnnotations

from crowdstrike_mcp.utils import resolve_env_number

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from crowdstrike_mcp.client import FalconClient

_VALID_TIERS = {"read", "write"}

# Per-session FalconClient for HTTP transports. Set by session_auth_middleware.
# Each asyncio task gets its own context copy, so concurrent requests are isolated.
# Canonical location — common/session_auth.py imports this.
_session_client: ContextVar["FalconClient | None"] = ContextVar("_session_client", default=None)

# asyncio.to_thread submits offloaded tool calls to the running loop's default
# executor, which Python creates lazily as ThreadPoolExecutor(max_workers=
# min(32, os.cpu_count()+4)) — as few as ~9 threads in a constrained container.
# NGSIEM searches (and other long-running tools) hold their worker for their
# entire runtime, so a burst of concurrent long-running calls at the scale the
# field report reproduced this bug with (~137 concurrent subagents) can
# exhaust that default pool and queue new calls behind it with no visible
# signal distinguishing "queued" from "the Falcon API is just slow" — a
# smaller-scale reprise of the exact wedge this offload exists to prevent.
DEFAULT_TOOL_THREADS = 64

# Loops we've already sized, not a bare process-global flag: a flag would
# incorrectly no-op for a second, independent event loop in the same process
# (e.g. an embedder or test harness that calls into the tool-offload path
# across more than one loop), silently leaving that loop with asyncio's small
# stdlib default and no signal that happened. Weak so a closed loop's entry
# doesn't outlive it. No lock: this is only ever called from a coroutine
# running on the one event-loop thread that owns the loop being sized —
# never from a raw OS thread — so there is no concurrent caller to race.
_sized_loops: "weakref.WeakSet[asyncio.AbstractEventLoop]" = weakref.WeakSet()


def _ensure_tool_executor() -> None:
    """Give the running event loop a generously-sized default executor.

    ``loop.set_default_executor`` needs a running event loop, which doesn't
    exist yet at module import / server construction time, so this runs
    lazily from inside the first offloaded tool call on that loop instead.
    """
    loop = asyncio.get_running_loop()
    if loop in _sized_loops:
        return
    max_workers = int(resolve_env_number("FALCON_MCP_TOOL_THREADS", DEFAULT_TOOL_THREADS, min_value=1, log_prefix="[BaseModule] "))
    loop.set_default_executor(ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="falcon-tool"))
    _sized_loops.add(loop)


def _offloaded(method: Callable) -> Callable:
    """Wrap a tool so its body runs off the asyncio event loop.

    Every tool is declared ``async def``, but the bodies are synchronous falconpy
    calls — falconpy is built on ``requests`` — plus, in the NGSIEM search path, a
    ``time.sleep()`` poll loop. None of that yields. A coroutine that never awaits
    holds the event loop from its first statement to its last, so a single
    in-flight call starved every other tool on the process: concurrent calls did
    not merely queue, they could not start.

    That is what made one stalled Falcon request look like a dead server. The
    giveaway in the field report was that ``ngsiem_list_lookup_files`` — which
    never touches queryjobs — hung exactly like a search, which is only possible
    if the two share something. What they share is this loop.

    Offloading is applied here, at the single registration seam, rather than in
    ~60 individual handlers, so a tool added later cannot forget it.

    The signature is preserved deliberately: FastMCP derives each tool's JSON
    input schema from it, so a wrapper that collapsed it into ``**kwargs`` would
    publish every tool with an empty schema. See ``_resolved_signature`` for why
    ``functools.wraps`` alone is not enough here.

    ``asyncio.to_thread`` copies the current context into the worker, so the
    ``_session_client`` ContextVar that HTTP mode sets per request still resolves
    correctly inside the thread.

    Known limitation — cancellation is best-effort, not real: a client
    ``notifications/cancelled`` now reaches this Task and unblocks the caller
    immediately (impossible before this wrapper existed, since the loop itself
    was the thing blocked), but ``concurrent.futures.Future.cancel()`` is a
    no-op once its work item has started running — Python cannot forcibly stop
    a running thread. The underlying falconpy call keeps executing in the
    background until it finishes or its own timeout fires
    (``FALCON_MCP_HTTP_TIMEOUT`` / ``FALCON_MCP_NGSIEM_TIMEOUT``); its result is
    then discarded. This also means there is currently no path for a tool to
    report MCP progress mid-call: the body runs inside a throwaway event loop
    on a worker thread, disconnected from the session/transport loop a
    ``Context`` would report through. Both are accepted tradeoffs of offloading
    to a thread rather than rewriting falconpy's call path onto an async HTTP
    client — fixing them for real needs that rewrite, not a deeper wrapper here.
    """
    if inspect.iscoroutinefunction(method):

        @functools.wraps(method)
        async def wrapper(*args, **kwargs):
            _ensure_tool_executor()
            # The coroutine is created here but driven to completion by a fresh
            # loop inside the worker thread, leaving the server's own loop free.
            return await asyncio.to_thread(asyncio.run, method(*args, **kwargs))

    else:

        @functools.wraps(method)
        async def wrapper(*args, **kwargs):
            _ensure_tool_executor()
            return await asyncio.to_thread(functools.partial(method, *args, **kwargs))

    wrapper.__signature__ = _resolved_signature(method)
    return wrapper


def _resolved_signature(method: Callable) -> inspect.Signature:
    """Return ``method``'s signature with its annotations already evaluated.

    Modules use ``from __future__ import annotations``, so every annotation
    reaches FastMCP as a string. FastMCP evaluates those strings against
    ``func.__globals__`` — and ``__globals__`` is a read-only attribute bound to
    the module a function was *defined* in, which ``functools.wraps`` cannot
    copy. A wrapper defined here would therefore have its tool schema resolved
    against ``base.py``'s namespace, where ``Annotated`` and the modules' own
    types do not exist.

    Evaluating the annotations here, while we still hold the original function
    and can reach its real globals, sidesteps that: FastMCP then receives
    concrete type objects with nothing left to resolve.

    Failure is raised, not swallowed. Registration happens at startup, so a
    broken annotation surfaces immediately and loudly; degrading to an
    unresolved signature would instead publish a tool whose input schema is
    silently wrong.
    """
    try:
        return inspect.signature(method, eval_str=True)
    except Exception as exc:  # pragma: no cover - a startup-time programming error
        raise RuntimeError(
            f"Could not resolve type annotations for tool {getattr(method, '__qualname__', method)!r}. "
            "The MCP input schema would be published incorrectly."
        ) from exc


class BaseModule(ABC):
    """Abstract base class for CrowdStrike MCP modules."""

    def __init__(self, client: FalconClient):
        self.client = client
        self.tools: list[str] = []
        self.resources: list[str] = []
        self.allow_writes: bool = False

    @abstractmethod
    def register_tools(self, server: FastMCP) -> None:
        """Register this module's tools with the FastMCP server.

        Subclasses must implement this to add their tools via ``_add_tool()``.
        """
        ...

    def register_resources(self, server: FastMCP) -> None:
        """Register this module's MCP resources (optional).

        Override in subclasses that expose FQL guides or other resources.
        """

    def _get_auth(self):
        """Get auth object — session-scoped (HTTP) or instance-level (stdio).

        In HTTP mode, session_auth_middleware sets _session_client ContextVar
        per-request. In stdio mode, the ContextVar is unset and we fall back
        to the instance-level client passed at construction.

        In HTTP mode an unauthenticated request reaches the app with the
        ContextVar unset (the handshake needs no credentials). Reaching here in
        that state means a tool was actually invoked, so fail with a message the
        caller can act on.
        """
        session = _session_client.get()
        if session is not None:
            return session.auth_object
        if getattr(self.client, "_deferred", False):
            raise RuntimeError(
                "CrowdStrike credentials were not supplied for this session. Send "
                "X-Falcon-Client-Id and X-Falcon-Client-Secret headers, or configure "
                "FALCON_CLIENT_ID and FALCON_CLIENT_SECRET in your client's connection settings."
            )
        return self.client.auth_object

    def _get_client_id(self) -> str | None:
        """Identify the credential set behind the current call.

        Session-scoped (HTTP) or instance-level (stdio), mirroring ``_get_auth``.
        Intended for cache keys that must not cross tenants: a module-instance
        cache keyed only on request content (e.g. AlertsModule's NGSIEM event
        cache, ThreatGraphModule's edge-type cache) is shared across every
        session in HTTP mode, so without this a cache hit for one tenant can
        return another tenant's data. Returns None if unresolvable rather than
        raising — a cache helper should degrade to "always miss", not crash a
        tool call that would otherwise succeed.
        """
        session = _session_client.get()
        client = session if session is not None else self.client
        return getattr(client, "client_id", None)

    def _service(self, cls):
        """Create a FalconPy service class bound to the current auth context.

        FalconPy service construction is lightweight (stores auth reference,
        no HTTP call). The expensive OAuth token exchange is cached by the
        FalconClient's OAuth2 instance.
        """
        return cls(auth_object=self._get_auth())

    def _add_tool(
        self,
        server: FastMCP,
        method: Callable,
        name: str,
        description: str | None = None,
        tier: str = "read",
        destructive: bool = False,
        idempotent: bool = False,
    ) -> None:
        """Register a tool function with the server and track it.

        Args:
            server: The FastMCP server instance.
            method: The async or sync callable to register.
            name: Tool name (e.g. ``"ngsiem_query"``).
            description: Optional tool description override.
            tier: Permission tier — ``"read"`` (default) or ``"write"``.
                  Write tools are skipped when ``allow_writes`` is False.
            destructive: For write tools, hint that the operation may be
                  disruptive or hard to undo (e.g. containing a host). Ignored
                  for read tools, where it is not meaningful.
            idempotent: Hint that repeating the call with the same arguments
                  has no additional effect (e.g. setting a status).

        Raises:
            ValueError: If ``tier`` is not a valid value.
        """
        if tier not in _VALID_TIERS:
            raise ValueError(f"Invalid tier {tier!r} for tool {name!r}. Must be one of: {sorted(_VALID_TIERS)}")
        if tier == "write" and not self.allow_writes:
            self._log(f"Skipping write tool '{name}' (allow_writes=False)")
            return
        kwargs = {
            "name": name,
            "annotations": self._annotations(name, tier, destructive, idempotent),
            # FastMCP otherwise auto-derives an outputSchema from the return-type
            # annotation of every tool. No caller in this codebase reads
            # structuredContent back out of a tool response, so the schema is
            # pure overhead — and MCP clients with a limited tools/list context
            # budget (VS Code Copilot, notably) silently drop tools once that
            # budget fills. See CrowdStrike falcon-mcp PR #376 for the report
            # this mirrors: https://github.com/CrowdStrike/falcon-mcp/pull/376
            "structured_output": False,
        }
        if description:
            kwargs["description"] = description
        server.tool(**kwargs)(_offloaded(method))
        self.tools.append(name)

    @staticmethod
    def _annotations(name: str, tier: str, destructive: bool, idempotent: bool) -> ToolAnnotations:
        """Build standard MCP hints from a tool's tier and flags.

        Every tool calls the external Falcon API, so ``openWorldHint`` is always
        true. ``readOnlyHint`` follows the tier. ``destructiveHint`` only applies
        to write tools (the spec defines it relative to non-read-only tools).
        """
        read_only = tier == "read"
        return ToolAnnotations(
            title=name,
            readOnlyHint=read_only,
            destructiveHint=(destructive if not read_only else None),
            idempotentHint=(idempotent or None),
            openWorldHint=True,
        )

    def _add_resource(self, server: FastMCP, resource) -> None:
        """Register an MCP resource and track its URI."""
        server.add_resource(resource)
        uri = getattr(resource, "uri", str(resource))
        self.resources.append(str(uri))

    def _log(self, message: str) -> None:
        """Log to stderr for MCP server debugging."""
        print(f"[{self.__class__.__name__}] {message}", file=sys.stderr)
