"""
BaseModule — abstract base class for all MCP tool modules.

Each module:
  - Receives a shared ``FalconClient`` instance
  - Registers its tools (and optionally resources) with a FastMCP server
  - Creates FalconPy service classes using ``self.client.auth_object``
"""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from contextvars import ContextVar
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

    from crowdstrike_mcp.client import FalconClient

_VALID_TIERS = {"read", "write"}

# Per-session FalconClient for HTTP transports. Set by session_auth_middleware.
# Each asyncio task gets its own context copy, so concurrent requests are isolated.
# Canonical location — common/session_auth.py imports this.
_session_client: ContextVar["FalconClient | None"] = ContextVar("_session_client", default=None)


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
    ) -> None:
        """Register a tool function with the server and track it.

        Args:
            server: The FastMCP server instance.
            method: The async or sync callable to register.
            name: Tool name (e.g. ``"ngsiem_query"``).
            description: Optional tool description override.
            tier: Permission tier — ``"read"`` (default) or ``"write"``.
                  Write tools are skipped when ``allow_writes`` is False.

        Raises:
            ValueError: If ``tier`` is not a valid value.
        """
        if tier not in _VALID_TIERS:
            raise ValueError(f"Invalid tier {tier!r} for tool {name!r}. Must be one of: {sorted(_VALID_TIERS)}")
        if tier == "write" and not self.allow_writes:
            self._log(f"Skipping write tool '{name}' (allow_writes=False)")
            return
        kwargs = {"name": name}
        if description:
            kwargs["description"] = description
        server.tool(**kwargs)(method)
        self.tools.append(name)

    def _add_resource(self, server: FastMCP, resource) -> None:
        """Register an MCP resource and track its URI."""
        server.add_resource(resource)
        uri = getattr(resource, "uri", str(resource))
        self.resources.append(str(uri))

    def _log(self, message: str) -> None:
        """Log to stderr for MCP server debugging."""
        print(f"[{self.__class__.__name__}] {message}", file=sys.stderr)
