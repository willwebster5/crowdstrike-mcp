#!/usr/bin/env python3
"""
CrowdStrike Falcon MCP Server — Modular Architecture (v3.0)

Multi-transport MCP server with auto-discovered tool modules.

Transports:
  stdio            — Default, for Claude Code / MCP stdio clients
  sse              — Server-Sent Events over HTTP
  streamable-http  — Streamable HTTP transport

Usage:
  python server.py                                    # stdio (default)
  python server.py --transport sse --port 8000        # SSE
  python server.py --modules ngsiem,alerts,hosts      # Selective modules
  python server.py --debug                            # Debug logging
  python server.py --allow-writes                     # Enable write tools

Environment variables (override CLI args):
  FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, FALCON_BASE_URL
  FALCON_MCP_TRANSPORT, FALCON_MCP_MODULES, FALCON_MCP_DEBUG
  FALCON_MCP_HOST, FALCON_MCP_PORT, FALCON_MCP_API_KEY
  FALCON_MCP_ALLOW_WRITES
"""

from __future__ import annotations

import argparse
import os
import sys

from dotenv import load_dotenv

load_dotenv()

from fastmcp import FastMCP

from crowdstrike_mcp.client import FalconClient
from crowdstrike_mcp.registry import get_available_modules


class FalconMCPServer:
    """Orchestrates module discovery, registration, and transport startup."""

    def __init__(
        self,
        transport: str = "stdio",
        modules_filter: set[str] | None = None,
        allow_writes: bool = False,
        debug: bool = False,
        host: str = "127.0.0.1",
        port: int = 8000,
        api_key: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        base_url: str | None = None,
    ):
        self.transport = transport
        self.debug = debug
        self.host = host
        self.port = port
        self.api_key = api_key

        # Create shared API client
        if transport == "stdio":
            # stdio: resolve credentials and authenticate eagerly
            self.client = FalconClient(
                client_id=client_id,
                client_secret=client_secret,
                base_url=base_url,
            )
            self.client.authenticate()
        else:
            # HTTP mode: credential-less startup, per-client auth via headers
            self.client = FalconClient.deferred()
            self._log("HTTP mode: server is credential-less, per-client auth via headers")

        # Create FastMCP server
        self.server = FastMCP("crowdstrike-falcon")

        # Discover and register modules
        self._modules = get_available_modules(
            self.client,
            enabled=modules_filter,
            allow_writes=allow_writes,
        )

        for mod in self._modules:
            mod.register_tools(self.server)
            mod.register_resources(self.server)

        tool_count = sum(len(m.tools) for m in self._modules)
        resource_count = sum(len(m.resources) for m in self._modules)
        write_mode = "enabled" if allow_writes else "read-only"
        self._log(f"Registered {tool_count} tools and {resource_count} resources from {len(self._modules)} modules ({write_mode})")

    def run(self):
        """Start the server with the configured transport."""
        if self.transport == "stdio":
            self._log("Starting stdio transport")
            self.server.run(transport="stdio")

        elif self.transport == "sse":
            self._run_http("sse")

        elif self.transport == "streamable-http":
            self._run_http("streamable-http")

        else:
            raise ValueError(f"Unknown transport: {self.transport}")

    def _run_http(self, transport_type: str):
        """Start an HTTP-based transport (SSE or streamable-http) with middleware stack."""
        import uvicorn

        from crowdstrike_mcp.client import SERVER_VERSION
        from crowdstrike_mcp.common.health import with_health_check
        from crowdstrike_mcp.common.session_auth import session_auth_middleware

        app = self.server.http_app(transport=transport_type)

        # Layer 1: per-session Falcon auth (innermost)
        app = session_auth_middleware(app)

        # Layer 2: server access gate (optional)
        if self.api_key:
            from crowdstrike_mcp.common.auth_middleware import auth_middleware

            app = auth_middleware(app, self.api_key)
            self._log(f"API key authentication enabled for {transport_type}")

        # Layer 3: health check (outermost, no auth)
        app = with_health_check(app, version=SERVER_VERSION, transport=transport_type)

        self._log(f"Starting {transport_type} transport on {self.host}:{self.port}")
        uvicorn.run(app, host=self.host, port=self.port)

    def _log(self, message: str):
        print(f"[FalconMCPServer] {message}", file=sys.stderr)


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments with env var fallbacks."""
    parser = argparse.ArgumentParser(
        description="CrowdStrike Falcon MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--transport",
        default=os.environ.get("FALCON_MCP_TRANSPORT", "stdio"),
        choices=["stdio", "sse", "streamable-http"],
        help="Transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--modules",
        default=os.environ.get("FALCON_MCP_MODULES"),
        help="Comma-separated list of modules to load (default: all)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=os.environ.get("FALCON_MCP_DEBUG", "").lower() in ("1", "true", "yes"),
        help="Enable debug logging",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("FALCON_MCP_HOST", "127.0.0.1"),
        help="HTTP host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("FALCON_MCP_PORT", "8000")),
        help="HTTP port (default: 8000)",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("FALCON_MCP_API_KEY"),
        help="API key for HTTP transport authentication",
    )
    parser.add_argument(
        "--allow-writes",
        action="store_true",
        default=os.environ.get("FALCON_MCP_ALLOW_WRITES", "").lower() in ("1", "true", "yes"),
        help="Enable write tools (update_alert_status, host_contain, etc). Default: read-only.",
    )

    return parser.parse_args()


def main():
    """CLI entry point."""
    args = parse_args()

    modules_filter = None
    if args.modules:
        modules_filter = {m.strip() for m in args.modules.split(",")}

    falcon_server = FalconMCPServer(
        transport=args.transport,
        modules_filter=modules_filter,
        allow_writes=args.allow_writes,
        debug=args.debug,
        host=args.host,
        port=args.port,
        api_key=args.api_key,
    )

    falcon_server.run()


if __name__ == "__main__":
    main()
