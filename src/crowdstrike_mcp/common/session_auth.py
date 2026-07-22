"""
Per-session Falcon authentication middleware for HTTP transports.

Extracts CrowdStrike API credentials from request headers, authenticates
via OAuth2, caches sessions, and sets a ContextVar for per-request isolation.
"""

import hashlib
import os
import sys
import time

from starlette.responses import JSONResponse

from crowdstrike_mcp.client import FalconClient
from crowdstrike_mcp.modules.base import _session_client
from crowdstrike_mcp.response_store import (
    ResponseStore,
    make_session_key,
    reset_response_session,
    set_response_session,
)

# Client cache: hash(creds) → (FalconClient, last_access_time)
_client_cache: dict[str, tuple[FalconClient, float]] = {}
_CACHE_TTL = 25 * 60  # 25 minutes (inside CrowdStrike's 30-min token window)
_CACHE_MAX = 100

# Per-connection id issued by the stateful streamable-HTTP transport (MCP spec).
# Absent on the initialize request, on SSE, and in stateless mode.
_MCP_SESSION_ID_HEADER = "mcp-session-id"


def _evict_stale():
    """Remove expired entries from the client cache, dropping their stored responses too."""
    now = time.time()
    expired = [k for k, (_, ts) in _client_cache.items() if now - ts > _CACHE_TTL]
    for k in expired:
        del _client_cache[k]
        ResponseStore.clear_credential_sessions(k)


def _evict_lru():
    """Evict least-recently-accessed entry when cache exceeds max size, with its stored responses."""
    if len(_client_cache) >= _CACHE_MAX:
        oldest_key = min(_client_cache, key=lambda k: _client_cache[k][1])
        del _client_cache[oldest_key]
        ResponseStore.clear_credential_sessions(oldest_key)


def _parse_headers(scope) -> dict[str, str]:
    """Lower-cased header map from an ASGI scope."""
    return {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}


def _extract_headers(headers: dict[str, str]) -> tuple[str | None, str | None, str | None]:
    """Extract Falcon credentials from a parsed header map.

    Native headers (X-Falcon-*) take precedence. As a fallback, credentials may
    arrive as prefixed env headers: MCP gateways commonly forward each per-user
    env var as ``<prefix><VAR_NAME>``. Set FALCON_MCP_ENV_HEADER_PREFIX to the
    gateway's prefix to read them.
    """
    prefix = os.environ.get("FALCON_MCP_ENV_HEADER_PREFIX", "").lower()

    def _get(native: str, env_var: str) -> str | None:
        value = headers.get(native)
        if not value and prefix:
            value = headers.get(f"{prefix}{env_var.lower()}")
        return value

    return (
        _get("x-falcon-client-id", "FALCON_CLIENT_ID"),
        _get("x-falcon-client-secret", "FALCON_CLIENT_SECRET"),
        _get("x-falcon-base-url", "FALCON_BASE_URL"),
    )


def session_auth_middleware(app):
    """ASGI middleware that authenticates per-client Falcon credentials.

    Extracts X-Falcon-Client-Id, X-Falcon-Client-Secret, and X-Falcon-Base-Url
    from request headers. Authenticates via OAuth2, caches the session, and
    sets the _session_client ContextVar for the request duration.

    Requests without credentials pass through unauthenticated, leaving the
    ContextVar unset. This is required: the MCP handshake (initialize,
    tools/list) is exercised by health probes before any user has connected,
    and those calls need no Falcon access. Tool invocations resolve the client
    lazily and raise if it is missing. Use --api-key to gate a directly
    exposed server.
    """

    async def middleware(scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await app(scope, receive, send)
            return

        headers = _parse_headers(scope)
        client_id, client_secret, base_url = _extract_headers(headers)

        if not client_id or not client_secret:
            await app(scope, receive, send)
            return

        base_url = base_url or "US1"
        cache_key = hashlib.sha256(f"{client_id}:{client_secret}:{base_url}".encode()).hexdigest()

        # Check cache (with lazy eviction)
        _evict_stale()

        if cache_key in _client_cache:
            cached_client, _ = _client_cache[cache_key]
            _client_cache[cache_key] = (cached_client, time.time())
        else:
            # Cache miss — authenticate
            _evict_lru()
            try:
                new_client = FalconClient(
                    client_id=client_id,
                    client_secret=client_secret,
                    base_url=base_url,
                )
                new_client.authenticate()
                _client_cache[cache_key] = (new_client, time.time())
                cached_client = new_client
                print(f"[SessionAuth] Authenticated new client (base_url={base_url})", file=sys.stderr)
            except (RuntimeError, ValueError) as e:
                response = JSONResponse(
                    {"error": f"CrowdStrike authentication failed: {e}"},
                    status_code=401,
                )
                await response(scope, receive, send)
                return

        # Set ContextVars for this request. The response store is partitioned by
        # credential *and* MCP connection: the credential key keeps one tenant
        # from reading another's stored responses via predictable ref_ids, and
        # the mcp-session-id keeps a single user's concurrent connections (e.g.
        # several projects on one Falcon credential) from sharing a ref
        # namespace / LRU budget. Falls back to the credential key when no
        # connection id is present (initialize, SSE, stateless).
        store_key = make_session_key(cache_key, headers.get(_MCP_SESSION_ID_HEADER))
        token = _session_client.set(cached_client)
        store_token = set_response_session(store_key)
        try:
            await app(scope, receive, send)
        finally:
            reset_response_session(store_token)
            _session_client.reset(token)

    return middleware
