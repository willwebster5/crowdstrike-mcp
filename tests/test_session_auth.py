"""Tests for the per-session Falcon auth middleware (HTTP transports).

Covers the two properties that let the server sit behind an MCP gateway:
credential-less startup probes must succeed, and gateways that inject
credentials as prefixed headers must be understood.
"""

from unittest.mock import MagicMock, patch

import pytest
from starlette.responses import JSONResponse
from starlette.testclient import TestClient

from crowdstrike_mcp.common import session_auth
from crowdstrike_mcp.common.session_auth import session_auth_middleware
from crowdstrike_mcp.modules.base import _session_client


@pytest.fixture(autouse=True)
def _clear_cache():
    """The client cache is module-level; keep tests independent."""
    session_auth._client_cache.clear()
    yield
    session_auth._client_cache.clear()


def _probe_app():
    """Minimal ASGI app reporting whether a session client was resolved."""

    async def app(scope, receive, send):
        client = _session_client.get()
        await JSONResponse({"session": client is not None})(scope, receive, send)

    return app


def _client(**kwargs):
    return TestClient(session_auth_middleware(_probe_app()), **kwargs)


def test_request_without_credentials_is_not_rejected():
    """initialize/tools/list run before any user supplies credentials.

    A gateway health-probes the container on boot, so an unauthenticated
    request must pass through rather than 401.
    """
    response = _client().post("/mcp", json={})

    assert response.status_code == 200
    assert response.json() == {"session": False}


def test_credentials_resolve_a_session_client():
    with patch.object(session_auth, "FalconClient") as falcon:
        falcon.return_value = MagicMock()

        response = _client().post(
            "/mcp",
            json={},
            headers={
                "X-Falcon-Client-Id": "id-1",
                "X-Falcon-Client-Secret": "secret-1",
            },
        )

    assert response.status_code == 200
    assert response.json() == {"session": True}


def test_bad_credentials_still_return_401():
    with patch.object(session_auth, "FalconClient") as falcon:
        falcon.return_value.authenticate.side_effect = RuntimeError("bad creds")

        response = _client().post(
            "/mcp",
            json={},
            headers={
                "X-Falcon-Client-Id": "id-1",
                "X-Falcon-Client-Secret": "nope",
            },
        )

    assert response.status_code == 401
    assert "authentication failed" in response.json()["error"].lower()


def test_credentials_are_read_from_a_prefixed_env_header(monkeypatch):
    """Gateways forward per-user env vars as ``<prefix><VAR_NAME>`` headers."""
    monkeypatch.setenv("FALCON_MCP_ENV_HEADER_PREFIX", "X-Gateway-Env-")

    with patch.object(session_auth, "FalconClient") as falcon:
        falcon.return_value = MagicMock()

        response = _client().post(
            "/mcp",
            json={},
            headers={
                "X-Gateway-Env-FALCON_CLIENT_ID": "id-1",
                "X-Gateway-Env-FALCON_CLIENT_SECRET": "secret-1",
            },
        )

    assert response.status_code == 200
    assert response.json() == {"session": True}


def test_native_headers_win_over_prefixed_env_headers(monkeypatch):
    monkeypatch.setenv("FALCON_MCP_ENV_HEADER_PREFIX", "X-Gateway-Env-")

    with patch.object(session_auth, "FalconClient") as falcon:
        falcon.return_value = MagicMock()

        _client().post(
            "/mcp",
            json={},
            headers={
                "X-Falcon-Client-Id": "native",
                "X-Falcon-Client-Secret": "native-secret",
                "X-Gateway-Env-FALCON_CLIENT_ID": "prefixed",
                "X-Gateway-Env-FALCON_CLIENT_SECRET": "prefixed-secret",
            },
        )

    assert falcon.call_args.kwargs["client_id"] == "native"
    assert falcon.call_args.kwargs["client_secret"] == "native-secret"
