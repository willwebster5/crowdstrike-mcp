"""Tests for HTTP transport-security (DNS rebinding) configuration.

The MCP SDK rejects non-localhost Host headers with HTTP 421 unless configured.
Deployments behind a proxy/gateway reach the server on an internal hostname, so
FALCON_MCP_ALLOWED_HOSTS opens that up without weakening the default.
"""

from starlette.testclient import TestClient

from crowdstrike_mcp.server import _transport_security_from_env


def test_unset_keeps_sdk_default(monkeypatch):
    monkeypatch.delenv("FALCON_MCP_ALLOWED_HOSTS", raising=False)
    assert _transport_security_from_env() is None


def test_wildcard_disables_protection(monkeypatch):
    monkeypatch.setenv("FALCON_MCP_ALLOWED_HOSTS", "*")
    settings = _transport_security_from_env()
    assert settings is not None
    assert settings.enable_dns_rebinding_protection is False


def test_host_list_enables_protection_with_allowlist(monkeypatch):
    monkeypatch.setenv("FALCON_MCP_ALLOWED_HOSTS", "mcp.internal, example.com:*")
    settings = _transport_security_from_env()
    assert settings is not None
    assert settings.enable_dns_rebinding_protection is True
    assert settings.allowed_hosts == ["mcp.internal", "example.com:*"]


def _app(monkeypatch, allowed_hosts_value):
    """A streamable-HTTP app constructed the way the server constructs it."""
    from mcp.server.fastmcp import FastMCP

    if allowed_hosts_value is None:
        monkeypatch.delenv("FALCON_MCP_ALLOWED_HOSTS", raising=False)
    else:
        monkeypatch.setenv("FALCON_MCP_ALLOWED_HOSTS", allowed_hosts_value)

    server = FastMCP("test", transport_security=_transport_security_from_env())
    return server.streamable_http_app()


_INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "probe", "version": "1.0"},
    },
}
_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "Host": "some-internal-host.example",
}


def test_foreign_host_rejected_when_allowlist_excludes_it(monkeypatch):
    """A host outside an explicit allowlist gets 421 — the deployment failure."""
    with TestClient(_app(monkeypatch, "allowed.example")) as client:
        response = client.post("/mcp", json=_INIT, headers=_HEADERS)
    assert response.status_code == 421


def test_listed_host_is_allowed(monkeypatch):
    with TestClient(_app(monkeypatch, "some-internal-host.example")) as client:
        response = client.post("/mcp", json=_INIT, headers=_HEADERS)
    assert response.status_code == 200


def test_foreign_host_allowed_with_wildcard(monkeypatch):
    with TestClient(_app(monkeypatch, "*")) as client:
        response = client.post("/mcp", json=_INIT, headers=_HEADERS)
    assert response.status_code == 200
