"""MCP protocol compliance tests.

Asserts the server's actual wire behavior conforms to the MCP spec and
JSON-RPC 2.0, mirroring the suite CrowdStrike's own falcon-mcp ships
(https://github.com/CrowdStrike/falcon-mcp/pull/364), adapted to this
codebase's module/resource/annotation conventions.
"""

from __future__ import annotations

import json
import re
import unittest
from typing import Any
from unittest.mock import MagicMock, patch

from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import LATEST_PROTOCOL_VERSION
from starlette.testclient import TestClient

from crowdstrike_mcp.server import FalconMCPServer
from tests.test_smoke_tools_list import EXPECTED_WRITE_TOOLS, _patch_falconpy

# falcon://{namespace}/{name} — confirmed against every server.resource(...)
# call site in src/crowdstrike_mcp/modules/*.py. No "-guide" suffix convention
# here (that's falcon-mcp's shape, not ours).
RESOURCE_URI_PATTERN = re.compile(r"^falcon://[a-z0-9-]+/[a-z0-9-]+$")

LOCALHOST_BASE_URL = "http://127.0.0.1:8000"
ACCEPT_HEADERS: dict[str, str] = {"Accept": "application/json, text/event-stream"}


def _initialize_payload(req_id: int = 1) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "initialize",
        "params": {
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "crowdstrike-mcp-compliance-tests", "version": "0.0.0"},
        },
    }


def _parse_jsonrpc(response) -> dict[str, Any]:
    content_type = response.headers.get("content-type", "")
    if "text/event-stream" in content_type:
        for raw_line in response.text.splitlines():
            if raw_line.startswith("data: "):
                return json.loads(raw_line[len("data: ") :])
        raise AssertionError(f"No data event in SSE response body: {response.text!r}")
    return response.json()


def _initialize_session(client: TestClient) -> tuple[str, dict[str, Any]]:
    response = client.post("/mcp", json=_initialize_payload(), headers=ACCEPT_HEADERS)
    assert response.status_code == 200, f"initialize failed: {response.status_code} {response.text}"
    session_id = response.headers.get("Mcp-Session-Id", "")
    body = _parse_jsonrpc(response)
    client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers={**ACCEPT_HEADERS, "Mcp-Session-Id": session_id},
    )
    return session_id, body


def _build_server(allow_writes: bool = True) -> FalconMCPServer:
    """Construct a real FalconMCPServer with FalconClient/FalconPy mocked out."""
    mock_client = MagicMock()
    mock_client.auth_object = MagicMock()
    with patch("crowdstrike_mcp.server.FalconClient") as mock_cls:
        mock_cls.deferred.return_value = mock_client
        with _patch_falconpy():
            return FalconMCPServer(transport="streamable-http", allow_writes=allow_writes)


class TestMCPComplianceTransport(unittest.TestCase):
    """Transport-level MCP protocol compliance tests using starlette TestClient."""

    def setUp(self):
        self.mcp_server = _build_server()
        app = self.mcp_server.server.streamable_http_app()
        self.http_client = TestClient(app, base_url=LOCALHOST_BASE_URL)
        self.http_client.__enter__()

    def tearDown(self):
        self.http_client.__exit__(None, None, None)

    def test_streamable_http_rejects_foreign_origin(self):
        """Spec transport security: SHOULD validate Origin header.

        A foreign Origin on a valid Host is a DNS-rebinding vector. Default
        FALCON_MCP_ALLOWED_HOSTS is unset, which keeps the SDK's own
        protection on (see _transport_security_from_env in server.py).
        """
        response = self.http_client.post(
            "/mcp",
            json=_initialize_payload(),
            headers={**ACCEPT_HEADERS, "Origin": "http://evil.example.com"},
        )
        self.assertGreaterEqual(
            response.status_code,
            400,
            f"Server accepted request with foreign Origin (status={response.status_code}). "
            f"This is a DNS-rebinding vector per MCP spec transport security.",
        )

    def test_jsonrpc_error_codes(self):
        """JSON-RPC 2.0 §5.1: unknown method and invalid params return proper error envelopes."""
        session_id, _ = _initialize_session(self.http_client)

        unknown = {"jsonrpc": "2.0", "id": 100, "method": "compliance/does-not-exist", "params": {}}
        response = self.http_client.post("/mcp", json=unknown, headers={**ACCEPT_HEADERS, "Mcp-Session-Id": session_id})
        body = _parse_jsonrpc(response)
        self.assertIn("error", body, f"Unknown method returned no error envelope: {body!r}")
        self.assertIn(
            body["error"]["code"],
            (-32601, -32602),
            f"Unknown method MUST return -32601 or -32602; got {body['error']!r}",
        )

        bad_params = {"jsonrpc": "2.0", "id": 101, "method": "tools/call", "params": {}}
        response = self.http_client.post("/mcp", json=bad_params, headers={**ACCEPT_HEADERS, "Mcp-Session-Id": session_id})
        body = _parse_jsonrpc(response)
        self.assertIn("error", body, f"tools/call with missing `name` should error; got {body!r}")
        self.assertEqual(
            body["error"]["code"],
            -32602,
            f"Invalid params MUST return -32602 per JSON-RPC 2.0 §5.1; got {body['error']!r}",
        )

    def test_mcp_session_id_binding_and_entropy(self):
        """Spec streamable-http: session id MUST bind requests, SHOULD have sufficient entropy."""
        session_id, _ = _initialize_session(self.http_client)
        self.assertTrue(session_id, "initialize did not return Mcp-Session-Id header")
        self.assertGreaterEqual(len(session_id), 22, f"Mcp-Session-Id too short for 128-bit entropy: len={len(session_id)}")

        tampered = ("0" if session_id[0] != "0" else "1") + session_id[1:]
        self.assertNotEqual(tampered, session_id)

        response = self.http_client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 200, "method": "tools/list"},
            headers={**ACCEPT_HEADERS, "Mcp-Session-Id": tampered},
        )
        self.assertIn(
            response.status_code,
            (400, 401, 403, 404),
            f"Server accepted tampered Mcp-Session-Id (status={response.status_code}).",
        )


class TestMCPComplianceProtocol(unittest.IsolatedAsyncioTestCase):
    """Protocol-level MCP compliance tests using in-process client sessions."""

    def setUp(self):
        self.mcp_server = _build_server()

    async def test_tools_list_immutable_across_sessions(self):
        """Tool definitions MUST be stable across sessions (rug-pull guard)."""

        def _tuple_for(tool: Any) -> tuple[str, str | None, str, str | None]:
            annotations_dump = tool.annotations.model_dump_json() if tool.annotations is not None else None
            return (tool.name, tool.description, json.dumps(tool.inputSchema, sort_keys=True), annotations_dump)

        async with create_connected_server_and_client_session(self.mcp_server.server) as session:
            snap1 = sorted(_tuple_for(tool) for tool in (await session.list_tools()).tools)
        async with create_connected_server_and_client_session(self.mcp_server.server) as session:
            snap2 = sorted(_tuple_for(tool) for tool in (await session.list_tools()).tools)

        self.assertEqual(snap1, snap2, "tools/list output differs between sessions")

    async def test_capabilities_match_actual_behavior(self):
        """Capabilities: listChanged MUST reflect server behavior.

        crowdstrike-mcp registers tools and resources at startup and never
        changes them at runtime, so declaring listChanged=True would mislead
        clients.
        """
        async with create_connected_server_and_client_session(self.mcp_server.server) as session:
            caps = session.get_server_capabilities()

        self.assertIsNotNone(caps, "ClientSession returned no server capabilities")
        self.assertIsNotNone(caps.tools, "Server registers tools but declares no tools capability")
        self.assertFalse(
            caps.tools.listChanged,
            f"Server declares tools.listChanged={caps.tools.listChanged} but never emits list_changed notifications.",
        )
        if caps.resources is not None:
            self.assertFalse(
                caps.resources.listChanged,
                f"Server declares resources.listChanged={caps.resources.listChanged} but never emits list_changed notifications.",
            )

    async def test_resource_uri_format(self):
        """Every resource URI MUST match falcon://{namespace}/{name}."""
        async with create_connected_server_and_client_session(self.mcp_server.server) as session:
            list_result = await session.list_resources()

        bad_uris = [str(resource.uri) for resource in list_result.resources if not RESOURCE_URI_PATTERN.match(str(resource.uri))]
        self.assertFalse(
            bad_uris,
            "Resource URIs do not match falcon://{namespace}/{name}:\n" + "\n".join(f"  - {uri}" for uri in bad_uris),
        )
        self.assertTrue(list_result.resources, "Expected at least one registered resource (FQL/CQL guides)")

    async def test_tool_annotations_across_all_modules(self):
        """Tool annotations: readOnlyHint and destructiveHint MUST be honest.

        Default-deny posture: every tool not in EXPECTED_WRITE_TOOLS
        (tests/test_smoke_tools_list.py — the existing source of truth for
        which tools are write-tier) MUST declare readOnlyHint=True and
        destructiveHint in (None, False). Enforced bidirectionally so a
        stale allowlist entry (a tool renamed/removed) also fails.
        """
        async with create_connected_server_and_client_session(self.mcp_server.server) as session:
            tools = (await session.list_tools()).tools

        tool_map = {t.name: t.annotations for t in tools}
        registered_names = set(tool_map)

        ghost_entries = EXPECTED_WRITE_TOOLS - registered_names
        self.assertFalse(
            ghost_entries,
            "EXPECTED_WRITE_TOOLS contains tool names that no longer exist:\n" + "\n".join(f"  - {name}" for name in sorted(ghost_entries)),
        )

        still_read_only: list[tuple[str, str]] = []
        for name in EXPECTED_WRITE_TOOLS:
            annotations = tool_map[name]
            if annotations is None or annotations.readOnlyHint is not False:
                read_only_val = None if annotations is None else annotations.readOnlyHint
                still_read_only.append((name, f"readOnlyHint={read_only_val!r}"))
        self.assertFalse(
            still_read_only,
            "EXPECTED_WRITE_TOOLS contains tools that are now read-only:\n" + "\n".join(f"  - {name}: {reason}" for name, reason in still_read_only),
        )

        violations: list[tuple[str, str]] = []
        for tool in tools:
            if tool.name in EXPECTED_WRITE_TOOLS:
                continue
            annotations = tool.annotations
            if annotations is None:
                violations.append((tool.name, "annotations=None"))
                continue
            if annotations.readOnlyHint is not True:
                violations.append((tool.name, f"readOnlyHint={annotations.readOnlyHint!r}"))
            if annotations.destructiveHint not in (None, False):
                violations.append((tool.name, f"destructiveHint={annotations.destructiveHint!r}"))
        self.assertFalse(
            violations,
            "Tools missing read-only annotations (add to EXPECTED_WRITE_TOOLS in "
            "tests/test_smoke_tools_list.py only after security review confirms mutation):\n"
            + "\n".join(f"  - {name}: {reason}" for name, reason in violations),
        )


if __name__ == "__main__":
    unittest.main()
