"""Regression tests: tools/list must not emit outputSchema.

FastMCP auto-derives an outputSchema from each tool's return-type annotation
unless structured_output=False is passed at registration. No caller in this
codebase reads structuredContent back out of a tool response, so the schema
is pure overhead on the wire — and it can blow a client's tools/list context
budget (VS Code Copilot silently drops tools once that budget fills; see
CrowdStrike falcon-mcp PR #376: https://github.com/CrowdStrike/falcon-mcp/pull/376).

_add_tool in modules/base.py is the single registration seam every module's
tools flow through, so one assertion here covers all of them.
"""

from __future__ import annotations

import json
import unittest

from mcp.shared.memory import create_connected_server_and_client_session
from starlette.testclient import TestClient

from tests.test_mcp_compliance import ACCEPT_HEADERS, LOCALHOST_BASE_URL, _build_server, _initialize_session


class TestToolsListOutputSchema(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.mcp_server = _build_server()

    async def test_no_tool_has_output_schema(self):
        async with create_connected_server_and_client_session(self.mcp_server.server) as session:
            tools = (await session.list_tools()).tools

        self.assertTrue(tools, "expected at least one registered tool")
        with_schema = [t.name for t in tools if t.outputSchema is not None]
        self.assertFalse(
            with_schema,
            f"tools still emit outputSchema (structured_output=False not applied): {with_schema}",
        )

    async def test_tools_still_have_input_schema(self):
        async with create_connected_server_and_client_session(self.mcp_server.server) as session:
            tools = (await session.list_tools()).tools

        missing_input_schema = [t.name for t in tools if not t.inputSchema]
        self.assertFalse(missing_input_schema, f"tools lost their inputSchema too: {missing_input_schema}")


def test_wire_serialization_excludes_output_schema_key():
    """The raw JSON-RPC payload a client actually parses must have no outputSchema key at all."""
    mcp_server = _build_server()
    app = mcp_server.server.streamable_http_app()

    with TestClient(app, base_url=LOCALHOST_BASE_URL) as client:
        session_id, _ = _initialize_session(client)
        response = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={**ACCEPT_HEADERS, "Mcp-Session-Id": session_id},
        )

    body_text = response.text
    for raw_line in body_text.splitlines():
        if raw_line.startswith("data: "):
            body_text = raw_line[len("data: ") :]
            break
    payload = json.loads(body_text)

    tools = payload["result"]["tools"]
    assert tools, "expected at least one tool in the wire response"
    assert all("outputSchema" not in tool for tool in tools), "outputSchema key still present on the wire"
