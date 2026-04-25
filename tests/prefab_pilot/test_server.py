"""Tests for the FastMCPApp pilot server wiring.

These exercise the registered tools directly (no stdio transport), so they
don't require a host. The transport-level smoke test ("does this actually
render in Claude Desktop?") is a manual check listed in the README, since
it can only be done by an agent or human with the right setup.
"""

from __future__ import annotations

import pytest

from crowdstrike_mcp.prefab_pilot.server import app


@pytest.mark.anyio
async def test_server_app_has_expected_name():
    assert app.name == "crowdstrike-prefab-pilot"


@pytest.mark.anyio
async def test_server_registers_ngsiem_query_demo_tool():
    tools = await app.list_tools()
    names = {t.name for t in tools}
    assert "ngsiem_query_demo" in names


@pytest.mark.anyio
async def test_server_registers_ngsiem_query_drilldown_tool():
    tools = await app.list_tools()
    names = {t.name for t in tools}
    assert "ngsiem_query_drilldown" in names


@pytest.mark.anyio
async def test_ngsiem_query_demo_returns_both_text_and_structured():
    tools = await app.list_tools()
    tool = next(t for t in tools if t.name == "ngsiem_query_demo")
    result = await tool.run(arguments={"count": 20, "query": "#repo=fdr"})
    assert result.content, "text fallback missing — non-rendering hosts would be broken"
    assert result.structured_content, "structured_content missing — Prefab would not render"


@pytest.mark.anyio
async def test_ngsiem_query_demo_text_fallback_is_self_contained():
    tools = await app.list_tools()
    tool = next(t for t in tools if t.name == "ngsiem_query_demo")
    result = await tool.run(arguments={"count": 15, "query": "#repo=fdr event=ProcessRollup2"})
    text = "\n".join(block.text for block in result.content if hasattr(block, "text"))
    assert "15 events" in text
    assert "#repo=fdr event=ProcessRollup2" in text


@pytest.mark.anyio
async def test_ngsiem_query_demo_structured_content_is_a_prefab_envelope():
    # The renderer hangs on "waiting for content" if we ship a bare component
    # tree. FastMCP wraps a Prefab Component into a PrefabApp envelope
    # (``$prefab``/``view``) when the Component is passed to ToolResult.
    tools = await app.list_tools()
    tool = next(t for t in tools if t.name == "ngsiem_query_demo")
    result = await tool.run(arguments={"count": 10, "query": "q"})
    sc = result.structured_content
    assert "$prefab" in sc, f"missing PrefabApp envelope: {list(sc.keys())}"
    assert "view" in sc
    assert sc["view"].get("type") in ("Div", "Column"), sc["view"].get("type")


@pytest.mark.anyio
async def test_ngsiem_query_drilldown_returns_single_row():
    # Drilldown now accepts the row dict directly (the DataTable's onRowClick
    # passes $event — the clicked row — through to it). It just echoes the
    # row out as text + structured content; no second NGSIEM round-trip.
    tools = await app.list_tools()
    tool = next(t for t in tools if t.name == "ngsiem_query_drilldown")
    row = {
        "ComputerName": "HOST-01",
        "event_simpleName": "ProcessRollup2",
        "timestamp": "2026-04-25T12:00:00+00:00",
        "ImageFileName": "/usr/bin/bash",
    }
    result = await tool.run(arguments={"row": row})
    assert result.structured_content == row
    text = "\n".join(b.text for b in result.content if hasattr(b, "text"))
    assert "HOST-01" in text
    assert "ProcessRollup2" in text


@pytest.mark.anyio
async def test_ngsiem_query_demo_mock_path_when_live_disabled(monkeypatch):
    monkeypatch.delenv("CROWDSTRIKE_PREFAB_LIVE", raising=False)
    tools = await app.list_tools()
    tool = next(t for t in tools if t.name == "ngsiem_query_demo")
    result = await tool.run(arguments={"query": "q", "count": 12, "seed": 7})
    text = "\n".join(block.text for block in result.content if hasattr(block, "text"))
    assert "Source: mock" in text
    assert "CROWDSTRIKE_PREFAB_LIVE" in text


@pytest.mark.anyio
async def test_ngsiem_query_demo_live_path_used_when_creds_set(monkeypatch):
    monkeypatch.setenv("CROWDSTRIKE_PREFAB_LIVE", "1")
    live_events = [
        {
            "ComputerName": "LIVE-HOST-01",
            "event_simpleName": "ProcessRollup2",
            "@timestamp": 1776470400000,
            "UserName": "jdoe",
            "ImageFileName": "/usr/bin/bash",
        }
    ]
    captured: dict = {}

    def fake_live(query, start_time, max_results):
        captured["query"] = query
        captured["start_time"] = start_time
        captured["max_results"] = max_results
        return {"success": True, "events": live_events}

    monkeypatch.setattr("crowdstrike_mcp.prefab_pilot.server._run_live_query", fake_live)
    tools = await app.list_tools()
    tool = next(t for t in tools if t.name == "ngsiem_query_demo")
    result = await tool.run(arguments={"query": "#repo=fdr *", "start_time": "6h", "max_results": 50})
    text = "\n".join(block.text for block in result.content if hasattr(block, "text"))
    assert "Source: live" in text
    assert "LIVE-HOST-01" in text
    assert captured == {"query": "#repo=fdr *", "start_time": "6h", "max_results": 50}


@pytest.mark.anyio
async def test_ngsiem_query_demo_live_failure_surfaces_error_and_falls_back(monkeypatch):
    monkeypatch.setenv("CROWDSTRIKE_PREFAB_LIVE", "1")

    def fake_live(query, start_time, max_results):
        return {"success": False, "error": "HTTP 403: forbidden"}

    monkeypatch.setattr("crowdstrike_mcp.prefab_pilot.server._run_live_query", fake_live)
    tools = await app.list_tools()
    tool = next(t for t in tools if t.name == "ngsiem_query_demo")
    result = await tool.run(arguments={"query": "q"})
    text = "\n".join(block.text for block in result.content if hasattr(block, "text"))
    assert "Source: mock" in text
    assert "HTTP 403: forbidden" in text


@pytest.mark.anyio
async def test_ngsiem_query_demo_live_exception_does_not_crash_tool(monkeypatch):
    monkeypatch.setenv("CROWDSTRIKE_PREFAB_LIVE", "1")

    def fake_live(query, start_time, max_results):
        raise RuntimeError("auth blew up")

    monkeypatch.setattr("crowdstrike_mcp.prefab_pilot.server._run_live_query", fake_live)
    tools = await app.list_tools()
    tool = next(t for t in tools if t.name == "ngsiem_query_demo")
    result = await tool.run(arguments={"query": "q"})
    text = "\n".join(block.text for block in result.content if hasattr(block, "text"))
    assert "Source: mock" in text
    assert "RuntimeError" in text
    assert "auth blew up" in text


@pytest.mark.anyio
async def test_ngsiem_query_demo_live_zero_events_reported_honestly(monkeypatch):
    monkeypatch.setenv("CROWDSTRIKE_PREFAB_LIVE", "1")

    def fake_live(query, start_time, max_results):
        return {"success": True, "events": []}

    monkeypatch.setattr("crowdstrike_mcp.prefab_pilot.server._run_live_query", fake_live)
    tools = await app.list_tools()
    tool = next(t for t in tools if t.name == "ngsiem_query_demo")
    result = await tool.run(arguments={"query": "q", "start_time": "15m"})
    text = "\n".join(block.text for block in result.content if hasattr(block, "text"))
    assert "Source: live" in text
    assert "0 events" in text
    assert "15m" in text


@pytest.mark.anyio
async def test_ngsiem_query_demo_handles_live_int_epoch_timestamps(monkeypatch):
    # Regression for CD's "fromisoformat: argument must be str" crash —
    # live NGSIEM returns @timestamp as epoch ms (int). Must not raise.
    monkeypatch.setenv("CROWDSTRIKE_PREFAB_LIVE", "1")
    live_events = [
        {"ComputerName": "H", "event_simpleName": "X", "@timestamp": 1776470400000},
        {"ComputerName": "H", "event_simpleName": "X", "@timestamp": 1776474000000},
    ]

    def fake_live(query, start_time, max_results):
        return {"success": True, "events": live_events}

    monkeypatch.setattr("crowdstrike_mcp.prefab_pilot.server._run_live_query", fake_live)
    tools = await app.list_tools()
    tool = next(t for t in tools if t.name == "ngsiem_query_demo")
    result = await tool.run(arguments={"query": "*"})
    assert result.structured_content
    assert "$prefab" in result.structured_content
    assert "view" in result.structured_content


@pytest.mark.anyio
async def test_ngsiem_query_demo_structured_content_uses_camelcase_aliases():
    # Regression for "waiting for content" in Claude Desktop — Prefab's React
    # renderer expects camelCase keys (cssClass, dataKey, xAxis, ...). Plain
    # pydantic model_dump emits snake_case Python field names, which the
    # renderer silently drops. Prefab's to_json() applies the aliases.
    import json

    tools = await app.list_tools()
    tool = next(t for t in tools if t.name == "ngsiem_query_demo")
    result = await tool.run(arguments={"query": "q", "count": 10})
    blob = json.dumps(result.structured_content)
    # Snake-case field names must NOT appear — they indicate the plain dump path.
    assert '"css_class"' not in blob
    assert '"on_mount"' not in blob
    assert '"data_key"' not in blob


@pytest.mark.anyio
async def test_drilldown_backend_name_matches_layout_constant():
    # The layout pre-computes the drilldown's wire-format name via
    # hashed_backend_name(app, tool). If someone renames the app or the tool
    # without updating layout.py's constants, the row-click action would
    # dispatch to a name FastMCP never registered. Catch that loudly here.
    from crowdstrike_mcp.prefab_pilot.layout import _DRILLDOWN_BACKEND_NAME

    tools = await app.list_tools()
    drilldown = next(t for t in tools if t.name == "ngsiem_query_drilldown")
    expected_hash = drilldown.meta["fastmcp"]["_tool_hash"]
    assert _DRILLDOWN_BACKEND_NAME == f"{expected_hash}_ngsiem_query_drilldown"


@pytest.fixture
def anyio_backend():
    return "asyncio"
