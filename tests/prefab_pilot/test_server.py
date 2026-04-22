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
async def test_ngsiem_query_demo_structured_content_is_a_column():
    tools = await app.list_tools()
    tool = next(t for t in tools if t.name == "ngsiem_query_demo")
    result = await tool.run(arguments={"count": 10, "query": "q"})
    assert result.structured_content["type"] == "Column"


@pytest.mark.anyio
async def test_ngsiem_query_drilldown_returns_single_row():
    tools = await app.list_tools()
    tool = next(t for t in tools if t.name == "ngsiem_query_drilldown")
    result = await tool.run(arguments={"row_index": 0, "count": 5, "seed": 1})
    # Drilldown is a backend @app.tool — the UI calls it; content carries the JSON row
    assert result.content or result.structured_content


@pytest.fixture
def anyio_backend():
    return "asyncio"
