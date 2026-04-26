"""Tests for NGSIEMRenderModule registration and tool wiring.

The module follows the fastmcp v2 composition pattern: at construction it
builds its own FastMCPApp, registers UI tools on the app, and on
register_tools(server) it mounts the app onto the main fastmcp.FastMCP
server via add_provider.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


def test_module_class_is_importable():
    from crowdstrike_mcp.modules.ngsiem_render import NGSIEMRenderModule
    assert NGSIEMRenderModule is not None


def test_module_registers_two_tools_on_internal_app_at_construction():
    """Tools register on the module's internal FastMCPApp eagerly so that
    register_tools(server) just needs to mount the app via add_provider."""
    from crowdstrike_mcp.modules.ngsiem_render import NGSIEMRenderModule

    mock_client = MagicMock()
    module = NGSIEMRenderModule(mock_client)

    assert "ngsiem_query_render" in module.tools
    assert "ngsiem_query_drilldown" in module.tools
    # The internal app must exist and be a FastMCPApp.
    from fastmcp.apps import FastMCPApp
    assert isinstance(module._app, FastMCPApp)


def test_module_register_tools_adds_provider_to_server():
    """register_tools(server) calls server.add_provider with the internal app."""
    from crowdstrike_mcp.modules.ngsiem_render import NGSIEMRenderModule

    mock_client = MagicMock()
    module = NGSIEMRenderModule(mock_client)

    fake_server = MagicMock()
    module.register_tools(fake_server)

    fake_server.add_provider.assert_called_once_with(module._app)


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_render_tool_returns_tool_result_with_text_and_structured_content(monkeypatch):
    from crowdstrike_mcp.modules.ngsiem_render import NGSIEMRenderModule
    from crowdstrike_mcp.modules.ngsiem_render.mock_data import generate_process_events

    mock_client = MagicMock()
    module = NGSIEMRenderModule(mock_client)

    # Stub execute_query to return mock events deterministically.
    def fake_exec(query, start_time="1d", max_results=100, fields=None):
        return {
            "success": True,
            "events": generate_process_events(count=5, seed=1),
            "events_processed": 5, "events_matched": 5, "events_returned": 5,
            "query": query, "time_range": start_time,
        }
    monkeypatch.setattr(module._ngsiem, "execute_query", fake_exec)

    result = await module.ngsiem_query_render(query="q", start_time="1h")
    text = "\n".join(b.text for b in result.content if hasattr(b, "text"))
    assert "5 events" in text or "Events: 5" in text
    assert "ref_id" in text or "resp_" in text
    assert result.structured_content is not None


@pytest.mark.anyio
async def test_render_tool_text_fallback_includes_ref_id_resolvable_via_response_store(monkeypatch):
    import re
    from crowdstrike_mcp.modules.ngsiem_render import NGSIEMRenderModule
    from crowdstrike_mcp.modules.ngsiem_render.mock_data import generate_process_events
    from crowdstrike_mcp.response_store import ResponseStore

    ResponseStore._reset()

    mock_client = MagicMock()
    module = NGSIEMRenderModule(mock_client)

    def fake_exec(query, start_time="1d", max_results=100, fields=None):
        return {"success": True, "events": generate_process_events(count=3, seed=1),
                "events_processed": 3, "events_matched": 3, "events_returned": 3,
                "query": query, "time_range": start_time}
    monkeypatch.setattr(module._ngsiem, "execute_query", fake_exec)

    result = await module.ngsiem_query_render(query="q")
    text = "\n".join(b.text for b in result.content if hasattr(b, "text"))
    match = re.search(r"resp_\d+", text)
    assert match is not None, f"no ref_id in fallback text:\n{text}"
    stored = ResponseStore.get(match.group(0))
    assert stored is not None
    assert stored.tool_name == "ngsiem_query_render"


@pytest.mark.anyio
async def test_render_tool_query_failure_returns_error_text(monkeypatch):
    """If execute_query returns success=False, the tool surfaces the error
    in text content rather than crashing."""
    from crowdstrike_mcp.modules.ngsiem_render import NGSIEMRenderModule

    mock_client = MagicMock()
    module = NGSIEMRenderModule(mock_client)

    def fake_exec(query, start_time="1d", max_results=100, fields=None):
        return {"success": False, "error": "HTTP 403: forbidden"}
    monkeypatch.setattr(module._ngsiem, "execute_query", fake_exec)

    result = await module.ngsiem_query_render(query="q")
    text = "\n".join(b.text for b in result.content if hasattr(b, "text"))
    assert "failed" in text.lower()
    assert "HTTP 403" in text


def test_drilldown_returns_row_as_text_and_structured_content():
    from crowdstrike_mcp.modules.ngsiem_render import NGSIEMRenderModule

    mock_client = MagicMock()
    module = NGSIEMRenderModule(mock_client)
    row = {"ComputerName": "H-01", "event_simpleName": "ProcessRollup2"}
    result = module.ngsiem_query_drilldown(row)

    assert result.structured_content == row
    text = "\n".join(b.text for b in result.content if hasattr(b, "text"))
    assert "H-01" in text
    assert "ProcessRollup2" in text


def test_drilldown_with_non_dict_returns_typed_error():
    from crowdstrike_mcp.modules.ngsiem_render import NGSIEMRenderModule

    mock_client = MagicMock()
    module = NGSIEMRenderModule(mock_client)
    result = module.ngsiem_query_drilldown("not a dict")
    text = "\n".join(b.text for b in result.content if hasattr(b, "text"))
    assert "expected a row dict" in text
    assert "str" in text
