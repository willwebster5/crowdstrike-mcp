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
