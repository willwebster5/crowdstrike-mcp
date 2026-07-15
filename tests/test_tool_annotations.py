"""Tests for MCP ToolAnnotations emitted by BaseModule._add_tool.

Annotations are standard MCP hints (readOnlyHint, destructiveHint,
idempotentHint, openWorldHint) that clients use to group and badge tools.
They are derived from the tier a module already declares, plus optional
per-tool destructive/idempotent flags.
"""

from mcp.server.fastmcp import FastMCP

from crowdstrike_mcp.modules.base import BaseModule


class _Probe(BaseModule):
    """Minimal concrete module so we can exercise _add_tool directly."""

    def register_tools(self, server: FastMCP) -> None:  # pragma: no cover - unused
        pass


def _register(**add_tool_kwargs):
    """Register one tool through _add_tool and return its MCP annotations."""
    server = FastMCP("test")
    module = _Probe(client=object())
    module.allow_writes = True
    module._add_tool(server, lambda: "ok", **add_tool_kwargs)
    tool = server._tool_manager.list_tools()[0]
    return tool.annotations


def test_read_tool_is_marked_read_only():
    ann = _register(name="get_thing", tier="read")
    assert ann is not None
    assert ann.readOnlyHint is True
    assert ann.destructiveHint is None


def test_every_tool_is_marked_open_world():
    """All tools reach the external Falcon API, so openWorldHint is always true."""
    read = _register(name="get_thing", tier="read")
    write = _register(name="set_thing", tier="write")
    assert read.openWorldHint is True
    assert write.openWorldHint is True


def test_write_tool_is_not_read_only():
    ann = _register(name="set_thing", tier="write")
    assert ann.readOnlyHint is False


def test_destructive_flag_sets_destructive_hint():
    ann = _register(name="contain_host", tier="write", destructive=True)
    assert ann.readOnlyHint is False
    assert ann.destructiveHint is True


def test_idempotent_flag_sets_idempotent_hint():
    ann = _register(name="set_status", tier="write", idempotent=True)
    assert ann.idempotentHint is True


def test_read_tool_ignores_destructive_flag():
    """destructiveHint is only meaningful for non-read-only tools."""
    ann = _register(name="get_thing", tier="read", destructive=True)
    assert ann.readOnlyHint is True
    assert ann.destructiveHint is None


def _real_server_annotations():
    """Register every module into a real FastMCP and index annotations by tool name."""
    from unittest.mock import MagicMock

    from crowdstrike_mcp.registry import get_available_modules
    from tests.test_smoke_tools_list import _patch_falconpy

    with _patch_falconpy():
        modules = get_available_modules(MagicMock(), allow_writes=True)
        server = FastMCP("integration")
        for mod in modules:
            mod.register_tools(server)
    return {t.name: t.annotations for t in server._tool_manager.list_tools()}


def test_specific_tools_are_annotated_end_to_end():
    ann = _real_server_annotations()

    # A representative read tool: read-only, external.
    assert ann["get_alerts"].readOnlyHint is True
    assert ann["get_alerts"].openWorldHint is True

    # Containment is a disruptive write.
    assert ann["host_contain"].readOnlyHint is False
    assert ann["host_contain"].destructiveHint is True

    # Lifting containment and status updates are idempotent, not destructive.
    assert ann["host_lift_containment"].idempotentHint is True
    assert ann["update_alert_status"].idempotentHint is True
    assert ann["update_alert_status"].readOnlyHint is False
