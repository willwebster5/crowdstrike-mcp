"""
NGSIEMRenderModule — UI tool that renders NGSIEM query results as Prefab.

Auto-discovered via registry.py. Holds an internal NGSIEMModule instance
to share the query engine without depending on auto-discovery instance
sharing (registry instantiates each module class with cls(client)).

Uses the fastmcp v2 composition pattern: constructs its own FastMCPApp,
registers UI tools via @app.ui() and @app.tool() on the FastMCPApp, then
mounts the app onto the main fastmcp.FastMCP server via add_provider().
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastmcp.apps import FastMCPApp

from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.modules.ngsiem import NGSIEMModule

if TYPE_CHECKING:
    from fastmcp import FastMCP


# Must match the FastMCPApp(name=...) below and the _APP_NAME constant
# in layout.py — drives the drilldown wire-format hash.
_APP_NAME = "crowdstrike-falcon"


class NGSIEMRenderModule(BaseModule):
    """Render NGSIEM query results as interactive Prefab UI."""

    def __init__(self, client):
        super().__init__(client)
        self._ngsiem = NGSIEMModule(client)
        # Build the FastMCPApp eagerly so the tool decorators run at
        # construction time, not at register_tools() time. Tools register
        # against self._app, then self._app gets added as a provider to
        # the main server in register_tools().
        self._app = FastMCPApp(_APP_NAME)
        self._register_app_tools()
        self._log("Initialized")

    def _register_app_tools(self) -> None:
        """Register UI tools on self._app (the FastMCPApp). The methods'
        bodies are placeholders here; Tasks 9 and 10 replace them."""
        self._app.ui("ngsiem_query_render")(self.ngsiem_query_render)
        self._app.tool("ngsiem_query_drilldown")(self.ngsiem_query_drilldown)
        # Track names for visibility (BaseModule.tools list is part of the
        # registration contract — tests inspect it).
        self.tools.append("ngsiem_query_render")
        self.tools.append("ngsiem_query_drilldown")

    def register_tools(self, server: "FastMCP") -> None:
        """Mount the FastMCPApp onto the main fastmcp.FastMCP server."""
        server.add_provider(self._app)

    async def ngsiem_query_render(
        self,
        query: str,
        start_time: str = "1d",
        max_results: int = 100,
    ):
        """Render an NGSIEM query result as Prefab UI for the user.

        Returns a ToolResult carrying:
          - content: short text summary including a ResponseStore ref_id
            so the agent can inspect specific events via
            get_stored_response(ref_id=...) without re-running the query.
          - structured_content: the Prefab UI layout component. FastMCPApp
            wraps it in the PrefabApp envelope at delivery time.
        """
        from fastmcp.tools import ToolResult
        from mcp.types import TextContent

        from crowdstrike_mcp.modules.ngsiem_render.layout import build_ngsiem_query_layout
        from crowdstrike_mcp.modules.ngsiem_render.summary import summarize_events
        from crowdstrike_mcp.response_store import ResponseStore

        max_results = min(max(max_results, 1), 1000)
        result = self._ngsiem.execute_query(query, start_time=start_time, max_results=max_results)

        if not result.get("success"):
            error = result.get("error", "unknown error")
            return ToolResult(
                content=[TextContent(
                    type="text",
                    text=f"NGSIEM render query failed: {error}",
                )],
            )

        events = result.get("events") or []
        summary = summarize_events(events)

        ref_id = ResponseStore.store(
            data={"events": events, "query": result.get("query"), "time_range": result.get("time_range")},
            tool_name="ngsiem_query_render",
            metadata={"query": query, "start_time": start_time},
        )

        text_lines = [
            "Rendered NGSIEM query for the user.",
            f"Query: {query}",
            f"Time range: {start_time}",
            f"Events: {summary.row_count}",
        ]
        if summary.top_host is not None:
            host, count = summary.top_host
            text_lines.append(f"Top host: {host} ({count})")
        text_lines.append(f"To inspect specific events, call get_stored_response(ref_id=\"{ref_id}\").")

        layout = build_ngsiem_query_layout(events=events, query=query, summary=summary)

        return ToolResult(
            content=[TextContent(type="text", text="\n".join(text_lines))],
            structured_content=layout,
        )

    def ngsiem_query_drilldown(self, row: dict):
        """Placeholder — implemented in Task 10."""
        raise NotImplementedError("Implemented in Task 10")
