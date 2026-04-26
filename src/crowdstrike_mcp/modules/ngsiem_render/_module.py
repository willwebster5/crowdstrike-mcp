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


# FastMCPApp name — surfaces in the renderer's _meta.fastmcp.app
# annotation so the host knows which Prefab "app" the rendered tree
# belongs to. Matches the main fastmcp.FastMCP server name.
_APP_NAME = "crowdstrike-falcon"


class NGSIEMRenderModule(BaseModule):
    """Render NGSIEM query results as interactive Prefab UI."""

    def __init__(self, client):
        super().__init__(client)
        # Internal NGSIEMModule instance for the shared execute_query call.
        # TODO: when a third consumer needs execute_query, promote it to a
        # free function in crowdstrike_mcp/queries/ngsiem.py so neither
        # module depends on instantiating the other.
        self._ngsiem = NGSIEMModule(client)
        # Build the FastMCPApp eagerly so the tool decorators run at
        # construction time, not at register_tools() time. Tools register
        # against self._app, then self._app gets added as a provider to
        # the main server in register_tools().
        self._app = FastMCPApp(_APP_NAME)
        self._register_app_tools()
        self._log(f"Initialized FastMCPApp '{_APP_NAME}' with 1 tool")

    def _register_app_tools(self) -> None:
        """Register UI tools on self._app (the FastMCPApp).

        Tool description distinguishes the user-rendering path from the
        agent-only ngsiem_query tool: the agent should pick this when the
        user wants to *see* results, not when the agent itself needs the
        full event data for reasoning.
        """
        self._app.ui(
            "ngsiem_query_render",
            description=(
                "Render an NGSIEM/CQL query result as an interactive Prefab UI "
                "for the user. Use this tool when the user asks to see, view, "
                "show, or visualize query results — NOT when you need the raw "
                "event data for your own reasoning (use ngsiem_query for that). "
                "Returns a brief summary plus a stored-response ref_id; call "
                "get_stored_response(ref_id=...) afterwards if you need to "
                "inspect specific events without re-running the query."
            ),
        )(self.ngsiem_query_render)
        self.tools.append("ngsiem_query_render")

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

        import os

        if os.environ.get("CROWDSTRIKE_RENDER_MOCK", "").strip().lower() in {"1", "true", "yes", "on"}:
            from crowdstrike_mcp.modules.ngsiem_render.mock_data import generate_process_events

            events_mock = generate_process_events(count=20, seed=1)
            result = {
                "success": True,
                "events": events_mock,
                "events_processed": len(events_mock),
                "events_matched": len(events_mock),
                "events_returned": len(events_mock),
                "query": query,
                "time_range": start_time,
            }
        else:
            result = self._ngsiem.execute_query(query, start_time=start_time, max_results=max_results)

        if not result.get("success"):
            error = result.get("error", "unknown error")
            return ToolResult(
                content=[
                    TextContent(
                        type="text",
                        text=f"NGSIEM render query failed: {error}",
                    )
                ],
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
        text_lines.append(f'To inspect specific events, call get_stored_response(ref_id="{ref_id}").')

        layout = build_ngsiem_query_layout(events=events, query=query, summary=summary)

        return ToolResult(
            content=[TextContent(type="text", text="\n".join(text_lines))],
            structured_content=layout,
        )
