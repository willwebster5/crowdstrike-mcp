"""
FastMCPApp pilot server — experimental stdio surface for Claude Desktop
rendering of NGSIEM query results.

Run directly with:

    python -m crowdstrike_mcp.prefab_pilot.server

…after installing the pilot extra:

    pip install -e '.[prefab-pilot]'

See ``README.md`` in this package for the handoff notes to the next agent:
how to point Claude Desktop at this server, where to swap in real FalconPy
calls, and the manual verification checklist.
"""

from __future__ import annotations

import json

from fastmcp.apps import FastMCPApp
from fastmcp.tools import ToolResult
from mcp.types import TextContent

from crowdstrike_mcp.prefab_pilot.fallback import summary_to_text
from crowdstrike_mcp.prefab_pilot.layout import build_ngsiem_query_layout
from crowdstrike_mcp.prefab_pilot.mock_data import generate_process_events
from crowdstrike_mcp.prefab_pilot.summary import summarize_events

app = FastMCPApp(name="crowdstrike-prefab-pilot")


@app.ui("ngsiem_query_demo")
def ngsiem_query_demo(
    count: int = 30,
    query: str = "#repo=fdr event_simpleName=ProcessRollup2",
    seed: int = 1,
) -> ToolResult:
    """Render a synthetic NGSIEM query result as a Prefab UI.

    Returns a ToolResult carrying both the interactive Prefab layout (for
    hosts that render MCP Apps — Claude Desktop, Claude.ai) and a text
    summary (for Claude Code and other non-rendering hosts).
    """
    events = generate_process_events(count=count, seed=seed)
    summary = summarize_events(events)
    layout = build_ngsiem_query_layout(events=events, query=query, summary=summary)
    text = summary_to_text(summary, query=query)

    return ToolResult(
        content=[TextContent(type="text", text=text)],
        structured_content=layout.model_dump(serialize_as_any=True),
    )


@app.tool("ngsiem_query_drilldown")
def ngsiem_query_drilldown(row_index: int, count: int = 30, seed: int = 1) -> ToolResult:
    """Backend tool the UI calls when the user clicks a table row.

    Returns the full JSON for a single event — much richer than the
    column set in the main table, useful for pivot decisions.
    """
    events = generate_process_events(count=count, seed=seed)
    if row_index < 0 or row_index >= len(events):
        return ToolResult(
            content=[TextContent(type="text", text=f"row_index {row_index} out of range (0..{len(events) - 1})")],
        )
    row = events[row_index]
    return ToolResult(
        content=[TextContent(type="text", text=json.dumps(row, indent=2))],
        structured_content=row,
    )


def main() -> None:
    """Entry point: run the pilot server over stdio."""
    app.run(transport="stdio")


if __name__ == "__main__":
    main()
