"""
FastMCPApp pilot server — experimental stdio surface for Claude Desktop
rendering of NGSIEM query results.

Run directly with:

    python -m crowdstrike_mcp.prefab_pilot.server

…after installing the pilot extra:

    pip install -e '.[prefab-pilot]'

When ``CROWDSTRIKE_PREFAB_LIVE`` is truthy in the environment, the
``ngsiem_query_demo`` tool executes ``query`` against live NGSIEM
(credentials resolved through ``FalconClient``'s normal chain: env vars or
~/.config/falcon/credentials.json). Otherwise — or on live-path failure —
it falls back to deterministic synthetic data so the pilot remains
runnable without credentials. The text fallback explicitly reports which
path produced the rendered events.

See ``README.md`` in this package for the handoff notes to the next agent:
how to point Claude Desktop at this server, where to swap in real FalconPy
calls, and the manual verification checklist.
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from dataclasses import dataclass

from fastmcp.apps import FastMCPApp
from fastmcp.tools import ToolResult
from mcp.types import TextContent

from crowdstrike_mcp.prefab_pilot.fallback import summary_to_text
from crowdstrike_mcp.prefab_pilot.layout import build_ngsiem_query_layout
from crowdstrike_mcp.prefab_pilot.mock_data import generate_process_events
from crowdstrike_mcp.prefab_pilot.summary import summarize_events

app = FastMCPApp(name="crowdstrike-prefab-pilot")

DEFAULT_QUERY = "#repo=fdr event_simpleName=ProcessRollup2"
DEFAULT_START_TIME = "1h"
DEFAULT_MAX_RESULTS = 100
_LIVE_TRUTHY = {"1", "true", "yes", "on"}


def _live_mode_enabled() -> bool:
    return os.environ.get("CROWDSTRIKE_PREFAB_LIVE", "").strip().lower() in _LIVE_TRUTHY


@dataclass(frozen=True)
class _QueryOutcome:
    events: list[dict]
    source: str  # "live" | "mock"
    note: str | None  # extra context for the text fallback (e.g. live error)


def _run_live_query(query: str, start_time: str, max_results: int) -> dict:
    """Execute a CQL query against live NGSIEM. Lazy-imports to keep the
    pilot's startup surface small when creds are absent."""
    from crowdstrike_mcp.client import FalconClient
    from crowdstrike_mcp.modules.ngsiem import NGSIEMModule

    client = FalconClient()
    client.authenticate()
    module = NGSIEMModule(client)
    return module._execute_query(query, start_time=start_time, max_results=max_results)


def _fetch_events(
    query: str,
    start_time: str,
    max_results: int,
    seed: int,
    count: int,
) -> _QueryOutcome:
    """Return events from the live path when creds are configured, otherwise
    from the synthetic generator. Any live-path failure degrades gracefully
    to mock data with an explicit note so the UI still renders."""
    if not _live_mode_enabled():
        return _QueryOutcome(
            events=generate_process_events(count=count, seed=seed),
            source="mock",
            note="CROWDSTRIKE_PREFAB_LIVE is not truthy — showing synthetic events.",
        )
    try:
        result = _run_live_query(query, start_time, max_results)
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return _QueryOutcome(
            events=generate_process_events(count=count, seed=seed),
            source="mock",
            note=f"Live NGSIEM call raised {type(exc).__name__}: {exc} — showing synthetic events.",
        )
    if not result.get("success"):
        return _QueryOutcome(
            events=generate_process_events(count=count, seed=seed),
            source="mock",
            note=f"Live NGSIEM call failed: {result.get('error', 'unknown')} — showing synthetic events.",
        )
    events = result.get("events") or []
    if not events:
        return _QueryOutcome(
            events=[],
            source="live",
            note=(f"Live NGSIEM returned 0 events for query {query!r} over {start_time}. Widen the window or loosen the filter."),
        )
    return _QueryOutcome(events=events, source="live", note=None)


@app.ui("ngsiem_query_demo")
def ngsiem_query_demo(
    query: str = DEFAULT_QUERY,
    start_time: str = DEFAULT_START_TIME,
    max_results: int = DEFAULT_MAX_RESULTS,
    count: int = 30,
    seed: int = 1,
) -> ToolResult:
    """Render an NGSIEM query result as a Prefab UI.

    When ``CROWDSTRIKE_PREFAB_LIVE`` is truthy,
    ``query``/``start_time``/``max_results`` drive a live CQL search against
    the ``search-all`` repository (FalconClient resolves creds from env or
    the credential file). Otherwise ``count``/``seed`` drive a deterministic
    synthetic result so the pilot still renders offline. On live-path failure
    the tool falls back to mock data and surfaces the error in the text
    content — silent fallbacks are intentionally not supported.

    Returns a ToolResult carrying both the interactive Prefab layout (for
    hosts that render MCP Apps — Claude Desktop, Claude.ai) and a text
    summary (for Claude Code and other non-rendering hosts). FastMCP wraps
    the layout Component in a PrefabApp envelope automatically; we don't
    construct one manually because that would drop the text fallback.
    """
    outcome = _fetch_events(
        query=query,
        start_time=start_time,
        max_results=max_results,
        seed=seed,
        count=count,
    )
    summary = summarize_events(outcome.events)
    layout = build_ngsiem_query_layout(events=outcome.events, query=query, summary=summary)
    text = summary_to_text(summary, query=query)
    text = f"Source: {outcome.source}\n{text}"
    if outcome.note:
        text = f"{text}\nNote: {outcome.note}"

    return ToolResult(
        content=[TextContent(type="text", text=text)],
        structured_content=layout,
    )


@app.tool("ngsiem_query_drilldown")
def ngsiem_query_drilldown(row: dict) -> ToolResult:
    """Backend tool the UI calls when the user clicks a table row.

    The DataTable's ``on_row_click`` action passes the clicked row's full
    dict here as ``$event``. Earlier versions replayed a mock seed; the live
    row already carries every field the original event had (after #/@ key
    sanitization), so we just return it — no second NGSIEM round-trip needed.
    """
    if not isinstance(row, dict):
        return ToolResult(
            content=[TextContent(
                type="text",
                text=f"ngsiem_query_drilldown expected a row dict, got {type(row).__name__}",
            )],
        )
    return ToolResult(
        content=[TextContent(type="text", text=json.dumps(row, indent=2, default=str))],
        structured_content=row,
    )


def main() -> None:
    """Entry point: run the pilot server over stdio."""
    app.run(transport="stdio")


if __name__ == "__main__":
    main()
