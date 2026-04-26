"""
Prefab layout assembly for the NGSIEM query pilot.

``build_ngsiem_query_layout`` returns a Prefab component tree (``Column``)
that the host renders inline. The widget composition for each result is
chosen by ``summary.widget_type`` — see ``summary.WidgetType``. The
``@app.ui()`` wrapping happens in ``server.py``; this module stays pure so
the layout is unit-testable.
"""

from __future__ import annotations

from fastmcp.server.providers.addressing import hashed_backend_name
from prefab_ui.actions.mcp import CallTool
from prefab_ui.components import (
    Badge,
    Card,
    CardContent,
    CardHeader,
    CardTitle,
    Column,
    DataTable,
    DataTableColumn,
    Heading,
    Metric,
    Muted,
    Row,
    Text,
)
from prefab_ui.components.charts import AreaChart, BarChart, ChartSeries, PieChart, ScatterChart

from crowdstrike_mcp.modules.ngsiem_render.summary import QuerySummary, WidgetType

# FastMCP routes backend-tool calls by a deterministic hash of (app_name,
# tool_name) — see fastmcp.server.providers.addressing. When we ship an
# action like CallTool("ngsiem_query_drilldown", ...) inside a layout we
# build ourselves (i.e. via ToolResult.structured_content), FastMCP's
# resolver doesn't get to swap the bare name for the wire-format name
# (the resolver only fires when the handler returns a bare PrefabApp /
# Component, which we don't because we want to keep the text fallback).
# Pre-compute the wire name here so the action ships ready to dispatch.
#
# The app name MUST match the FastMCPApp(name=...) in server.py.
_APP_NAME = "crowdstrike-falcon"
_DRILLDOWN_BACKEND_NAME = hashed_backend_name(_APP_NAME, "ngsiem_query_drilldown")

_PROCESS_COLUMNS = [
    DataTableColumn(key="timestamp", header="Time", sortable=True, width="180px"),
    DataTableColumn(key="ComputerName", header="Host", sortable=True),
    DataTableColumn(key="event_simpleName", header="Event", sortable=True),
    DataTableColumn(key="UserName", header="User", sortable=True),
    DataTableColumn(key="ImageFileName", header="Image", sortable=False),
]

_PROCESS_SCHEMA_KEYS = {"ComputerName", "event_simpleName", "UserName", "ImageFileName"}


# Fields to surface first when inferring columns from arbitrary events.
# Any of these present in the data will appear as the leading columns
# in the order listed here; remaining fields fill the rest (up to the cap).
_PREFERRED_FIELDS = [
    "timestamp",
    "ComputerName",
    "event_simpleName",
    "UserName",
    "name",
    "ImageFileName",
    "aid",
    "repo",
    "event_count",
]
# Internal/noisy fields to push to the end or omit entirely.
_DEPRIORITIZED_FIELDS = {
    "rawstring",
    "ingesttimestamp",
    "humioAutoShard",
    "repo.cid",
    "sourcetype",
    "timezone",
    "id",
    "cid",
}


def _humanize(key: str) -> str:
    """`#repo` / `_count` / `event_simpleName` → readable series labels."""
    return key.lstrip("#@_").replace("_", " ").strip().title() or key


def _infer_columns(events: list[dict]) -> list[DataTableColumn]:
    """Build DataTableColumn list from the actual keys present in events.

    Preferred fields (timestamp, ComputerName, etc.) appear first if present.
    Noisy internal fields are deprioritized. Caps at 10 columns total.
    """
    # Collect all keys across first 20 events
    seen: dict[str, None] = {}
    for ev in events[:20]:
        for k in ev.keys():
            seen[k] = None
    all_keys = set(seen.keys())

    # Preferred first, then remaining non-deprioritized, then deprioritized
    ordered: list[str] = []
    for k in _PREFERRED_FIELDS:
        if k in all_keys:
            ordered.append(k)
    for k in seen:  # preserves insertion order
        if k not in ordered and k not in _DEPRIORITIZED_FIELDS:
            ordered.append(k)
    for k in seen:
        if k not in ordered:
            ordered.append(k)

    keys = ordered[:10]
    cols = []
    for k in keys:
        header = k.replace("_", " ").title()
        width = "180px" if k == "timestamp" else None
        cols.append(DataTableColumn(key=k, header=header, sortable=True, **({"width": width} if width else {})))
    return cols


def _get_columns(events: list[dict]) -> list[DataTableColumn]:
    """Return hardcoded process columns when events look like ProcessRollup2,
    otherwise infer columns from the actual event schema."""
    if not events:
        return _PROCESS_COLUMNS
    first = events[0]
    if _PROCESS_SCHEMA_KEYS.issubset(first.keys()):
        return _PROCESS_COLUMNS
    return _infer_columns(events)


def _summary_card(summary: QuerySummary) -> Card:
    badges: list = [Badge(children=[Text(content=f"{summary.row_count} events")])]
    if summary.top_host is not None:
        host, count = summary.top_host
        badges.append(Badge(children=[Text(content=f"top host: {host} ({count})")]))
    if summary.top_event_name is not None:
        name, count = summary.top_event_name
        badges.append(Badge(children=[Text(content=f"top event: {name} ({count})")]))
    if summary.time_range is not None:
        start, end = summary.time_range
        badges.append(Badge(children=[Text(content=f"{start} → {end}")]))

    return Card(
        children=[
            CardHeader(children=[CardTitle(content="Summary")]),
            CardContent(children=[Row(children=badges, gap=2)]),
        ]
    )


def _hourly_chart(summary: QuerySummary) -> AreaChart | BarChart:
    """AreaChart for timechart() output (single or multi-series), BarChart
    for the synthetic hourly distribution on raw event queries."""
    if summary.widget_type == WidgetType.TIMECHART_MULTI:
        return AreaChart(
            data=summary.hourly_buckets,
            series=[ChartSeries(dataKey=k, label=_humanize(k)) for k in summary.series_keys],
            xAxis="hour",
            height=320,
            stacked=True,
            curve="smooth",
            y_axis_format="compact",
        )
    if summary.widget_type == WidgetType.TIMECHART:
        return AreaChart(
            data=summary.hourly_buckets,
            series=[ChartSeries(dataKey="count", label="Events")],
            xAxis="hour",
            height=300,
            curve="smooth",
            y_axis_format="compact",
        )
    return BarChart(
        data=summary.hourly_buckets,
        series=[ChartSeries(dataKey="count", label="Events per hour")],
        xAxis="hour",
        height=220,
    )


def _metric(summary: QuerySummary) -> Card:
    """Single-value Metric wrapped in a Card, centered and padded for hero presence."""
    val = summary.single_value if summary.single_value is not None else 0
    formatted = f"{int(val):,}" if isinstance(val, (int, float)) else str(val)
    return Card(
        children=[
            CardContent(
                css_class="flex flex-col items-center justify-center py-12",
                children=[
                    Metric(
                        label=summary.single_value_label or "Result",
                        value=formatted,
                        css_class="text-center scale-200",
                    ),
                ],
            ),
        ]
    )


def _pie_chart(summary: QuerySummary) -> PieChart:
    return PieChart(
        data=summary.pie_data,
        data_key="value",
        name_key="name",
        inner_radius=60,
        show_legend=True,
        height=300,
    )


def _scatter_chart(summary: QuerySummary) -> ScatterChart:
    """Two-numeric aggregate as points. X = first numeric, Y = second; the
    label field rides along on each point so the renderer's tooltip can
    show which row produced the dot."""
    y_label = _humanize(summary.scatter_y or "y")
    return ScatterChart(
        data=summary.scatter_data,
        series=[ChartSeries(dataKey=summary.scatter_y or "y", label=y_label)],
        xAxis=summary.scatter_x or "x",
        yAxis=summary.scatter_y or "y",
        height=320,
    )


def _sanitize_row(row: dict) -> dict:
    """Rekey any field whose name starts with # or @ to a plain identifier.

    The Prefab DataTable renderer runs in JS where object keys starting with
    # are valid JSON but can cause lookup mismatches against DataTableColumn
    key strings in some renderer builds. We sanitize on the Python side so
    column keys and row keys always agree.
    """
    return {
        k.lstrip("#@"): v
        for k, v in row.items()
        if k.lstrip("#@")  # skip keys that are *only* # or @
    }


def _events_table(events: list[dict]) -> DataTable:
    sanitized = [_sanitize_row(r) for r in events]
    return DataTable(
        columns=_get_columns(sanitized),
        rows=sanitized,
        search=True,
        paginated=True,
        pageSize=25,
        onRowClick=CallTool(
            _DRILLDOWN_BACKEND_NAME,
            arguments={"row": "{{ $event }}"},
        ),
    )


def build_ngsiem_query_layout(
    events: list[dict],
    query: str,
    summary: QuerySummary,
) -> Column:
    """Build the full Prefab layout for an NGSIEM query result.

    Composition is dispatched on ``summary.widget_type`` — each branch picks
    the visual shape that fits the query result. Adding a new widget type
    means adding a branch here and a detection rule in ``summary.py``.
    """
    children: list = [
        Heading(content=f"NGSIEM query — {summary.row_count} events", level=2),
        Muted(content=f"query: {query}"),
    ]

    wt = summary.widget_type

    # Single-value queries (count(), sum(), avg()) get a clean Metric — the
    # number IS the summary, so a separate summary card would be redundant.
    if wt == WidgetType.SINGLE_VALUE:
        children.append(_metric(summary))
        return Column(children=children, gap=4)

    children.append(_summary_card(summary))

    # Time series — chart only, no raw bucket table (the chart is the data)
    if wt in (WidgetType.TIMECHART, WidgetType.TIMECHART_MULTI):
        if summary.hourly_buckets:
            children.append(_hourly_chart(summary))
        return Column(children=children, gap=4)

    # Small-N category aggregate — pie alongside the table for cross-reference
    if wt == WidgetType.PIE_CANDIDATE:
        if summary.pie_data:
            children.append(_pie_chart(summary))
        if events:
            children.append(_events_table(events))
        return Column(children=children, gap=4)

    # 2-numeric aggregate — scatter plot with the table below for exact values
    if wt == WidgetType.SCATTER:
        if summary.scatter_data:
            children.append(_scatter_chart(summary))
        if events:
            children.append(_events_table(events))
        return Column(children=children, gap=4)

    # RAW_EVENTS or AGGREGATE_TABLE — hourly bar (only if we found timestamps)
    # and the table.
    if summary.hourly_buckets:
        children.append(_hourly_chart(summary))
    if events:
        children.append(_events_table(events))

    return Column(children=children, gap=4)
