"""
Prefab layout assembly for the NGSIEM query pilot.

``build_ngsiem_query_layout`` returns a Prefab component tree (``Column``)
that the host renders inline. The ``@app.ui()`` wrapping happens in
``server.py``; this module stays pure so the layout is unit-testable.
"""

from __future__ import annotations

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
    Muted,
    Row,
    Text,
)
from prefab_ui.components.charts import BarChart, ChartSeries

from crowdstrike_mcp.prefab_pilot.summary import QuerySummary

_TABLE_COLUMNS = [
    DataTableColumn(key="@timestamp", header="Time", sortable=True, width="180px"),
    DataTableColumn(key="ComputerName", header="Host", sortable=True),
    DataTableColumn(key="event_simpleName", header="Event", sortable=True),
    DataTableColumn(key="UserName", header="User", sortable=True),
    DataTableColumn(key="ImageFileName", header="Image", sortable=False),
]


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


def _hourly_bar_chart(summary: QuerySummary) -> BarChart:
    return BarChart(
        data=summary.hourly_buckets,
        series=[ChartSeries(dataKey="count", label="Events per hour")],
        xAxis="hour",
        height=220,
    )


def _events_table(events: list[dict]) -> DataTable:
    return DataTable(
        columns=_TABLE_COLUMNS,
        rows=events,
        search=True,
        paginated=True,
        pageSize=25,
    )


def build_ngsiem_query_layout(
    events: list[dict],
    query: str,
    summary: QuerySummary,
) -> Column:
    """Build the full Prefab layout for an NGSIEM query result."""
    children: list = [
        Heading(content=f"NGSIEM query — {summary.row_count} events", level=2),
        Muted(content=f"query: {query}"),
        _summary_card(summary),
    ]

    if summary.hourly_buckets:
        children.append(_hourly_bar_chart(summary))

    if events:
        children.append(_events_table(events))

    return Column(children=children, gap=4)
