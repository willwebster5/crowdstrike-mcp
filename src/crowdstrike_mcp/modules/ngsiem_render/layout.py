"""
Prefab layout assembly for the NGSIEM query pilot.

``build_ngsiem_query_layout`` returns a Prefab component tree (``Column``)
that the host renders inline. The widget composition for each result is
chosen by ``summary.widget_type`` — see ``summary.WidgetType``. The
``@app.ui()`` wrapping happens in ``server.py``; this module stays pure so
the layout is unit-testable.
"""

from __future__ import annotations

import json

from prefab_ui.actions import OpenLink
from prefab_ui.actions.mcp import SendMessage
from prefab_ui.components import (
    Badge,
    Button,
    Card,
    CardContent,
    CardHeader,
    CardTitle,
    Column,
    DataTable,
    DataTableColumn,
    ExpandableRow,
    Form,
    Heading,
    Metric,
    Muted,
    Popover,
    Row,
    Text,
    Textarea,
)
from prefab_ui.components.charts import AreaChart, BarChart, ChartSeries, PieChart, ScatterChart

from crowdstrike_mcp.modules.ngsiem_render.summary import QuerySummary, WidgetType

# TODO: replace with the customer's Falcon tenant URL pattern once known.
# This stub points at the public host-management page; clicking will at
# least land the user in their Falcon console even if the path is wrong.
_FALCON_HOST_URL_TEMPLATE = "https://falcon.crowdstrike.com/host-management/host/{aid}"

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


def _row_fields_card(row: dict) -> Card:
    """Render every field of the row as label/value Text pairs.

    Keeps things readable for wide rows: long values truncate at 200
    chars in the visible Text but the full value still ships in the
    SendMessage payloads (which include the row JSON).
    """
    rows: list = []
    for key, value in row.items():
        s_value = str(value)
        if len(s_value) > 200:
            s_value = s_value[:200] + "…"
        rows.append(Row(children=[Muted(content=f"{key}:"), Text(content=s_value)], gap=2))
    return Card(
        children=[
            CardHeader(children=[CardTitle(content="Row data")]),
            CardContent(children=[Column(children=rows, gap=1)]),
        ]
    )


def _ask_button(label: str, prompt: str) -> Button:
    """Send-a-message button with a baked-in natural-language prompt.

    All row-actions are intentionally framed as natural language: we ship
    the agent context and let it decide which tools to run, rather than
    pre-canning specific CQL queries.
    """
    return Button(label=label, on_click=SendMessage(prompt))


def _correlate_popover(row: dict, row_json: str) -> Popover | None:
    """Open a sub-menu of correlation prompts. Each item is conditional
    on a relevant field being present — if no fields are present, the
    whole popover is omitted (returns None)."""
    user = row.get("UserName") or row.get("user.name") or row.get("UPN")
    host = row.get("ComputerName")
    aid = row.get("aid")
    src_ip = row.get("source.ip") or row.get("LocalAddressIP4")
    image = row.get("ImageFileName")
    sha = row.get("SHA256HashData") or row.get("sha256")
    event_name = row.get("event_simpleName")

    items: list[Button] = []
    if user:
        items.append(
            _ask_button(
                "User",
                f"What other activity is associated with user '{user}' around this event? "
                f"Look across endpoints, SaaS auth, and network. Row context:\n{row_json}",
            )
        )
    if host or aid:
        items.append(
            _ask_button(
                "Endpoint / Host",
                f"What else happened on host {host or aid!r} around this event? "
                f"Surface notable processes, user logons, and outbound connections. Row context:\n{row_json}",
            )
        )
    if user or host:
        items.append(
            _ask_button(
                "SaaS",
                f"Are there SaaS-auth events (Azure AD, Okta, GWS) tied to "
                f"{('user ' + user) if user else ('host ' + str(host))} around this event? Row context:\n{row_json}",
            )
        )
    if src_ip or host:
        items.append(
            _ask_button(
                "Network",
                f"Show network activity related to {('IP ' + str(src_ip)) if src_ip else ('host ' + str(host))} "
                f"around this event. Row context:\n{row_json}",
            )
        )
    if image or sha or event_name:
        items.append(
            _ask_button(
                "IOC",
                f"Are there other instances of this signature ({event_name or 'this event'}, "
                f"{image or sha or 'no file/hash'}) on other hosts in the last 24 hours? Row context:\n{row_json}",
            )
        )

    if not items:
        return None

    return Popover(
        title="Correlate this event",
        side="bottom",
        children=[
            Button(label="Correlate ▾", variant="outline"),
            Column(children=items, gap=1),
        ],
    )


def _pivot_popover(row: dict, row_json: str) -> Popover | None:
    """Sub-menu of pivot prompts (more events from same host/user/etc)."""
    user = row.get("UserName")
    host = row.get("ComputerName")
    event_name = row.get("event_simpleName")
    timestamp = row.get("timestamp") or row.get("@timestamp")

    items: list[Button] = []
    if host:
        items.append(
            _ask_button(
                "Same host",
                f"Show all events on host '{host}' in the last 1 hour. Row context:\n{row_json}",
            )
        )
    if user:
        items.append(
            _ask_button(
                "Same user",
                f"Show all events for user '{user}' in the last 1 hour. Row context:\n{row_json}",
            )
        )
    if event_name:
        items.append(
            _ask_button(
                "Same event_simpleName",
                f"Show all '{event_name}' events in the last 1 hour. Row context:\n{row_json}",
            )
        )
    if timestamp:
        items.append(
            _ask_button(
                "Time window ±5 min",
                f"Show all events within ±5 minutes of {timestamp}. Row context:\n{row_json}",
            )
        )

    if not items:
        return None

    return Popover(
        title="Pivot from this event",
        side="bottom",
        children=[
            Button(label="Pivot ▾", variant="outline"),
            Column(children=items, gap=1),
        ],
    )


def _open_in_falcon_button(row: dict) -> Button | None:
    """Open the host's page in the Falcon console. Hidden when no aid."""
    aid = row.get("aid")
    if not aid:
        return None
    return Button(
        label="Open in Falcon",
        variant="outline",
        on_click=OpenLink(_FALCON_HOST_URL_TEMPLATE.format(aid=aid)),
    )


def _custom_prompt_form(row: dict, row_json: str, prompt_state_key: str) -> Form:
    """Free-form prompt input — the user types a question, the agent
    receives it with the row JSON appended as context."""
    submit_template = "{{ " + prompt_state_key + " }}\n\nRow context (NGSIEM event):\n```json\n" + row_json + "\n```"
    return Form(
        on_submit=SendMessage(submit_template),
        gap=2,
        children=[
            Muted(content="Ask Claude something about this event:"),
            Textarea(
                name=prompt_state_key,
                placeholder="e.g., Is this normal for this user? Compare to baseline…",
                rows=3,
            ),
            Row(children=[Button(label="Send to Claude", button_type="submit")], gap=2),
        ],
    )


def _row_detail_panel(row: dict, row_index: int) -> Card:
    """Build the full ExpandableRow detail Component for one row.

    Layout:
        Card[
          row fields (label/value pairs)
          custom prompt Form
          Row[ Ask Claude | Correlate ▾ | Pivot ▾ | Open in Falcon ]
        ]
    """
    row_json = json.dumps(row, indent=2, default=str)
    prompt_state_key = f"row_{row_index}_prompt"

    action_buttons: list = [
        _ask_button(
            "Ask Claude about this event",
            f"What's notable about this NG-SIEM event? Anything suspicious, unusual, or worth following up on?\n```json\n{row_json}\n```",
        ),
    ]
    correlate = _correlate_popover(row, row_json)
    if correlate is not None:
        action_buttons.append(correlate)
    pivot = _pivot_popover(row, row_json)
    if pivot is not None:
        action_buttons.append(pivot)
    falcon = _open_in_falcon_button(row)
    if falcon is not None:
        action_buttons.append(falcon)

    return Card(
        children=[
            CardContent(
                children=[
                    Column(
                        gap=4,
                        children=[
                            _row_fields_card(row),
                            _custom_prompt_form(row, row_json, prompt_state_key),
                            Row(children=action_buttons, gap=2),
                        ],
                    )
                ]
            )
        ]
    )


def _events_table(events: list[dict]) -> DataTable:
    sanitized = [_sanitize_row(r) for r in events]
    rows: list = [ExpandableRow(row, detail=_row_detail_panel(row, i)) for i, row in enumerate(sanitized)]
    return DataTable(
        columns=_get_columns(sanitized),
        rows=rows,
        search=True,
        paginated=True,
        pageSize=25,
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
