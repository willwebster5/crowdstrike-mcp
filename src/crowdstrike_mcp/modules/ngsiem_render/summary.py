"""
Model-facing summary reducer for NGSIEM query results.

This is the core of the context-window arbitrage story: the UI receives the
full result set, while the model receives only ``QuerySummary``. Everything
in ``QuerySummary`` should be compact enough to inline in a tool response
without pressure on the model's context window.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

# Epoch values above this threshold are treated as milliseconds, below as
# seconds. 1e11 seconds ≈ year 5138, so any modern epoch-seconds value stays
# well below; 1e11 milliseconds ≈ year 1973, so any modern epoch-ms value
# stays well above. This gives us a clean split without a format flag.
_EPOCH_MS_THRESHOLD = 10**11

_PROCESS_SCHEMA_KEYS = {"ComputerName", "event_simpleName"}
_TS_KEYS = {"@timestamp", "#ts", "timestamp", "time"}
_PIE_MAX_ROWS = 20
_SCATTER_MIN_ROWS = 3
_SCATTER_MAX_ROWS = 50


class WidgetType(str, Enum):
    """Which Prefab widget the layout should render for this query result.

    Detection runs once during ``summarize_events`` so every consumer agrees
    on the shape (the layout, the text fallback, future tests). Adding a new
    widget = add an enum value + a detection branch + a layout branch — no
    scattered ``is_X`` booleans.
    """

    RAW_EVENTS = "raw_events"          # has timestamps; show hourly bar + table
    AGGREGATE_TABLE = "aggregate_table"  # generic groupBy — show table only
    SINGLE_VALUE = "single_value"      # 1 row, 1 numeric field — render as Metric
    PIE_CANDIDATE = "pie_candidate"    # small-N label+count — show pie + table
    SCATTER = "scatter"                # label + ≥2 numerics — show scatter + table
    TIMECHART = "timechart"            # _bucket + _count — area chart, no table
    TIMECHART_MULTI = "timechart_multi"  # _bucket + multi-series — stacked area


@dataclass(frozen=True)
class QuerySummary:
    """Compact structured summary of an NGSIEM query result."""

    row_count: int
    widget_type: WidgetType = WidgetType.RAW_EVENTS
    top_host: tuple[str, int] | None = None
    top_event_name: tuple[str, int] | None = None
    time_range: tuple[str, str] | None = None
    hourly_buckets: list[dict] = field(default_factory=list)
    # SINGLE_VALUE
    single_value_label: str | None = None
    single_value: int | float | None = None
    # PIE_CANDIDATE — pre-formatted for prefab_ui.PieChart (data_key/name_key)
    pie_data: list[dict] = field(default_factory=list)  # [{"name": ..., "value": ...}]
    # TIMECHART_MULTI — series field names for AreaChart's ChartSeries list
    series_keys: list[str] = field(default_factory=list)
    # SCATTER — pre-formatted for prefab_ui.ScatterChart with sanitized keys
    scatter_data: list[dict] = field(default_factory=list)  # [{x: n, y: n, label: s}, ...]
    scatter_x: str | None = None  # data key for x-axis (sanitized, matches scatter_data keys)
    scatter_y: str | None = None  # data key for y-axis

    @property
    def is_timechart(self) -> bool:
        """True for any time-bucketed widget. Convenience for layout / fallback
        code that doesn't care which timechart variant produced the buckets."""
        return self.widget_type in (WidgetType.TIMECHART, WidgetType.TIMECHART_MULTI)


def _coerce_timestamp(raw: object) -> datetime | None:
    """Normalize any plausible NGSIEM @timestamp shape to a UTC datetime.

    Accepts: int/float epoch (seconds or milliseconds, auto-detected),
    numeric string (treated as epoch), ISO-8601 string. Returns ``None`` for
    anything we can't parse — the caller skips those events rather than
    crashing the whole reduction.
    """
    if raw is None:
        return None
    if isinstance(raw, bool):  # bool is a subclass of int — guard explicitly
        return None
    if isinstance(raw, (int, float)):
        return _epoch_to_datetime(float(raw))
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return None
        # Numeric string → epoch
        try:
            return _epoch_to_datetime(float(stripped))
        except ValueError:
            pass
        # ISO-8601
        try:
            dt = datetime.fromisoformat(stripped)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    return None


def _epoch_to_datetime(value: float) -> datetime | None:
    if value >= _EPOCH_MS_THRESHOLD:
        value = value / 1000.0
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _top(items: list[str]) -> tuple[str, int] | None:
    filtered = [i for i in items if isinstance(i, str) and i]
    if not filtered:
        return None
    value, count = Counter(filtered).most_common(1)[0]
    return (value, count)


def _hourly_buckets(datetimes: list[datetime]) -> list[dict]:
    if not datetimes:
        return []
    counts: Counter[str] = Counter()
    for dt in datetimes:
        hour = dt.replace(minute=0, second=0, microsecond=0)
        counts[hour.isoformat()] += 1
    return [{"hour": h, "count": c} for h, c in sorted(counts.items())]


def _is_numeric(v: object) -> bool:
    """Return True for int/float values and numeric strings (LogScale returns
    all event field values as strings, so '315841' must be treated as numeric)."""
    if isinstance(v, bool):
        return False
    if isinstance(v, (int, float)):
        return True
    if isinstance(v, str):
        try:
            float(v)
            return True
        except (ValueError, TypeError):
            return False
    return False


def _to_number(v: object) -> int | float | None:
    """Coerce a numeric value or numeric string to int/float. Returns None
    if the value cannot be converted."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, str):
        try:
            f = float(v)
            return int(f) if f == int(f) else f
        except (ValueError, TypeError):
            return None
    return None


def _first_string_field(events: list[dict], exclude: set[str]) -> str | None:
    """Return the first key in the first event that holds a real (non-numeric)
    non-empty string and is not in ``exclude``. Used for generic label-field
    detection. LogScale returns all values as strings — a count like ``"184"``
    is technically a string but is logically numeric, so we filter it out here
    or it would shadow the actual category label (e.g. ``#event_simpleName``)."""
    for ev in events[:5]:
        if not isinstance(ev, dict):
            continue
        for k, v in ev.items():
            if k not in exclude and isinstance(v, str) and v and not _is_numeric(v):
                return k
    return None


def _first_numeric_field(events: list[dict], exclude: set[str]) -> str | None:
    """Return the first key whose values look like counts/metrics."""
    for ev in events[:5]:
        if not isinstance(ev, dict):
            continue
        for k, v in ev.items():
            if k not in exclude and _is_numeric(v):
                return k
    return None


def _humanize_field(key: str) -> str:
    """`#repo`, `_count`, `event_simpleName` → `Repo`, `Count`, `Event Simple Name`.
    Used for label text on Metric and chart series names."""
    return key.lstrip("#@_").replace("_", " ").strip().title() or key


def _detect_widget_type(events: list[dict]) -> WidgetType:
    """Single source of truth for which Prefab widget renders this result.

    Order matters: SINGLE_VALUE and TIMECHART checks run before pie/aggregate
    detection because a 1-row aggregate is more usefully a Metric than a pie
    of one slice, and a `_bucket` row is always a time series even at small N.
    """
    if not events:
        return WidgetType.RAW_EVENTS  # empty — choice is moot

    first = events[0]
    if not isinstance(first, dict):
        return WidgetType.RAW_EVENTS

    has_process_schema = _PROCESS_SCHEMA_KEYS.issubset(first.keys())
    has_timestamp = any(k in first for k in _TS_KEYS)

    # 1) timechart() — _bucket present. Runs before SINGLE_VALUE so a 1-row
    #    timechart (rare but legal) stays a time series instead of collapsing
    #    to a Metric.
    if "_bucket" in first:
        numeric_keys = [
            k for k, v in first.items() if k != "_bucket" and _is_numeric(v)
        ]
        if len(numeric_keys) > 1:
            return WidgetType.TIMECHART_MULTI
        if len(numeric_keys) >= 1:
            return WidgetType.TIMECHART

    # 2) Single numeric value (count(), sum(), avg() with no breakout).
    #    Exclude raw events: a 1-row response that carries timestamps or the
    #    process schema is a single event, not a metric.
    if len(events) == 1 and not has_process_schema and not has_timestamp:
        numeric_keys = [k for k, v in first.items() if _is_numeric(v)]
        if len(numeric_keys) == 1:
            return WidgetType.SINGLE_VALUE

    # 3) Process schema or any rows with a real timestamp = raw events
    if has_process_schema or has_timestamp:
        return WidgetType.RAW_EVENTS

    # 4) Aggregate with one label + ≥2 numeric fields → scatter candidate.
    #    Runs before PIE_CANDIDATE so a query that produces both axes (e.g.
    #    `groupBy(host, [count(), avg(...)])`) renders the more informative
    #    scatter instead of a pie that picks just one numeric and discards the
    #    other.
    if _SCATTER_MIN_ROWS <= len(events) <= _SCATTER_MAX_ROWS:
        exclude = _TS_KEYS | {"_bucket"}
        numeric_count = sum(
            1 for k, v in first.items() if k not in exclude and _is_numeric(v)
        )
        if numeric_count >= 2 and _first_string_field(events, exclude):
            return WidgetType.SCATTER

    # 5) Small-N aggregate with a label + count → pie candidate (still also gets a table)
    if 2 <= len(events) <= _PIE_MAX_ROWS:
        exclude = _TS_KEYS | {"_bucket"}
        if _first_string_field(events, exclude) and _first_numeric_field(events, exclude):
            return WidgetType.PIE_CANDIDATE

    return WidgetType.AGGREGATE_TABLE


def _summarize_single_value(events: list[dict], row_count: int) -> QuerySummary:
    ev = events[0]
    num_key, raw_val = next((k, v) for k, v in ev.items() if _is_numeric(v))
    num_val = _to_number(raw_val) or 0
    # If the row also carries a category label, prefer that as the headline
    # ("fdr" reads better than "Count"); else humanize the numeric field name.
    string_fields = [(k, v) for k, v in ev.items() if isinstance(v, str) and v and not _is_numeric(v)]
    if string_fields:
        _, label = string_fields[0]
    else:
        label = _humanize_field(num_key)
    return QuerySummary(
        row_count=row_count,
        widget_type=WidgetType.SINGLE_VALUE,
        single_value_label=label,
        single_value=num_val,
    )


def _summarize_timechart(events: list[dict]) -> QuerySummary:
    """Single-series timechart (_bucket + _count or one numeric field)."""
    first = events[0]
    numeric_key = next(
        (k for k, v in first.items() if k != "_bucket" and _is_numeric(v)),
        "_count",
    )
    datetimes: list[datetime] = []
    buckets: list[dict] = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        dt = _coerce_timestamp(ev.get("_bucket"))
        if dt is None:
            continue
        datetimes.append(dt)
        # LogScale ships values as strings — coerce so the chart's y-axis sees
        # numbers (Recharts plots a string "184" as the category label, not a value).
        count = _to_number(ev.get(numeric_key)) or 0
        buckets.append({"hour": dt.isoformat(), "count": count})
    buckets.sort(key=lambda b: b["hour"])
    datetimes.sort()
    time_range = (datetimes[0].isoformat(), datetimes[-1].isoformat()) if datetimes else None
    return QuerySummary(
        row_count=len(events),
        widget_type=WidgetType.TIMECHART,
        time_range=time_range,
        hourly_buckets=buckets,
    )


def _summarize_timechart_multi(events: list[dict]) -> QuerySummary:
    """Multi-series timechart: _bucket + N numeric columns (one per series).

    Series field names are sanitized (# / @ stripped) so chart consumers can
    address them by plain identifiers — same convention as DataTable rows.
    """
    first = events[0]
    raw_series_keys = [k for k, v in first.items() if k != "_bucket" and _is_numeric(v)]
    # Sanitize (matches what the DataTable renderer expects)
    series_keys = [k.lstrip("#@") for k in raw_series_keys]
    datetimes: list[datetime] = []
    buckets: list[dict] = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        dt = _coerce_timestamp(ev.get("_bucket"))
        if dt is None:
            continue
        datetimes.append(dt)
        row = {"hour": dt.isoformat()}
        for raw, clean in zip(raw_series_keys, series_keys):
            row[clean] = _to_number(ev.get(raw)) or 0
        buckets.append(row)
    buckets.sort(key=lambda b: b["hour"])
    datetimes.sort()
    time_range = (datetimes[0].isoformat(), datetimes[-1].isoformat()) if datetimes else None
    return QuerySummary(
        row_count=len(events),
        widget_type=WidgetType.TIMECHART_MULTI,
        time_range=time_range,
        hourly_buckets=buckets,
        series_keys=series_keys,
    )


def _summarize_pie(events: list[dict]) -> QuerySummary:
    exclude = _TS_KEYS | {"_bucket"}
    label_field = _first_string_field(events, exclude)
    count_field = _first_numeric_field(events, exclude)
    pie_data: list[dict] = []
    names: list[str] = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        name = ev.get(label_field) if label_field else None
        raw_value = ev.get(count_field) if count_field else None
        value = _to_number(raw_value)
        if not isinstance(name, str) or not name or value is None:
            continue
        # Coerce to real numbers so PieChart slice sizes are angles, not labels —
        # Recharts treats string values as categorical and gives every slice an
        # equal angle when it can't compare them numerically.
        pie_data.append({"name": name, "value": value})
        names.append(name)
    return QuerySummary(
        row_count=len(events),
        widget_type=WidgetType.PIE_CANDIDATE,
        top_event_name=_top(names) if names else None,
        pie_data=pie_data,
    )


def _summarize_scatter(events: list[dict]) -> QuerySummary:
    """Aggregate with 1 label + ≥2 numeric fields. First numeric → X axis,
    second → Y axis. Field keys are sanitized (# / @ stripped) so axis names
    in the rendered chart aren't disfigured by NGSIEM's reserved-prefix sigils.
    """
    exclude = _TS_KEYS | {"_bucket"}
    first = events[0]
    label_field = _first_string_field(events, exclude)
    raw_numeric_keys = [
        k for k, v in first.items() if k not in exclude and _is_numeric(v)
    ]
    if len(raw_numeric_keys) < 2 or not label_field:
        # Defensive — detector should have ruled this out, but if events vary
        # in shape we degrade to AGGREGATE_TABLE rather than crash.
        return _summarize_aggregate(events)
    raw_x, raw_y = raw_numeric_keys[0], raw_numeric_keys[1]
    x_key = raw_x.lstrip("#@_") or raw_x
    y_key = raw_y.lstrip("#@_") or raw_y
    label_key = label_field.lstrip("#@") or label_field

    scatter_data: list[dict] = []
    names: list[str] = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        x_val = _to_number(ev.get(raw_x))
        y_val = _to_number(ev.get(raw_y))
        label_val = ev.get(label_field)
        if x_val is None or y_val is None or not isinstance(label_val, str) or not label_val:
            continue
        scatter_data.append({x_key: x_val, y_key: y_val, label_key: label_val})
        names.append(label_val)

    return QuerySummary(
        row_count=len(events),
        widget_type=WidgetType.SCATTER,
        top_event_name=_top(names) if names else None,
        scatter_data=scatter_data,
        scatter_x=x_key,
        scatter_y=y_key,
    )


def _summarize_raw_events(events: list[dict]) -> QuerySummary:
    """Process events / arbitrary raw events with timestamps."""
    first = events[0]
    is_process = _PROCESS_SCHEMA_KEYS.issubset(first.keys())

    hosts: list[str] = []
    names: list[str] = []
    datetimes: list[datetime] = []

    if is_process:
        for ev in events:
            if not isinstance(ev, dict):
                continue
            host = ev.get("ComputerName")
            if isinstance(host, str) and host:
                hosts.append(host)
            name = ev.get("event_simpleName")
            if isinstance(name, str) and name:
                names.append(name)
            dt = _coerce_timestamp(ev.get("@timestamp"))
            if dt is not None:
                datetimes.append(dt)
    else:
        # Generic raw events with some timestamp field
        label_field = _first_string_field(events, exclude=_TS_KEYS)
        for ev in events:
            if not isinstance(ev, dict):
                continue
            if label_field:
                val = ev.get(label_field)
                if isinstance(val, str) and val:
                    names.append(val)
            for tk in _TS_KEYS:
                dt = _coerce_timestamp(ev.get(tk))
                if dt is not None:
                    datetimes.append(dt)
                    break

    datetimes.sort()
    time_range = (datetimes[0].isoformat(), datetimes[-1].isoformat()) if datetimes else None
    return QuerySummary(
        row_count=len(events),
        widget_type=WidgetType.RAW_EVENTS,
        top_host=_top(hosts) if hosts else None,
        top_event_name=_top(names) if names else None,
        time_range=time_range,
        hourly_buckets=_hourly_buckets(datetimes),
    )


def _summarize_aggregate(events: list[dict]) -> QuerySummary:
    """Generic groupBy result with no time component and either >20 rows or
    no clear label+count pair. Falls back to a row count + table-only render."""
    exclude = _TS_KEYS | {"_bucket"}
    label_field = _first_string_field(events, exclude)
    names: list[str] = []
    if label_field:
        for ev in events:
            if isinstance(ev, dict):
                val = ev.get(label_field)
                if isinstance(val, str) and val:
                    names.append(val)
    return QuerySummary(
        row_count=len(events),
        widget_type=WidgetType.AGGREGATE_TABLE,
        top_event_name=_top(names) if names else None,
    )


def summarize_events(events: list[dict]) -> QuerySummary:
    """Reduce a list of NGSIEM events to a compact, widget-typed summary.

    Detection happens up-front (``_detect_widget_type``); each branch then
    builds the QuerySummary fields the layout needs for that widget. Adding a
    new widget type is a matter of adding to ``WidgetType``, the detector,
    a ``_summarize_<type>`` helper, and a layout branch.
    """
    if not events:
        return QuerySummary(row_count=0, widget_type=WidgetType.RAW_EVENTS)

    widget = _detect_widget_type(events)
    row_count = len(events)

    if widget == WidgetType.SINGLE_VALUE:
        return _summarize_single_value(events, row_count)
    if widget == WidgetType.TIMECHART:
        return _summarize_timechart(events)
    if widget == WidgetType.TIMECHART_MULTI:
        return _summarize_timechart_multi(events)
    if widget == WidgetType.PIE_CANDIDATE:
        return _summarize_pie(events)
    if widget == WidgetType.SCATTER:
        return _summarize_scatter(events)
    if widget == WidgetType.AGGREGATE_TABLE:
        return _summarize_aggregate(events)
    return _summarize_raw_events(events)
