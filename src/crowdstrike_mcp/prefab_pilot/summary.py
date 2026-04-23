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

# Epoch values above this threshold are treated as milliseconds, below as
# seconds. 1e11 seconds ≈ year 5138, so any modern epoch-seconds value stays
# well below; 1e11 milliseconds ≈ year 1973, so any modern epoch-ms value
# stays well above. This gives us a clean split without a format flag.
_EPOCH_MS_THRESHOLD = 10**11


@dataclass(frozen=True)
class QuerySummary:
    """Compact structured summary of an NGSIEM query result."""

    row_count: int
    top_host: tuple[str, int] | None = None
    top_event_name: tuple[str, int] | None = None
    time_range: tuple[str, str] | None = None
    hourly_buckets: list[dict] = field(default_factory=list)


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


def summarize_events(events: list[dict]) -> QuerySummary:
    """Reduce a list of NGSIEM events to a compact summary.

    Tolerant to the messier shapes live NGSIEM returns: missing fields,
    ``None`` values, and ``@timestamp`` as epoch-millis int instead of an
    ISO string. Bad values are skipped, not raised — a populated result set
    with one garbage row should still produce a useful summary.
    """
    if not events:
        return QuerySummary(row_count=0)

    hosts: list[str] = []
    names: list[str] = []
    datetimes: list[datetime] = []
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

    datetimes.sort()
    time_range = (datetimes[0].isoformat(), datetimes[-1].isoformat()) if datetimes else None

    return QuerySummary(
        row_count=len(events),
        top_host=_top(hosts),
        top_event_name=_top(names),
        time_range=time_range,
        hourly_buckets=_hourly_buckets(datetimes),
    )
