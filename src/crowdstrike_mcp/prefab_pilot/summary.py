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
from datetime import datetime


@dataclass(frozen=True)
class QuerySummary:
    """Compact structured summary of an NGSIEM query result."""

    row_count: int
    top_host: tuple[str, int] | None = None
    top_event_name: tuple[str, int] | None = None
    time_range: tuple[str, str] | None = None
    hourly_buckets: list[dict] = field(default_factory=list)


def _top(items: list[str]) -> tuple[str, int] | None:
    if not items:
        return None
    value, count = Counter(items).most_common(1)[0]
    return (value, count)


def _hourly_buckets(timestamps: list[str]) -> list[dict]:
    if not timestamps:
        return []
    counts: Counter[str] = Counter()
    for raw in timestamps:
        dt = datetime.fromisoformat(raw).replace(minute=0, second=0, microsecond=0)
        counts[dt.isoformat()] += 1
    return [{"hour": h, "count": c} for h, c in sorted(counts.items())]


def summarize_events(events: list[dict]) -> QuerySummary:
    """Reduce a list of NGSIEM events to a compact summary."""
    if not events:
        return QuerySummary(row_count=0)

    hosts = [e["ComputerName"] for e in events if "ComputerName" in e]
    names = [e["event_simpleName"] for e in events if "event_simpleName" in e]
    timestamps = sorted(e["@timestamp"] for e in events if "@timestamp" in e)

    time_range = (timestamps[0], timestamps[-1]) if timestamps else None

    return QuerySummary(
        row_count=len(events),
        top_host=_top(hosts),
        top_event_name=_top(names),
        time_range=time_range,
        hourly_buckets=_hourly_buckets(timestamps),
    )
