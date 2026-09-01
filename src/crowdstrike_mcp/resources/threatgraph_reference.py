"""
Threat Graph edge-type reference — lazily populated from the live API.

Unlike the static FQL guides in fql_guides.py, the Threat Graph edge-type
catalog evolves with CrowdStrike releases. We fetch it on first resource
read, cache in process memory, and let callers invalidate via the
threatgraph_get_edge_types tool.
"""

from __future__ import annotations

import threading
from typing import Callable

FETCH_FAILURE_BODY = (
    "# Threat Graph — Edge Types\n\n"
    "Failed to fetch the live edge-type list. Call `threatgraph_get_edge_types` "
    "directly or retry this resource read.\n\n"
    "API error: {detail}\n"
)


class ThreatGraphEdgeTypeCache:
    """Lazy, process-lifetime cache for Threat Graph edge types, scoped per tenant."""

    def __init__(self, fetcher: Callable[[], dict]):
        """
        Args:
            fetcher: zero-arg callable returning the falconpy response dict
                     from get_edge_types() (keys: status_code, body).
        """
        self._fetcher = fetcher
        # Keyed by client_id, not a single scalar: ThreatGraphModule is
        # instantiated once at server startup and shared across every session
        # in HTTP mode. Without this, the first tenant to read the edge-type
        # resource permanently seeds the cache for every subsequent tenant —
        # e.g. a tenant with a different edge-type entitlement would silently
        # receive another tenant's cached list. Guarded by a lock since
        # concurrent tool calls now genuinely run in parallel (see
        # modules/base.py::_offloaded).
        self._cached: dict[str | None, str] = {}
        self._lock = threading.Lock()

    def read(self, client_id: str | None = None) -> str:
        """Return the formatted edge-type reference, fetching if needed."""
        with self._lock:
            cached = self._cached.get(client_id)
        if cached is not None:
            return cached
        response = self._fetcher()
        status = response.get("status_code")
        if status != 200:
            errors = (response.get("body") or {}).get("errors") or []
            detail = errors[0].get("message") if errors else f"HTTP {status}"
            return FETCH_FAILURE_BODY.format(detail=detail)
        resources = (response.get("body") or {}).get("resources") or []
        formatted = self._format(resources)
        with self._lock:
            self._cached[client_id] = formatted
        return formatted

    def invalidate(self, client_id: str | None = None) -> None:
        """Drop the cached response for one tenant so its next read re-fetches."""
        with self._lock:
            self._cached.pop(client_id, None)

    @staticmethod
    def _format(resources: list) -> str:
        # Resources may be a list of strings (edge names) or a list of dicts
        # with a "name" key. Support both; fall back to repr.
        lines = ["# Threat Graph — Edge Types", ""]
        lines.append(f"{len(resources)} edge types available.")
        lines.append("")
        for item in resources:
            if isinstance(item, str):
                lines.append(f"- `{item}`")
            elif isinstance(item, dict):
                name = item.get("name") or item.get("type") or repr(item)
                lines.append(f"- `{name}`")
            else:
                lines.append(f"- `{item!r}`")
        lines.append("")
        lines.append("Pass any of these as the `edge_type` argument to `threatgraph_get_edges`.")
        return "\n".join(lines)
