"""
ResponseStore — in-memory structured data store for large MCP tool responses.

Stores raw Python dicts from tool output (before text formatting) so the
get_stored_response MCP tool can do field-level extraction without Bash/grep.

This file lives at the root level (peer to utils.py) to keep the dependency
direction clean: utils.py imports from here, modules import from utils.py.

Isolation: the store is partitioned per session. In HTTP transports a single
process serves many authenticated tenants, so a process-global store would let
one tenant read another's stored Falcon data via predictable ref_ids. The
session key is set per request by session_auth_middleware and combines the
credential (cross-tenant isolation) with the MCP connection id when present
(so one user's concurrent connections — e.g. several projects sharing a Falcon
credential — don't share a ref namespace or LRU budget). stdio (single client)
uses the default session. All access is guarded by a lock since FastMCP runs
sync tool bodies in a worker threadpool.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from contextvars import ContextVar, Token
from dataclasses import dataclass
from datetime import datetime, timezone

# Per-session partition key. Set by session_auth_middleware for HTTP transports;
# stdio and tests use the default single-session value.
_DEFAULT_SESSION = "local"
_session_id: ContextVar[str] = ContextVar("response_store_session", default=_DEFAULT_SESSION)

# Separator joining a credential key to an MCP connection id in a partition key.
# The credential key is a fixed-length sha256 hex digest, so this separator is
# always unambiguous for the prefix scan in clear_credential_sessions.
_CONNECTION_SEP = "|"


def make_session_key(cred_key: str, connection_id: str | None) -> str:
    """Build a response-store partition key.

    Per-connection when a stable connection id is available (so a single user's
    concurrent projects don't share one ref namespace / LRU budget), else the
    bare credential key — the backward-compatible partition for stdio, SSE, and
    stateless HTTP, which have no ``mcp-session-id``.
    """
    if connection_id:
        return f"{cred_key}{_CONNECTION_SEP}{connection_id}"
    return cred_key


def set_response_session(session_id: str) -> Token:
    """Bind the response-store session for the current context. Returns a reset token."""
    return _session_id.set(session_id)


def reset_response_session(token: Token) -> None:
    """Restore the previous response-store session using a token from set_response_session."""
    _session_id.reset(token)


# Top-level keys that denote the primary record collection in stored payloads,
# in preference order. Avoids conflating heterogeneous lists (e.g. ngsiem_query's
# `events` records vs its `field_projection` list of field names).
_PRIMARY_RECORD_KEYS = (
    "records",
    "events",
    "behaviors",
    "investigations",
    "vulns",
    "vulnerabilities",
    "risks",
    "resources",
    "vertices",
    "edges",
    "hosts",
    "login_history",
    "network_history",
    "entity_ids",
    "data",
    "results",
)


def select_records(data: dict) -> list:
    """Return the primary record list from a stored payload.

    Resolution order: a known primary key holding a list, else the longest
    top-level list, else top-level dict values treated as single records
    (e.g. ``{"record": {...}}``), else empty.
    """
    if not isinstance(data, dict):
        return []
    for key in _PRIMARY_RECORD_KEYS:
        value = data.get(key)
        if isinstance(value, list):
            return value
    lists = [v for v in data.values() if isinstance(v, list)]
    if lists:
        return max(lists, key=len)
    dicts = [v for v in data.values() if isinstance(v, dict)]
    if dicts:
        return dicts
    return []


@dataclass
class StoredResponse:
    """A stored structured response from an MCP tool."""

    ref_id: str
    tool_name: str
    timestamp: datetime
    data: dict
    metadata: dict
    record_count: int


class ResponseStore:
    """Session-partitioned in-memory store for structured MCP tool responses.

    All methods are classmethods — no instantiation needed. Each session gets an
    LRU buffer capped at ``_max_entries``; the number of retained sessions is
    capped at ``_max_sessions`` (oldest session evicted whole). Thread-safe.
    """

    _lock: threading.RLock = threading.RLock()
    # session_id -> (ref_id -> StoredResponse), ordered by recency (LRU).
    _sessions: "OrderedDict[str, OrderedDict[str, StoredResponse]]" = OrderedDict()
    # session_id -> monotonic ref counter (never reused, so ref_ids stay unique).
    _counters: dict[str, int] = {}
    _max_entries: int = 50
    _max_sessions: int = 100
    # Entries older than this are treated as absent (bounds how long sensitive
    # Falcon data stays resident). Mirrors the 25-min auth-session window.
    _ttl_seconds: int = 25 * 60

    @classmethod
    def store(
        cls,
        data: dict,
        tool_name: str = "",
        metadata: dict | None = None,
    ) -> str:
        """Store structured data for the current session and return a ref_id."""
        with cls._lock:
            sk = _session_id.get()
            entries = cls._sessions.get(sk)
            if entries is None:
                # New session — bound total sessions before adding.
                while len(cls._sessions) >= cls._max_sessions:
                    old_sk, _ = cls._sessions.popitem(last=False)
                    cls._counters.pop(old_sk, None)
                entries = OrderedDict()
                cls._sessions[sk] = entries
                cls._counters[sk] = 0
            cls._sessions.move_to_end(sk)  # session recency

            cls._counters[sk] += 1
            ref_id = f"resp_{cls._counters[sk]:03d}"

            if len(entries) >= cls._max_entries:
                entries.popitem(last=False)  # evict least-recently-used in this session

            entries[ref_id] = StoredResponse(
                ref_id=ref_id,
                tool_name=tool_name,
                timestamp=datetime.now(timezone.utc),
                data=data,
                metadata=metadata or {},
                record_count=cls._count_records(data),
            )
            return ref_id

    @classmethod
    def get(cls, ref_id: str) -> StoredResponse | None:
        """Retrieve a stored response by ref_id within the current session."""
        with cls._lock:
            entries = cls._sessions.get(_session_id.get())
            if not entries:
                return None
            sr = entries.get(ref_id)
            if sr is None:
                return None
            if cls._is_expired(sr):
                del entries[ref_id]
                return None
            entries.move_to_end(ref_id)  # reading refreshes LRU recency
            return sr

    @classmethod
    def list_refs(cls) -> list[dict]:
        """Return summary of all non-expired stored responses for the current session."""
        with cls._lock:
            entries = cls._sessions.get(_session_id.get())
            if not entries:
                return []
            live = [sr for sr in entries.values() if not cls._is_expired(sr)]
            return [
                {
                    "ref_id": sr.ref_id,
                    "tool_name": sr.tool_name,
                    "timestamp": sr.timestamp.isoformat(),
                    "record_count": sr.record_count,
                    "metadata": sr.metadata,
                }
                for sr in live
            ]

    @classmethod
    def clear_session(cls, session_id: str) -> None:
        """Drop a session's entire partition (e.g. when its auth session is evicted)."""
        with cls._lock:
            cls._sessions.pop(session_id, None)
            cls._counters.pop(session_id, None)

    @classmethod
    def clear_credential_sessions(cls, cred_key: str) -> None:
        """Drop every partition owned by a credential.

        Clears the bare credential partition and all per-connection
        sub-partitions (``cred_key|<connection id>``). Called when a credential's
        auth session is evicted so its stored Falcon data doesn't outlive it,
        regardless of how many connections were open under it.
        """
        with cls._lock:
            prefix = f"{cred_key}{_CONNECTION_SEP}"
            owned = [sk for sk in cls._sessions if sk == cred_key or sk.startswith(prefix)]
            for sk in owned:
                cls._sessions.pop(sk, None)
                cls._counters.pop(sk, None)

    @classmethod
    def _is_expired(cls, sr: StoredResponse) -> bool:
        """True if the entry is older than the TTL."""
        age = (datetime.now(timezone.utc) - sr.timestamp).total_seconds()
        return age > cls._ttl_seconds

    @classmethod
    def _count_records(cls, data: dict) -> int:
        """Count records using the primary record list (see select_records)."""
        return len(select_records(data))

    @classmethod
    def _reset(cls) -> None:
        """Clear all stored responses and counters. For testing only."""
        with cls._lock:
            cls._sessions.clear()
            cls._counters.clear()


# Metadata keys used (in order) to build the truncation-notice context line.
_CONTEXT_KEYS = ("detection_id", "query", "filter")


def build_truncation_notice(
    *,
    summary: str,
    text_len: int,
    ref_id: str,
    record_count: int,
    tool_name: str,
    metadata: dict | None,
) -> str:
    """Build the truncation notice for a large, stored response.

    Authoring the get_stored_response usage hints is store-domain knowledge, so
    it lives here rather than in the generic text formatter. The record-key hint
    is driven by a generic ``record_key`` metadata field (``triggering_pid`` is
    accepted as a back-compat alias) — the formatter need not know either name.
    """
    metadata = metadata or {}

    context_line = ""
    for key in _CONTEXT_KEYS:
        val = metadata.get(key)
        if val:
            context_line = f"\nTool: {tool_name} | {key}: {val}"
            break

    record_key = metadata.get("record_key") or metadata.get("triggering_pid")
    if record_key:
        last_lines = [
            f'  get_stored_response(ref_id="{ref_id}", record_key="{record_key}")  → keyed record',
            f'  get_stored_response(ref_id="{ref_id}", record_index=0)                 → first record (chronological)',
        ]
    else:
        last_lines = [
            f'  get_stored_response(ref_id="{ref_id}", record_index=0)                → full first record',
        ]

    parts = [
        summary,
        "",
        f"--- RESPONSE TRUNCATED ({text_len:,} chars) ---",
        f"Structured data stored as: {ref_id} ({record_count} records){context_line}",
        "",
        "To query this data use the get_stored_response tool:",
        f'  get_stored_response(ref_id="{ref_id}")                                → metadata overview',
        f'  get_stored_response(ref_id="{ref_id}", fields="source.ip,user.name")  → extract fields',
        f'  get_stored_response(ref_id="{ref_id}", search="keyword")              → search records',
        *last_lines,
    ]
    return "\n".join(parts)
