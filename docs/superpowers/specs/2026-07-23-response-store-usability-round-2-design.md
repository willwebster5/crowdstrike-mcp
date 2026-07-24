# Response Store Usability Round 2: Paging, Discoverability, Tombstones

**Date**: 2026-07-23
**Status**: Approved
**Author**: Claude + Will Webster

---

## Problem

Telemetry from Darlah's runtime sessions (159MB of transcripts) and the MintMCP
gateway logs in NGSIEM (`#type=mintmcp`, 7 days) shows the response store is
load-bearing — 918 `get_stored_response` calls (31% of all CrowdStrike MCP
traffic), 91% of truncation notices followed correctly, 27.3M chars of would-be
output reduced to 0.9M in context — but exposes four measured friction points:

1. **Index-walking**: 56% of `get_stored_response` calls fetch a single record
   by `record_index`; 122 sequential walk runs (98 spanning ≥3 consecutive
   records, some 8–10 long). There is no way to fetch a *page of complete
   records* — `offset`/`max_results` paging (PR #48) applies only to `fields`
   and `search` modes. Each walk step costs a tool round-trip plus a model turn.
2. **Blind field guessing**: 16 all-null projection warnings, every one caused
   by the agent inventing plausible field names (`Ngsiem.event.usernames`, …)
   instead of discovering the schema. Only 5% of calls are the bare metadata
   overview. The schema hint exists — but not in the truncation notice, which
   is where 91% of follow-up calls originate.
3. **Dead-end ref errors**: 7 "reference not found" failures (TTL expiry,
   restarts, hallucinated refs). Eviction discards metadata along with data, so
   the error cannot tell the agent how to regenerate the result.
4. **Silent search misses**: 31 "no records matching" results with no feedback
   about what was scanned or which fields exist.

## Design

### A. Full-record paging via `fields="*"`

`fields="*"` becomes an identity projection: the record passes through
unchanged, flowing down the existing `fields` path — size-aware `_emit_page`,
`offset`, `max_results`, and page notices all work as they do today.

- No tool-schema change (MintMCP and clients see the same signature).
- `"*"` mixed with other field names (e.g. `fields="*,source.ip"`) is treated
  as just `"*"` — the wildcard subsumes any explicit field.
- The all-null warning check is skipped for wildcard projections (an identity
  projection of a non-empty record is never all-null; empty-dict records are
  returned as-is, not warned about).
- Advertised where the agent looks: a wildcard example line is added to the
  truncation notice and to the `get_stored_response` tool description
  (`fields="*"` → full records, paged).

Alternatives considered: a new `records: bool` parameter (most explicit, but
widens the schema and adds a fourth retrieval mode); a `limit` parameter on
`record_index` (matches the observed walking habit, but creates two competing
paging vocabularies). The wildcard reuses everything that already exists.

### B. Schema hint in the truncation notice

`build_truncation_notice()` gains a `Fields:` line listing available field
paths, derived from the same schema-hint logic the metadata overview uses.

- The shared helpers (`_top_level_keys`, `_schema_hint`) move from
  `modules/response_store.py` to root-level `response_store.py`, preserving the
  dependency direction (utils → response_store; modules → utils). The module
  imports them from there.
- The line is capped at 40 entries and ~600 chars, whichever is hit first, with
  a `(+N more)` suffix. The notice stays a notice.
- The inline `[Structured data available: resp_NNN]` footer is unchanged —
  bloating every small response to fix a truncation-path problem is backwards.

### C. Eviction tombstones

When an entry is evicted by LRU displacement or TTL expiry, the store retains a
tombstone: `{tool_name, metadata, evicted_at, reason}` (`reason` ∈
`"lru" | "ttl"`).

- Tombstones live in a per-session `OrderedDict` capped at 50 (oldest dropped),
  inside the session partition.
- **Security boundary preserved**: `clear_session` and
  `clear_credential_sessions` wipe tombstones with the partition — metadata
  (which can embed query strings/indicators) never outlives its credential.
- `get_stored_response` on a missing ref consults the tombstone and returns an
  actionable error, e.g.:
  `resp_003 expired (25-min TTL). It was ngsiem_query (query: <original query>)
  — re-run that tool to regenerate the data.`
  LRU-evicted refs say "was evicted to make room" instead of "expired".
- Refs with no tombstone (never existed / hallucinated) keep the current error
  listing available refs.

### D. Search-miss feedback

The no-match search response becomes actionable:

```
No records matching 'jetbrain' in resp_001 (searched 200 records).
Search is a case-insensitive substring match over all record values.
Available fields: <schema hint, same cap as B>
Tip: try a shorter substring, or extract candidate fields with fields=...
```

### Not changing

- `record_key` stays despite zero observed usage (feature removal deferred —
  separate decision).
- The inline footer format.
- Store limits (`_max_entries`, `_max_sessions`, TTL) and partitioning.

## Testing (TDD)

| Area | Tests |
|------|-------|
| A | `fields="*"` returns full records; respects `_PAGE_BYTE_BUDGET` and emits page notices; `offset` continues from a page notice; `"*,x"` treated as `"*"`; no all-null warning on wildcard; works combined with `search` and with `record_index` (verbatim single record, unchanged) |
| B | Truncation notice contains `Fields:` line; capped at 40 entries/~600 chars with `+N more`; absent when no records; metadata overview output unchanged |
| C | TTL expiry leaves tombstone; LRU eviction leaves tombstone with `lru` reason; miss error includes tool name + metadata context; hallucinated ref (no tombstone) keeps existing error; `clear_session`/`clear_credential_sessions` wipe tombstones; tombstone cap enforced |
| D | No-match message includes scanned count, substring note, schema hint; match path unchanged |

## Out of Scope

- Removing `record_key`
- Persisting the store or tombstones to disk
- Server-side aggregation (`group by` style) over stored records
- Changing falcon-mcp comparison posture / upstreaming
