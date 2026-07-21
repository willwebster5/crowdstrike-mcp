# host_lookup user enrichment (#44)

## Problem

`host_lookup` returns device posture (containment, policy, OS, agent version, IPs)
but no user. To answer "who was on this host?" — the common next question during
alert triage — an analyst must run a *second* tool (login history) or an NGSIEM
correlation query, both keyed off the same hostname. Issue #44 asks `host_lookup`
to "at least return the logged-in user."

## Goal

Fold recent-user information into `host_lookup` so a single call answers both
"what is this host?" and "who has been on it?".

## Non-goals

- No NGSIEM correlation (login history is the native, cheaper source).
- No new tool parameters (always-on enrichment).
- No change to `host_login_history` / `host_network_history`.

## Design

### Source

Reuse the existing `_get_login_history(device_id)` wrapper around
`query_device_login_history` (`QueryDeviceLoginHistory`). One extra API call per
resolved device.

### Normalizer: `_extract_recent_users(login_resources) -> list[dict]`

The API response shape is `resources: [{device_id, recent_logins: [{user_name,
login_time}, ...]}]`, most-recent-first. To avoid depending on one exact wrapper,
the normalizer accepts either shape:

- a resource carrying `recent_logins` (list) → use those entries; or
- a resource that is itself a login record (`user_name` present) → use directly.

It then:

- collects `{user_name, login_time}` entries preserving input order
  (most-recent-first),
- dedupes by `user_name` **case-insensitively**, keeping the first (most-recent)
  occurrence — so repeated system accounts (e.g. `NT AUTHORITY\SYSTEM`) collapse
  to one and real users still fill the list,
- returns the deduped, ordered list.

### host_lookup output

For each device, after the existing fields, add:

```
- Most Recent User: DOMAIN\alice (2026-07-20T14:03:00Z)
- Recent Users: DOMAIN\alice, DOMAIN\bob, NT AUTHORITY\SYSTEM
```

- "Most Recent User" = first deduped entry (with its `login_time` when present).
- "Recent Users" = up to 3 deduped user names.
- The enriched `device` dict gains `most_recent_user` (dict or None) and
  `recent_users` (list, ≤3).

### Graceful degradation

Enrichment must never fail the core lookup. If `_get_login_history` returns an
error or no logins, `host_lookup` still succeeds and renders
`- Recent Users: (none available)`.

### Retrievability

`host_lookup` currently passes no `structured_data`. Add the enriched device list
(including user fields) as `structured_data` with `metadata` (hostname/device_id/
count), matching `host_login_history` / `host_network_history`, so results are
queryable via `get_stored_response`.

## Testing

- `_extract_recent_users`: wrapped `recent_logins` shape; flat login-record shape;
  case-insensitive dedup collapses repeated system accounts; empty/None input →
  `[]`; ordering preserved (most-recent-first); caps at 3 uniques.
- `host_lookup`: renders Most Recent User + Recent Users when history present;
  renders `(none available)` and still succeeds when history errors/empty;
  multiple resolved devices each enriched independently;
  large result routed through ResponseStore (structured_data present).

## Files

- `src/crowdstrike_mcp/modules/hosts.py` — normalizer + `host_lookup` enrichment.
- `tests/test_host_lookup_user_enrichment.py` — new.
