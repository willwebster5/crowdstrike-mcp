# Prefab pilot — handoff notes

This is an experimental FastMCPApp surface built to validate the feasibility
study in
[`docs/superpowers/specs/2026-04-21-fastmcp-prefab-migration-feasibility.md`](../../../docs/superpowers/specs/2026-04-21-fastmcp-prefab-migration-feasibility.md).

It is **additive**. It does not touch the main `server.py` or any existing
module. Deleting this directory would leave production unchanged.

---

## What it is

A standalone stdio MCP server that exposes two tools:

- `ngsiem_query_demo` — an `@app.ui()` entry point. Returns a Prefab
  `Column` layout with a heading, summary card, `BarChart` of hourly event
  counts, and a searchable/paginated `DataTable` of events. Wrapped in a
  `ToolResult` so non-rendering hosts (Claude Code) get a self-contained
  text summary instead of the UI.
- `ngsiem_query_drilldown` — an `@app.tool()` the UI calls when a row is
  clicked. Returns the full JSON for a single event.

The pilot uses **synthetic data** from `mock_data.generate_process_events`.
No Falcon credentials are required to run it.

---

## Install and run

```bash
# from repo root, with any recent Python 3.11+
python3 -m venv .venv-prefab
source .venv-prefab/bin/activate
pip install -e '.[prefab-pilot]'

# start the pilot server (stdio)
crowdstrike-prefab-pilot
# or equivalently:
python -m crowdstrike_mcp.prefab_pilot.server
```

This installs the PrefectHQ `fastmcp[apps]` extra, which pulls in
`prefab-ui`. Neither is a dependency of the main `crowdstrike-mcp`
package — they are isolated to the `[prefab-pilot]` extra.

---

## Point Claude Desktop at it

Add this entry to the Claude Desktop config
(`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS,
`%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "crowdstrike-prefab-pilot": {
      "command": "/absolute/path/to/.venv-prefab/bin/crowdstrike-prefab-pilot"
    }
  }
}
```

Restart Claude Desktop. Ask: *"Run the ngsiem_query_demo tool."* The
interactive layout should render inline in the chat.

---

## Manual verification checklist (for the follow-up agent)

Tests in `tests/prefab_pilot/` cover the Python logic, but they cannot
verify host-side rendering. **The following must be done manually by an
agent or human with the right environment.**

- [ ] Pilot server starts without errors under `crowdstrike-prefab-pilot`.
- [ ] Claude Desktop successfully discovers both tools after config reload.
- [ ] Calling `ngsiem_query_demo` in Claude Desktop renders a visible
      `Column` layout containing: heading, summary card with badges,
      `BarChart`, and a `DataTable`.
- [ ] The `DataTable` is sortable (click a column header) and searchable.
- [ ] Pagination works — change `count` to 100 and confirm multiple pages.
- [ ] Calling `ngsiem_query_demo` in Claude Code produces a legible text
      summary (the `ToolResult.content` fallback) — row count, top host,
      top event name, time range. **No `[Rendered Prefab UI]` placeholder
      should reach the user.**
- [ ] Calling `ngsiem_query_drilldown` with `row_index=0` returns the JSON
      for a single event, both as text content and structured content.
- [ ] Invalid `row_index` (e.g. -1 or 1_000_000) returns a clean error
      message, not a traceback.

If any of these fail, update the feasibility doc's open questions and the
§10 decision framework accordingly.

---

## What to swap for real Falcon credentials

The mock generator is a single replaceable seam. To wire up live NGSIEM:

1. In `server.py`, replace the `events = generate_process_events(...)` line
   inside `ngsiem_query_demo`:

   ```python
   # Before (mock):
   events = generate_process_events(count=count, seed=seed)

   # After (live):
   from crowdstrike_mcp.client import FalconClient
   from crowdstrike_mcp.modules.ngsiem import NGSIEMModule

   client = FalconClient()
   client.authenticate()
   module = NGSIEMModule(client)
   events = module._execute_cql(query, limit=count)  # or the real public entry
   ```

   Check `src/crowdstrike_mcp/modules/ngsiem.py` for the exact query
   execution entry point — the mock's dict shape intentionally matches the
   fields `summary.summarize_events` expects
   (`ComputerName`, `event_simpleName`, `@timestamp`, `UserName`,
   `ImageFileName`), so no downstream changes should be needed.

2. Do the same substitution in `ngsiem_query_drilldown` if you want the
   drilldown to fetch a live event by `@id` instead of replaying the
   seeded mock.

3. Keep `generate_process_events` in place. It's useful for tests and for
   offline development, and removing it would break the existing unit
   tests in `tests/prefab_pilot/test_mock_data.py`.

4. Consider an `if FALCON_CLIENT_ID:` gate so the pilot falls back to mock
   data when no creds are configured — preserves the "runs out of the
   box" property for demos.

---

## Known limitations

- **No auth middleware.** The main server has session-scoped FalconClient
  injection via `common/session_auth.py`. The pilot doesn't — it's stdio
  only, single-user. If you want to run this under SSE / streamable-HTTP,
  that middleware stack needs porting to PrefectHQ `fastmcp`'s ASGI app.
  See feasibility doc §5.6 for the open question.
- **Claude Code renders text only.** The fallback is deliberate and tested
  (`test_fallback.py`). Don't try to "fix" this by pointing Code at the
  same server expecting UI.
- **`DataTable` column config is static.** The five columns are hardcoded
  in `layout._TABLE_COLUMNS`. A real migration would make these adapt to
  the query's projected fields.
- **No `onRowClick` wired to the drilldown yet.** The backend tool exists
  (`@app.tool("ngsiem_query_drilldown")`), but the `DataTable` component
  in `layout.py` doesn't have its `onRowClick` action pointing at it. See
  `prefab_ui.actions` — likely a one-liner once you've seen how Prefab
  action callbacks resolve to tool hashes.
- **Dependency weight.** `fastmcp[apps]` pulls in `prefab-ui`, which is
  ~10 MB with all its CSS and renderer assets. Acceptable for an opt-in
  extra; would be worth measuring as a concern if we migrate the main
  server.

---

## Files in this package

| File | Purpose | Tests |
|---|---|---|
| `__init__.py` | Package marker | — |
| `mock_data.py` | Synthetic NGSIEM event generator (seeded, deterministic) | `test_mock_data.py` |
| `summary.py` | `QuerySummary` dataclass + reducer — the compact model-facing payload | `test_summary.py` |
| `fallback.py` | Summary → plain text for Claude Code / non-rendering hosts | `test_fallback.py` |
| `layout.py` | Prefab component assembly — `build_ngsiem_query_layout` | `test_layout.py` |
| `server.py` | `FastMCPApp` instance with `@app.ui()` and `@app.tool()` handlers, `main()` entry point | `test_server.py` |

Run the tests with:

```bash
.venv-prefab/bin/pytest tests/prefab_pilot/ -v
```

All six test modules should report green. If any fail after a dependency
refresh, pin `fastmcp` to the version this was built against (3.2.4) and
file an open question against the feasibility doc.
