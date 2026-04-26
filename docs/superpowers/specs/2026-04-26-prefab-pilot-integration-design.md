# Prefab Pilot Integration — Design Spec

**Date:** 2026-04-26
**Status:** Draft (pre-implementation)
**Branch context:** `prototype/fastmcp-prefab-pilot` (PR #19)

## Background

The Prefab pilot at `src/crowdstrike_mcp/prefab_pilot/` currently runs as a
standalone `FastMCPApp` server alongside the main `crowdstrike_mcp`
`FastMCP` server. It registers two tools (`ngsiem_query_demo` and
`ngsiem_query_drilldown`) that render NGSIEM query results as interactive
Prefab UI components in Claude Desktop.

The pilot has reached a working state for four widget types
(`Metric`, `PieChart`, `AreaChart`/`BarChart`, `ScatterChart`) and is
ready to fold into the main server so the rendering capability lives
alongside the existing read-only NGSIEM tool surface (`ngsiem_query`,
`ngsiem_list_*`, etc.).

The integration is itself a meaningful design decision because the
agent-facing tool and the user-facing UI tool serve different purposes:

- `ngsiem_query` exists to populate the agent's reasoning context with
  full event data.
- The UI tool exists to render results to the user; the agent receives
  only a brief summary plus a stored-response reference, not the full
  payload.

This spec defines how the two coexist on a single MCP server.

## Goals

- Fold the pilot's render path into the main `crowdstrike_mcp` server.
- Preserve every behavior of the existing `ngsiem_query` agent tool.
- Make the UI tool a peer of `ngsiem_query` (the model picks based on
  intent), not a flag on it.
- Share the query engine between both tools so they cannot drift.
- Have the UI tool emit a `ref_id` the agent can use with
  `get_stored_response` for follow-up reasoning over specific events.
- Retire the standalone pilot server.

## Non-goals

- Fixing the unsolved row-click bug in Claude Desktop. The drilldown
  wire format is preserved as-is; integration is separate from
  click-handler debugging.
- Routing drilldown payloads through `ResponseStore`. The clicked row
  ships inline via `$event` (current pilot behavior). A future
  `ref_id`-based drilldown is strictly additive and explicitly out of
  scope here.
- Redesigning `ResponseStore` or `format_text_response` semantics.
- Adding new widget types or layout features.

## Decisions

The brainstorming session settled six decisions, each labeled with the
option chosen.

### D1. Call site: agent-driven (option A)

The model decides whether to invoke the UI tool based on tool
descriptions. There is no user-facing slash command or explicit "render
this" hint. Tool naming and descriptions must be unambiguous enough that
the model picks correctly.

### D2. Agent payload: summary plus `ref_id` (option B)

The UI tool's text fallback gives the agent a short summary and a
stored-response reference, not the full event dump. The agent must opt
in to detail by calling `get_stored_response(ref_id=...)`.

### D3. Tool shape: separate tool, shared engine (option C)

Register a distinct `ngsiem_query_render` tool alongside the unchanged
`ngsiem_query`. Both call the same query-execution function. No flag on
the existing tool; no schema change to the agent path.

### D4. Drilldown carrier: inline row (option A)

The DataTable's `onRowClick` ships the clicked row dict inline as the
`CallTool` argument (`{"row": "{{ $event }}"}`). The drilldown tool
echoes the row back. No coupling to `ResponseStore`. (Future option C
— inline row + `ref_id` riding along — is left open as a strictly
additive change.)

### D5. Server framework: adopt `FastMCPApp` (option A)

Replace `FastMCP("crowdstrike-falcon")` with
`FastMCPApp("crowdstrike-falcon")` in `server.py`. The
`@app.ui()` decorator becomes available for this and future UI tools.
Gated on a spike (see Risks).

### D6. Module location: new sibling module (option B)

Add `NGSIEMRenderModule` as a sibling of `NGSIEMModule`. The render
module imports the query module and calls its (newly public)
`execute_query`. The `prefab_pilot/` package contents migrate into a
`modules/ngsiem_render/` package.

## Architecture

```
src/crowdstrike_mcp/
  server.py                         # FastMCP -> FastMCPApp
  modules/
    ngsiem.py                       # _execute_query -> execute_query
    ngsiem_render.py                # NEW: NGSIEMRenderModule
    ngsiem_render/                  # NEW package
      __init__.py                   # exposes RENDER_AVAILABLE flag
      summary.py                    # migrated from prefab_pilot/
      layout.py                     # migrated; _APP_NAME flips
      fallback.py                   # migrated
      mock_data.py                  # kept for offline dev/tests

# REMOVED after integration:
src/crowdstrike_mcp/prefab_pilot/   # entire package
tests/prefab_pilot/                 # tests migrate to tests/modules/ngsiem_render/
```

## Components and contracts

### `NGSIEMModule` (modified, minimal)

- `_execute_query` renamed to `execute_query`. One known caller
  (`AlertsModule`) updated to match.
- All public tools and behavior unchanged.

### `NGSIEMRenderModule` (new)

```python
class NGSIEMRenderModule(BaseModule):
    def __init__(self, client, ngsiem_module: NGSIEMModule): ...
    def register_tools(self, server: FastMCPApp) -> None:
        # Registers ngsiem_query_render via server.ui(...)
        # Registers ngsiem_query_drilldown via server.tool(...)

    async def ngsiem_query_render(
        self,
        query: str,
        start_time: str = "1d",
        max_results: int = 100,
    ) -> ToolResult: ...

    def ngsiem_query_drilldown(self, row: dict) -> ToolResult: ...
```

The render tool calls `self.ngsiem.execute_query(...)`, summarizes via
`summarize_events`, builds the layout via `build_ngsiem_query_layout`,
pushes the events into `ResponseStore` (same path `ngsiem_query` uses
through `format_text_response(structured_data=...)`), and returns a
`ToolResult` with:

- `content=[TextContent(...)]` — short summary including the `ref_id`.
- `structured_content=<PrefabApp envelope>` — produced by FastMCPApp's
  envelope wrapper when the handler returns a Prefab Component, OR
  constructed manually if we end up returning `ToolResult` directly
  (the pilot does the latter; integration preserves that to keep the
  text fallback intact).

### `server.py` (modified)

```python
self.server = FastMCPApp("crowdstrike-falcon")
# ... existing module registrations unchanged ...
try:
    from crowdstrike_mcp.modules.ngsiem_render import (
        RENDER_AVAILABLE, NGSIEMRenderModule,
    )
    if RENDER_AVAILABLE:
        modules.append(NGSIEMRenderModule(client, ngsiem_module))
except ImportError:
    pass
```

### `ngsiem_render/layout.py` (migrated, one constant change)

```python
_APP_NAME = "crowdstrike-falcon"  # was "crowdstrike-prefab-pilot"
_DRILLDOWN_BACKEND_NAME = hashed_backend_name(_APP_NAME, "ngsiem_query_drilldown")
```

The drilldown wire-format hash recomputes from the new app name.

## Data flow

### Agent path (unchanged)

```
agent calls ngsiem_query(query=...)
  -> NGSIEMModule.execute_query(...)
  -> format_text_response(..., structured_data=result)
  -> ResponseStore.put -> ref_id
  -> text dump (full events) returned to agent
```

### UI path (new)

```
model calls ngsiem_query_render(query=...)
  -> NGSIEMModule.execute_query(...)            # same engine
  -> summarize_events(events) -> QuerySummary
  -> ResponseStore.put -> ref_id                # same store as agent path
  -> build_ngsiem_query_layout(...) -> Component
  -> ToolResult(
       content=[TextContent(short summary + "ref_id=resp_NNN")],
       structured_content=<PrefabApp envelope>
     )
```

The text fallback shape:

```
Rendered NGSIEM query for the user.
Query: <query>
Time range: <start_time>
Events: <N> (top host: <host> with <count>)
To inspect specific events, call get_stored_response(ref_id="resp_NNN").
```

### Drilldown (unchanged from pilot)

```
user clicks DataTable row
  -> CallTool(<hashed_drilldown_name>, arguments={"row": "{{ $event }}"})
  -> ngsiem_query_drilldown(row)
  -> ToolResult(content=[json.dumps(row)], structured_content=row)
```

## Error handling

- Live NGSIEM failure on the render path falls back to mock data and
  surfaces the error in the text content (existing pilot behavior;
  preserved).
- `prefab_ui` import failure: render module never registers; agent
  tools and the rest of the server function normally.
- `ResponseStore` eviction: the agent's later
  `get_stored_response(ref_id=...)` call returns the standard
  not-found message with the list of available refs. No new failure
  mode introduced.
- Drilldown row not a dict: existing pilot behavior preserved
  (returns a typed error in the text content).

## Testing

- All `tests/prefab_pilot/test_summary.py` and `test_layout.py` tests
  migrate unchanged (modulo the import path) to
  `tests/modules/ngsiem_render/`.
- `tests/prefab_pilot/test_server.py` rewrites: ~5 tests need to
  instantiate `NGSIEMRenderModule` against a test `FastMCPApp`
  rather than importing the pilot's module-level `app`. Test intents
  preserved.
- New test: `ngsiem_query_render` text fallback contains a `ref_id`
  matching `resp_\d+`, and the same id resolves through
  `ResponseStore.get`.
- New test: `NGSIEMRenderModule` with `RENDER_AVAILABLE=False`
  registers nothing (simulated by monkeypatching the
  `prefab_ui` import).
- New test: `_APP_NAME` constant cross-check against the registered
  drilldown's wire hash (port the pilot's existing
  `test_drilldown_backend_name_matches_layout_constant`).
- Existing main-server smoke tests
  (`tests/test_smoke_tools_list.py`, etc.) must still pass after the
  `FastMCP` -> `FastMCPApp` swap.

## Risks and mitigations

### R1. `FastMCPApp` is not a drop-in for `FastMCP`

**Risk:** `FastMCPApp` is not a subclass of `FastMCP`. We have not
verified that it supports `server.resource(...)` registration, the
prompt registration the existing modules use, lifespan hooks, or any
other surface the existing 12-module server depends on.

**Mitigation:** Run a spike before any other implementation work:

1. Construct `FastMCPApp("crowdstrike-falcon")` in isolation.
2. Register one resource (`falcon://cql/syntax`).
3. Register one existing module's tools.
4. Run `tests/test_smoke_tools_list.py`.

Outcomes:

- Spike passes -> implement as designed.
- Spike fails on resources only -> patch the registration call, document
  the diff, implement as designed.
- Spike fails on a deep surface (lifespan, tool semantics) -> fall back
  to keeping `FastMCP`, register render tools as plain `@app.tool` and
  manually construct the `PrefabApp` envelope. This adds ~30 lines of
  envelope-wrapping code we maintain ourselves. Update this spec and
  re-review before implementing.

### R2. Lost standalone pilot harness

**Risk:** The pilot ran via `python -m crowdstrike_mcp.prefab_pilot.server`
for fast iteration without spinning up the full server. Integration
removes this path.

**Mitigation:** Preserve `mock_data.py` and add a
`CROWDSTRIKE_RENDER_MOCK=1` env flag the render tool honors (returns
mock events without calling `execute_query`). Dev iteration without
FalconPy creds remains possible against the integrated server.

### R3. Drilldown wire-format hash changes

**Risk:** The hash is a function of `(app_name, tool_name)`. Changing
the app name from `"crowdstrike-prefab-pilot"` to `"crowdstrike-falcon"`
invalidates the pilot's hardcoded hash and any cached client state.

**Mitigation:** The existing test
`test_drilldown_backend_name_matches_layout_constant` catches drift.
Update the constant in `layout.py` and the test fixture in the same
commit. No client-side state is cached across server restarts, so
Claude Desktop will pick up the new hash on next reconnect.

### R4. The unsolved row-click bug

**Risk:** Row clicks in Claude Desktop do not currently fire the
drilldown despite verified-correct wire format. This bug travels
unchanged to the integrated tool.

**Mitigation:** Out of scope for this integration. Documented here so
post-integration testing does not falsely attribute the symptom to the
integration work.

### R5. `ResponseStore` ref_id capture

**Risk:** `format_text_response(..., structured_data=...)` is the
mechanism that pushes results into `ResponseStore`. We need to confirm
that the call returns or otherwise exposes the assigned `ref_id` so we
can include it in the render tool's text fallback.

**Mitigation:** Read `format_text_response` and `ResponseStore.put`
implementations during the spike; if `ref_id` is not currently
returned, the smallest possible change is to expose it (return value
or out-parameter). This is a one-line API surface change to a function
already designed for ref-id semantics.

## Open questions

None at design time. Implementation will surface details (exact
`format_text_response` signature change, exact `FastMCPApp.resource`
shape) that the plan should call out as discovery items.

## Out of scope (future work)

- Drilldown via `ref_id + record_index` instead of inline row (D4
  option C). Strictly additive when wanted.
- Promoting `execute_query` into a shared `crowdstrike_mcp/queries/`
  module and breaking both `NGSIEMModule` and `NGSIEMRenderModule`'s
  dependency on each other. Worth doing when a third consumer appears.
- Render tools for alerts, IOCs, RTR sessions, etc. Each is its own
  spec; this one establishes the pattern.
- Fixing the row-click bug.
