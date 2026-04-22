# Design: FastMCP + Prefab / MCP Apps Migration — Feasibility Study

**Date:** 2026-04-21
**Status:** Research / feasibility — no code changes proposed
**Scope:** Evaluate migrating `crowdstrike-mcp` from the official `mcp` Python SDK's built-in `FastMCP` helper to the PrefectHQ `fastmcp` package (v3.2+), with a view to adopting Prefab / MCP Apps for interactive UI rendering in supported hosts.

---

## 1. Summary & recommendation

**Recommendation: proceed with a staged migration.** The migration is technically tractable and the strategic payoff is real — chiefly in contending with NGSIEM's context-window problem. The primary host-support concern has resolved: per the [MCP Apps launch post](https://blog.modelcontextprotocol.io/posts/2026-01-26-mcp-apps/), *"Claude — available today both on web and desktop experiences"*, meaning Claude Desktop renders MCP Apps content out of the box (since 2026-01-26). Two gating conditions remain before committing:

1. Confirm PrefectHQ `fastmcp` has **transport parity** with what we use today: stdio, SSE, streamable-HTTP, plus the per-request auth middleware stack in `src/crowdstrike_mcp/common/session_auth.py` and `auth_middleware.py`. Plumbing-level verification, not a conceptual risk.
2. Let Prefab cycle once more. It moved from 3.1 (March 2026) to 3.2 (April 2026) in a few weeks; waiting one more release cuts the risk of a breaking API change landing mid-migration.

The sequencing should be: **migrate the framework first** (pure port, no Prefab), stabilize on v4.4, **then layer `FastMCPApp` onto NGSIEM** as the pilot in v4.5. Doing both in one branch is unnecessarily risky.

Claude Code remains the one host where we expect no UI render, since rendering HTML iframes in a terminal is structurally impractical. The context-window arbitrage benefit (§7) still applies regardless of renderer, so Claude Code users still benefit from the model/UI data split even without seeing a visual table.

The rest of this document supports that recommendation.

---

## 2. Background: the two FastMCPs

The name "FastMCP" refers to **two different Python packages** that export a class called `FastMCP`. This project's history has conflated them.

| | Official MCP SDK (what we use today) | PrefectHQ FastMCP (what Prefab requires) |
|---|---|---|
| PyPI name | `mcp` (>=1.12.1 in `pyproject.toml`) | `fastmcp` (v3.2 as of 2026-04) |
| Import | `from mcp.server.fastmcp import FastMCP` | `from fastmcp import FastMCP` |
| Origin | [modelcontextprotocol/python-sdk](https://github.com/modelcontextprotocol/python-sdk) | [PrefectHQ/fastmcp](https://github.com/PrefectHQ/fastmcp) (originally `jlowin/fastmcp`) |
| Relationship | Reference implementation of the MCP protocol, with a convenience helper named `FastMCP` | Independent superset; early versions donated code to the official SDK, has since diverged |
| MCP Apps / Prefab | Not supported | Supported via `FastMCPApp` + `prefab_ui` components |

Our `src/crowdstrike_mcp/server.py:36` imports from `mcp.server.fastmcp`, confirming we are on the official SDK. Every module in `src/crowdstrike_mcp/modules/` uses the same import guarded under `TYPE_CHECKING`.

The two APIs are similar but not identical. The migration surface is described in §5.

---

## 3. What MCP Apps / Prefab is

### 3.1 MCP Apps (the protocol-level capability)

**MCP Apps** is an [official MCP extension](https://blog.modelcontextprotocol.io/posts/2026-01-26-mcp-apps/) announced in January 2026. Tools can return interactive UI content — layouts, tables, forms, charts — instead of plain text or structured JSON. The host renders the UI inline in the conversation; the model receives a summary payload separately. Implementation references live at [`@modelcontextprotocol/ext-apps`](https://apps.extensions.modelcontextprotocol.io/api/).

### 3.2 Prefab (FastMCP's Python bindings)

Prefab is PrefectHQ's Python component library for authoring MCP Apps UIs. You describe layouts, data display, charts, and forms in Python; Prefab compiles them into the MCP Apps payload the host renders. Components observed in the docs:

- **Layout:** `Column`, `Row`, `Grid`, `Card`, `CardContent`
- **Display:** `Text`, `Heading`, `Muted`, `Badge` (with `success`/`destructive`/`warning` variants), `Separator`, `Alert`
- **Tables:** `Table` (documented but details sparse in public docs as of writing)
- **Charts:** `BarChart`, `LineChart` (other types referenced generically)
- **Forms:** `Input`, `Select`/`SelectOption`, `Slider`, `Switch`
- **Control flow:** `If`/`Elif`/`Else`, `ForEach`
- **State:** client-side key-value store; components with `name` auto-bind; `Rx("key")` creates reactive references

### 3.3 FastMCPApp (the runtime split)

`FastMCPApp` ([docs](https://gofastmcp.com/apps/interactive-apps)) introduces two decorators that split what the model sees from what the UI uses:

- `@app.ui()` — entry point. The **model calls this**; it returns a Prefab layout for the host to render. Defaults to `visibility=["model"]`.
- `@app.tool()` — backend tool. **The UI calls these via `CallTool`** (e.g., a button click, a table row drill-down, a filter change). Default `visibility=["app"]` — hidden from the model unless explicitly exposed with `model=True`.

This is the critical architectural property for our use case: **the bulk data driving the UI never enters the model's context**.

---

## 4. Host-support matrix

Sourced from the [MCP Apps launch post](https://blog.modelcontextprotocol.io/posts/2026-01-26-mcp-apps/) (2026-01-26) and follow-up coverage. The blog's explicit language is *"Claude — available today both on web and desktop experiences"*, plus "Goose", "Visual Studio Code Insiders", and "ChatGPT (starting that week)". [The Register](https://www.theregister.com/2026/01/26/claude_mcp_apps_arrives/) and [claude.com/blog/interactive-tools-in-claude](https://claude.com/blog/interactive-tools-in-claude) corroborate Claude Desktop.

| Host | MCP Apps rendering | Notes |
|---|---|---|
| Claude.ai (web) | **Shipped** (2026-01-26) | Explicitly named in launch post |
| Claude Desktop | **Shipped** (2026-01-26) | Explicitly named in launch post; renders UI in a sandboxed iframe in-chat |
| Claude Code (CLI) | **No** (structural) | Terminal UI; rendering HTML iframes in a shell is impractical. Not mentioned in launch post. Expect text-only fallback |
| VS Code (Insiders) | Shipped | Per launch post |
| Cursor | Unknown | Not named in launch post; supports MCP broadly — verify separately |
| ChatGPT | Shipped | Per launch post |
| Goose | Shipped | Per launch post |
| JetBrains / Kiro / Antigravity | Exploring | Named as adopters in launch post, no ship date |

**How hosts render.** MCP Apps run in a **sandboxed iframe** controlled by the host. The iframe cannot access the parent, steal cookies, or escape its container — so hosts render third-party apps without trusting the server author. Bidirectional communication is supported: the app (iframe) calls any tool on the MCP server, and the host pushes fresh results back into the iframe. This is the mechanism behind `@app.tool()` callbacks in FastMCPApp.

**Graceful degradation for Claude Code and unsupported hosts.** When a host does not render MCP Apps, FastMCP emits `"[Rendered Prefab UI]"` as a fallback text block — useless on its own. The required pattern is to wrap every `@app.ui()` return in a `ToolResult` carrying both the Prefab payload *and* a meaningful text summary (row count, top values, schema). Any migration must enforce this pattern as a lint or review rule; otherwise we silently degrade the experience for Claude Code users, who are a significant share of our audience.

**The Claude Code audience still benefits.** Even without the UI, the model/UI data split described in §7 still reduces context pressure: Claude Code receives the compact summary from `ToolResult` rather than the full blob, so the context-window win applies there too. The UI chrome is what Claude Code loses, not the architectural benefit.

---

## 5. Migration surface: `mcp.server.fastmcp` → `fastmcp`

The following are concrete change points identified by reading our current codebase against the PrefectHQ `fastmcp` public API.

### 5.1 Imports

```python
# Before
from mcp.server.fastmcp import FastMCP

# After
from fastmcp import FastMCP
```

Touch-points: `src/crowdstrike_mcp/server.py:36`, plus a `TYPE_CHECKING` guarded import in every module (`modules/base.py:18`, `modules/cloud_registration.py:18`, `modules/correlation.py:27`, `modules/response.py:27`, `modules/response_store.py:19`, and 9 more).

### 5.2 Decorator behavior change (v2 → v3)

PrefectHQ `fastmcp` v3 changed `@mcp.tool` to return the original function unchanged. In the official `mcp` SDK, `server.tool()(method)` returns a wrapped object.

Our `BaseModule._add_tool` at `src/crowdstrike_mcp/modules/base.py:103` writes:

```python
server.tool(**kwargs)(method)
```

…and discards the return value. That makes the v3 decorator-behavior change a **no-op for us**: we never accessed `.name`/`.description` on the decorated object. No action needed here.

### 5.3 `add_tool` signature

PrefectHQ `fastmcp` v2+ requires `add_tool` to receive a `Tool` object, not a bare callable (see [PrefectHQ discussion #3340](https://github.com/PrefectHQ/fastmcp/discussions/3340)). The idiomatic form is:

```python
from fastmcp.tools import Tool
tool = Tool.from_function(method, name=name, description=description)
mcp.add_tool(tool)
```

We do not currently call `add_tool` directly — we use the `server.tool()(method)` decorator pattern exclusively — so no mandatory change. If we later want structured tool registration (e.g., to attach MCP Apps metadata), `Tool.from_function` is the path.

### 5.4 Resources

`ngsiem.py:53` uses `server.resource(uri, name=..., description=...)(fn)`. `base.py:108` uses `server.add_resource(resource)`. Both patterns have direct equivalents in PrefectHQ `fastmcp`. Expect parity; verify with a smoke test.

### 5.5 Transports

Today we run three transports (`server.py:97–110`):

- **stdio** — `self.server.run(transport="stdio")`
- **sse** — HTTP via `uvicorn`
- **streamable-http** — HTTP via `uvicorn`

PrefectHQ `fastmcp` supports all three, but **verify the exact runner API**. Public docs are not explicit about whether `run(transport="streamable-http")` is a supported spelling or whether the runner requires a different call path. This is an **open question** (§11).

### 5.6 Middleware / session auth

We have custom ASGI middleware for HTTP transports:

- `common/auth_middleware.py` — API key enforcement
- `common/session_auth.py` — per-request FalconClient injection into a `ContextVar`
- `common/health.py` — health-check endpoint

These mount in `server.py:_run_http` via `uvicorn` around the FastMCP app. PrefectHQ `fastmcp` exposes an ASGI app too, so structurally this should carry over — but the attribute name (`.streamable_http_app()`, `.sse_app()`, etc.) differs between the two libraries. Expect 30–60 minutes of plumbing work.

### 5.7 Registry / auto-discovery

`src/crowdstrike_mcp/registry.py` walks `modules/` via `pkgutil` and calls `mod.register_tools(server)` / `mod.register_resources(server)`. Nothing in this pattern is FastMCP-specific — it's independent of which FastMCP we use.

### 5.8 Tests

We have a `tests/` directory. Our tests likely construct a `FastMCP` instance directly. Every test that does so needs a one-line import update. We should also add a smoke test per transport post-migration.

---

## 6. Effort estimate

Assuming framework-only migration (no Prefab UIs yet):

| Task | Effort |
|---|---|
| Import updates across 14 modules + server + tests | 1–2 hours |
| Transport runner verification (stdio, SSE, streamable-HTTP) | 2–4 hours |
| Middleware re-plumbing (ASGI app attribute differences) | 1–3 hours |
| Resource registration smoke test | 30 min |
| CI updates (`pyproject.toml` dep, lockfile) | 30 min |
| Manual end-to-end from Claude Desktop + Claude Code | 1–2 hours |
| Docs / README refresh | 1 hour |
| **Subtotal** | **~1 engineer-day** |

Adding Prefab to one module (NGSIEM pilot) as a follow-on:

| Task | Effort |
|---|---|
| Learn Prefab component model, state/Rx patterns | 0.5 day |
| Design + build `ngsiem_query_app` (interactive table + BarChart) | 1–1.5 days |
| Wire `@app.tool` handlers for drill-down / filter | 0.5 day |
| `ToolResult` fallback pattern for non-rendering hosts | 0.5 day |
| Manual QA across Claude Desktop / Claude.ai / Claude Code | 0.5 day |
| **Subtotal** | **~3–4 engineer-days** |

**Rolling out Prefab across all 14 modules** is not recommended as a single effort. Module-by-module over several sprints, guided by which modules actually benefit from UI (§8), is the right cadence.

`talonctl` is intentionally on v0.x per the memory note; since it is beta and not tagged v4.x, there is no compat-break concern — but verify the sibling repo imports do not pin the official `mcp` SDK in a way that would break if only `crowdstrike-mcp` migrates.

---

## 7. The strategic upside: context-window arbitrage

The most valuable property of `FastMCPApp`, for this project specifically, is not "pretty charts." It is the split between model-facing output and UI-facing data.

### 7.1 Today's failure mode

`ngsiem_query` results go directly into the model's context. A typical CQL query returning 500 events, each with 20 fields, is tens of thousands of tokens. Analysts often want to *look at* that data — sort it, filter it — but the model only needs aggregate reasoning (counts, top-K, anomalies). Today, the full blob burns context every time.

This is the same pressure driving the `ngsiem-alert-analysis-timeout-fix` spec (2026-04-16) and the `ngsiem-read-expansion` design (2026-04-21). Both work around context bloat indirectly — budgeting queries, compacting responses.

### 7.2 What FastMCPApp enables

With `@app.ui()` + `@app.tool()`:

- `@app.ui()` returns a Prefab layout with a `Table` bound to the full result set. **The data reaches the user's screen but does not enter the model's context.**
- The model receives a compact summary: row count, time range, top host, top event_simpleName, any notable outliers. A few hundred tokens instead of tens of thousands.
- If the user asks a follow-up that requires model reasoning over specific rows, the user clicks a "send to model" button wired to an `@app.tool()` that echoes the selected rows back into the conversation on demand.

This is closer in spirit to how the Falcon console already works: the analyst scans a result table, then escalates specific rows for deeper analysis. Today our MCP collapses that into a one-shot: everything goes to the model or nothing does.

### 7.3 Quantitative sketch

A typical NGSIEM triage query (`#repo=fdr #event_simpleName=ProcessRollup2 | ...` limited to 24h, 1 host) returns:

- **Today:** ~8–40k tokens in model context per call, depending on limit
- **With FastMCPApp:** ~200–500 tokens to the model, full data in the UI
- **Reduction:** 95–99% context pressure on result payloads

Repeated across an analyst's session, this is the difference between hitting model-context limits mid-investigation and not.

---

## 8. Module-by-module UI vision

Presented as concrete Prefab sketches for the three modules where UI yields the largest benefit. Described declaratively — the Prefab-syntax specifics can be confirmed against current docs at implementation time.

### 8.1 NGSIEM — `ngsiem_query_app` (pilot candidate)

**Entry point** (`@app.ui()`): the model calls this with a CQL string and time range. The app:

1. Runs the CQL query via the existing FalconPy NGSIEM client (reuse current `ngsiem_query` logic unchanged).
2. Returns a Prefab layout:
   - **Header row:** query string, result count, time range, run duration (`Heading`, `Muted`, `Badge`)
   - **Summary card:** top host, top `event_simpleName`, distinct count per dimension (`Card`, `Text`)
   - **`BarChart`:** event count by hour (`_bucket(1h)`) if the query has a time component
   - **`Table`:** full result set, paginated client-side, with sortable columns. Common NGSIEM columns (`@timestamp`, `aid`, `ComputerName`, `event_simpleName`, `UserName`) get explicit column configs; everything else falls into a JSON expand.
3. Returns `ToolResult` with both the Prefab payload and a text summary (row count, schema, top values) for the model and for non-rendering hosts.

**Backend tools** (`@app.tool()`):
- `ngsiem_query_drilldown(row_id)` — the UI's row-click handler; returns the full single-row JSON as a `Card` or copies to model context.
- `ngsiem_query_pivot_host(aid)` — pre-populates a follow-up query scoped to one host.

### 8.2 Threat Graph — `threat_graph_explorer_app`

Today the threat_graph module returns text lists of vertices and edges. In a UI, the natural representation is a vertex card with clickable edge badges that trigger pivots.

**Entry point:** the model calls with a seed indicator (hash, IP, domain, device).
1. Fetches the vertex.
2. Renders a `Card` with vertex properties (`Heading`, `Text`, `Muted`).
3. Below: a `Grid` of edge `Badge`s grouped by edge type (`INCIDENT_OF`, `WRITTEN_BY`, `EXECUTED_BY`, etc.) — each badge is a button.
4. `@app.tool()` handlers for each pivot use case; clicking an edge replaces the vertex card without round-tripping through the model.

This preserves exploratory pivot flow without exhausting context on edges the analyst doesn't care about.

### 8.3 Spotlight — `spotlight_vulns_app`

Vulnerability lists are a natural tabular use case:

1. Entry point: the model calls with a host filter or CVE filter.
2. Render a `Table` with columns: `CVE`, `severity` (colored `Badge`), `CVSS`, host count, exploit status, first seen, last seen.
3. Sortable by any column; default sort is severity DESC then CVSS DESC.
4. Row expansion (an `@app.tool()`) fetches host list for that CVE on demand.

### 8.4 Second-tier candidates

Mentioned but not designed in detail — each warrants its own mini-design before implementation:

- **alerts** — triage board view (columns by status, card per alert, severity badges)
- **cloud_security** — risk list with grouping by cloud/account; timeline view for `cloud_risk_timeline`
- **case_management** — case detail with timeline and comment thread
- **correlation** — rule list with FQL preview; `@app.tool()` to test a rule against recent events

### 8.5 Modules that gain little from UI

- `response_store` — purely internal; no user-facing render value
- `rtr` — already a conversational pattern; table not helpful
- `idp` — low query volume; not worth the surface area
- `cloud_registration` — config/management ops, not investigative

---

## 9. Risks & unknowns

### 9.1 Dependency risk
- PrefectHQ `fastmcp` has shipped 3.0 → 3.1 → 3.2 in the first four months of 2026. Rapid iteration means breaking changes are likely. Pin tightly and monitor changelogs.
- We inherit a non-Anthropic dependency on our primary MCP code path. If `fastmcp` diverges from protocol changes the official `mcp` SDK adopts first, we could lag.

### 9.2 Host fragmentation
- Claude Desktop and Claude.ai render UI; Claude Code does not. UX bifurcates: rich in Desktop/web, text-only in Code. `ToolResult` fallback is non-trivial to maintain well — it's easy to let the text summary rot out of sync with the UI over time. Treat the text summary as a first-class return value with its own review criteria, not an afterthought.
- VS Code, Cursor (if supported), ChatGPT, and Goose will not all render identically — sandboxed iframes are consistent in mechanism but hosts can style, size, and constrain them differently. Cross-client QA cost compounds.

### 9.3 Testing
- Our current test suite constructs `FastMCP` directly. Any Prefab-returning tool is hard to assert against beyond "it returned something of the right shape." UI correctness needs manual QA; this is a known gap in MCP Apps tooling generally.

### 9.4 Credential-less HTTP transport compat
- Our `FalconClient.deferred()` pattern plus `session_auth_middleware` assumes we control the ASGI app. If PrefectHQ `fastmcp` wraps the ASGI app in layers we don't control, the session `ContextVar` injection site may move. Worth a spike before committing.

### 9.5 Rollback plan
- The migration is file-level; git revert is trivial. But if we release a version publicly and users pin it, rolling back the framework is disruptive. Gate the migration behind a minor version bump (v4.4) with a clear CHANGELOG and a longer-than-usual release candidate window.

### 9.6 Scope creep
- The temptation to "migrate and also Prefab-ify everything in one PR" is strong and should be resisted. Migration first. Prefab second, per-module.

---

## 10. Decision framework

**Proceed** (framework migration in v4.4, NGSIEM Prefab pilot in v4.5) **when all three hold:**

1. Smoke test confirms PrefectHQ `fastmcp` runs our three transports (stdio, SSE, streamable-HTTP) with the existing middleware stack intact. This is plumbing verification — §5.5 and §5.6.
2. `fastmcp` v3.3 (or the next release after this doc's date) ships without further `FastMCPApp` API breakage, suggesting the surface is stabilizing.
3. An analyst user is identified who will exercise the NGSIEM UI and give feedback within two weeks of pilot availability.

**Wait and re-evaluate in 6–8 weeks** if 1 or 2 is unresolved.

**Decline** if:
- A subsequent PrefectHQ `fastmcp` release deprecates `FastMCPApp` in favor of something else.
- Anthropic ships an equivalent UI capability directly into the official `mcp` SDK, eliminating the need to migrate framework.
- Transport or middleware compatibility (§5.5, §5.6) proves materially harder than the effort estimate (§6) allows — i.e., more than ~1 day of uvicorn/ASGI spelunking.

### Cheapest experiment that resolves the biggest remaining unknown

The host-rendering unknown is now resolved via documentation — no experiment needed there. The remaining unknown is transport/middleware parity. A half-day spike:

1. Stand up a PrefectHQ `fastmcp` server that imports two trivial tools and one resource.
2. Confirm it runs under our three transports with `uvicorn` and our existing `auth_middleware.py` / `session_auth.py` unchanged.
3. Confirm `Tool.from_function` + `add_tool` works as a registration path, since some module use cases may prefer it over the decorator form.

If that spike passes, proceed to a full migration PR. If middleware mounting requires non-trivial rework, re-evaluate scope.

---

## 11. Open questions

Items resolved since earlier drafts:

- ~~Does Claude Desktop render MCP Apps?~~ **Resolved** — launch post states "Claude — available today both on web and desktop experiences" (2026-01-26). Claude Desktop renders UI in a sandboxed iframe in-chat.
- ~~Does Claude Code render MCP Apps?~~ **Resolved** — not named in any launch post; rendering HTML iframes in a terminal is structurally impractical. Treat as unsupported and rely on `ToolResult` text fallback.

Items still open:

1. **PrefectHQ `fastmcp` transport runner API:** exact signatures for stdio, SSE, streamable-HTTP (§5.5).
2. **PrefectHQ `fastmcp` ASGI app attribute:** where our middleware mounts when running under uvicorn (§5.6).
3. **Is `fastmcp dev apps` production-safe or development-only?** Docs don't say.
4. **Prefab component subset consistency across hosts.** Sandboxed iframes are a uniform mechanism, but Claude Desktop, VS Code, and Goose may impose different CSP, sizing, or event constraints. Any components known to misrender on specific hosts?
5. **How does `FastMCPApp` compose with existing `FastMCP` tools?** Can a single server expose both plain tools and app tools, so migration happens module-by-module?
6. **`Table` component specifics** — column definition syntax, server-side vs. client-side pagination, row-selection events — underspecified in public docs as of 2026-04-21.
7. **Sandboxed-iframe restrictions vs. our FalconPy callbacks.** `@app.tool()` handlers for drill-down calls will hit FalconPy; confirm there are no iframe-origin constraints that block the `CallTool` round trip.

Resolving 1, 2, and 5 is the prerequisite set before any implementation plan is written.

---

## 12. Next steps if approved

1. Run the 1-hour throwaway experiment in §10.
2. Based on result, either archive this doc or proceed to write a separate **implementation plan** (via `writing-plans` skill) scoped to §5 (framework migration only), with §8.1 (NGSIEM pilot) as a follow-up plan.
3. Keep §8.2–8.4 as deferred backlog items; do not plan them until the pilot proves the value hypothesis.

---

## Sources

- [MCP Apps — Bringing UI Capabilities to MCP Clients (MCP blog, 2026-01-26)](https://blog.modelcontextprotocol.io/posts/2026-01-26-mcp-apps/)
- [Interactive connectors and MCP Apps (claude.com)](https://claude.com/blog/interactive-tools-in-claude)
- [Claude supports MCP Apps, presents UI within chat window (The Register, 2026-01-26)](https://www.theregister.com/2026/01/26/claude_mcp_apps_arrives/)
- [MCP Apps overview (modelcontextprotocol.io)](https://modelcontextprotocol.io/extensions/apps/overview)
- [MCP Apps design guidelines (claude.com)](https://claude.com/docs/connectors/building/mcp-apps/design-guidelines)
- [@modelcontextprotocol/ext-apps (v1.1.2)](https://apps.extensions.modelcontextprotocol.io/api/)
- [Prefab UI — FastMCP](https://gofastmcp.com/apps/prefab)
- [FastMCPApp — Interactive Apps](https://gofastmcp.com/apps/interactive-apps)
- [FastMCP 3.2 release notes — Mostly Harmless](https://jlowin.dev/blog/fastmcp-3-2)
- [FastMCP 3.1.0: Code to Joy](https://github.com/PrefectHQ/fastmcp/releases/tag/v3.1.0)
- [Migrating from `mcp` to `fastmcp` (PrefectHQ discussion #3340)](https://github.com/PrefectHQ/fastmcp/discussions/3340)
- [PrefectHQ/fastmcp on GitHub](https://github.com/PrefectHQ/fastmcp)
