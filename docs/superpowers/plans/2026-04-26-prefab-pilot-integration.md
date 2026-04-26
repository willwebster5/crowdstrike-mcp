# Prefab Pilot Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fold the standalone Prefab pilot server into the main `crowdstrike_mcp` server as a peer rendering tool that shares the NGSIEM query engine and emits `ResponseStore` ref_ids the agent can follow up on.

**Architecture:** The main server swaps from `mcp.server.fastmcp.FastMCP` to `fastmcp.apps.FastMCPApp` so `@app.ui()` is available. A new `NGSIEMRenderModule` (auto-discovered like every other module) registers `ngsiem_query_render` and `ngsiem_query_drilldown`. It holds an internal `NGSIEMModule` instance and calls its newly-public `execute_query` so the query engine is shared with zero drift risk. The pilot's `prefab_pilot/` package is deleted; its `summary.py`/`layout.py`/`fallback.py` migrate under `modules/ngsiem_render/`.

**Tech Stack:** Python 3.11+, `fastmcp.apps.FastMCPApp`, `prefab_ui` components/actions, `pytest`/`pytest-asyncio`, existing `BaseModule` + `ResponseStore` infrastructure.

**Spec:** `docs/superpowers/specs/2026-04-26-prefab-pilot-integration-design.md`

---

## File Map

**Created:**
- `src/crowdstrike_mcp/modules/ngsiem_render.py` — `NGSIEMRenderModule` class (auto-discovered)
- `src/crowdstrike_mcp/modules/ngsiem_render/__init__.py` — `RENDER_AVAILABLE` flag + re-exports
- `src/crowdstrike_mcp/modules/ngsiem_render/summary.py` — migrated from `prefab_pilot/summary.py`
- `src/crowdstrike_mcp/modules/ngsiem_render/layout.py` — migrated; `_APP_NAME` flips to `"crowdstrike-falcon"`
- `src/crowdstrike_mcp/modules/ngsiem_render/fallback.py` — migrated
- `src/crowdstrike_mcp/modules/ngsiem_render/mock_data.py` — migrated
- `tests/modules/ngsiem_render/__init__.py`
- `tests/modules/ngsiem_render/test_summary.py` — migrated
- `tests/modules/ngsiem_render/test_layout.py` — migrated
- `tests/modules/ngsiem_render/test_module.py` — rewritten from pilot's `test_server.py`
- `scripts/spike_fastmcpapp.py` — temporary spike script (deleted at end of plan)

**Modified:**
- `src/crowdstrike_mcp/server.py:79` — `FastMCP("crowdstrike-falcon")` → `FastMCPApp("crowdstrike-falcon")`
- `src/crowdstrike_mcp/modules/ngsiem.py:207` — `_execute_query` → `execute_query` (also any in-file callers)

**Deleted:**
- `src/crowdstrike_mcp/prefab_pilot/` — entire package
- `tests/prefab_pilot/` — entire directory

**Conflict check:** `src/crowdstrike_mcp/modules/ngsiem_render.py` (file) and `src/crowdstrike_mcp/modules/ngsiem_render/` (package) cannot coexist in standard Python. Resolution: the module class lives at `src/crowdstrike_mcp/modules/ngsiem_render/__init__.py` (top of the package). The auto-discovery walker in `registry.py` uses `pkgutil.iter_modules` which yields packages too, so this works. There is no separate `ngsiem_render.py` file.

**Revised file map (final):**
- `src/crowdstrike_mcp/modules/ngsiem_render/__init__.py` — exposes `NGSIEMRenderModule` AND `RENDER_AVAILABLE`
- `src/crowdstrike_mcp/modules/ngsiem_render/_module.py` — class implementation (kept private to avoid being picked up as a separate sibling)
- `src/crowdstrike_mcp/modules/ngsiem_render/summary.py`
- `src/crowdstrike_mcp/modules/ngsiem_render/layout.py`
- `src/crowdstrike_mcp/modules/ngsiem_render/fallback.py`
- `src/crowdstrike_mcp/modules/ngsiem_render/mock_data.py`

`registry.py:43-46` does `for attr_name in dir(mod)` against the imported package; `__init__.py` re-exports `NGSIEMRenderModule`, so it's discovered exactly once.

---

## Task 1: FastMCPApp drop-in spike

**Why:** Spec R1 requires confirming `FastMCPApp` supports the surfaces existing modules use (`.tool()`, `.add_resource()`, `.resource()`, `.run(transport=...)`) before any other code changes.

**Files:**
- Create: `scripts/spike_fastmcpapp.py` (temporary; deleted in Task 18)

- [ ] **Step 1: Write the spike script**

```python
# scripts/spike_fastmcpapp.py
"""
Spike: verify fastmcp.apps.FastMCPApp is a drop-in for mcp.server.fastmcp.FastMCP
for the crowdstrike-mcp server's needs.

Surfaces required:
  - .tool(name=...) decorator (BaseModule._add_tool calls server.tool(**kwargs)(method))
  - .add_resource(resource) (BaseModule._add_resource)
  - .resource(uri, ...) decorator (NGSIEMModule.register_resources uses this)
  - .run(transport="stdio")
  - .sse_app() / .streamable_http_app() (HTTP transports)

Run: python scripts/spike_fastmcpapp.py
Outputs: PASS/FAIL per surface, plus a summary verdict.
"""

from __future__ import annotations

import sys


def check(label: str, fn) -> bool:
    try:
        fn()
        print(f"  PASS  {label}")
        return True
    except Exception as exc:
        print(f"  FAIL  {label}: {type(exc).__name__}: {exc}")
        return False


def main() -> int:
    from fastmcp.apps import FastMCPApp

    app = FastMCPApp("spike-test")
    results: list[bool] = []

    # 1. server.tool() decorator
    def _tool_decorator():
        @app.tool(name="spike_tool")
        def my_tool() -> str:
            return "ok"
    results.append(check(".tool(name=...) decorator", _tool_decorator))

    # 2. server.add_resource(resource)
    def _add_resource():
        from mcp.types import Resource
        # Build a minimal Resource. If FastMCPApp expects a different type,
        # this fail will tell us what to migrate to.
        r = Resource(uri="spike://test", name="spike", description="test")
        app.add_resource(r)
    results.append(check(".add_resource(Resource)", _add_resource))

    # 3. server.resource(uri, ...) decorator
    def _resource_decorator():
        @app.resource("spike://decorator", name="spike-dec", description="d")
        def _payload():
            return "hello"
    results.append(check(".resource(uri, ...) decorator", _resource_decorator))

    # 4. .sse_app() / .streamable_http_app()
    results.append(check(".sse_app()", lambda: app.sse_app()))
    results.append(check(".streamable_http_app()", lambda: app.streamable_http_app()))

    print()
    if all(results):
        print("VERDICT: PASS — proceed with FastMCPApp swap (Task 4).")
        return 0
    print("VERDICT: FAIL — see Task 1 outcomes section of the plan for fallback.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Run the spike**

Run: `python scripts/spike_fastmcpapp.py`

**Outcomes:**

- *All PASS:* proceed with the plan as written.
- *`.add_resource` fails or `.resource` decorator fails:* document the actual signature/type FastMCPApp accepts (read `fastmcp.apps.FastMCPApp` source via `python -c "import inspect; from fastmcp.apps import FastMCPApp; print(inspect.getsource(FastMCPApp))"`). If the fix is a simple type swap, update the BaseModule `_add_resource` and Task 4's adapter notes. If the fix needs a refactor to all modules, **STOP** and re-spec.
- *`.sse_app()` / `.streamable_http_app()` fail:* HTTP transport is broken under FastMCPApp. **STOP** and re-spec — this is the deep-surface failure called out in spec R1.
- *Any other surface fails:* **STOP** and re-spec.

- [ ] **Step 3: Commit the spike output**

```bash
git add scripts/spike_fastmcpapp.py
git commit -m "spike: verify FastMCPApp drop-in compatibility for crowdstrike-mcp server"
```

---

## Task 2: Make `NGSIEMModule.execute_query` public

**Why:** Spec D6 — `NGSIEMRenderModule` calls into `NGSIEMModule.execute_query`. Underscore-prefixed methods signal "don't reach in from outside the module"; renaming aligns the public surface with the actual usage.

**Files:**
- Modify: `src/crowdstrike_mcp/modules/ngsiem.py:207` — rename method
- Modify: `src/crowdstrike_mcp/modules/ngsiem.py:150` — update internal caller in `ngsiem_query`
- Modify: `src/crowdstrike_mcp/modules/alerts.py` — update any caller (verify with grep)

- [ ] **Step 1: Identify all callers**

Run: `grep -rn "_execute_query" src/crowdstrike_mcp/`
Expected output: a handful of references — at minimum `ngsiem.py:150` (internal) and `ngsiem.py:207` (definition). Audit any other matches.

- [ ] **Step 2: Run existing NGSIEM tests to establish baseline**

Run: `pytest tests/test_ngsiem_reads.py tests/test_ngsiem_timeout_fix.py -v`
Expected: PASS (whatever the current state is — the rename should not change this).

- [ ] **Step 3: Rename method in `ngsiem.py`**

In `src/crowdstrike_mcp/modules/ngsiem.py`:

- Line 150: change `result = self._execute_query(...)` to `result = self.execute_query(...)`
- Line 207: change `def _execute_query(` to `def execute_query(`

Leave behavior, signature, and docstring otherwise unchanged.

- [ ] **Step 4: Update other callers**

For each caller surfaced in Step 1, swap `_execute_query` → `execute_query`. Likely `src/crowdstrike_mcp/modules/alerts.py` is unaffected because it has its own `_execute_ngsiem_query` (different name) — confirm this.

- [ ] **Step 5: Re-run tests**

Run: `pytest tests/test_ngsiem_reads.py tests/test_ngsiem_timeout_fix.py tests/test_alerts_endpoint_enrichment.py -v`
Expected: PASS — same as Step 2.

- [ ] **Step 6: Commit**

```bash
git add src/crowdstrike_mcp/modules/ngsiem.py src/crowdstrike_mcp/modules/alerts.py
git commit -m "refactor(ngsiem): make execute_query public for cross-module reuse"
```

---

## Task 3: Create `modules/ngsiem_render/` package skeleton

**Why:** Establishes the new package and the `RENDER_AVAILABLE` import-gate flag before migrating files into it. Ensures auto-discovery doesn't trip on a half-built package.

**Files:**
- Create: `src/crowdstrike_mcp/modules/ngsiem_render/__init__.py`

- [ ] **Step 1: Write the package init**

```python
# src/crowdstrike_mcp/modules/ngsiem_render/__init__.py
"""
NGSIEM render module — interactive Prefab UI for NGSIEM query results.

Registers two tools:
  ngsiem_query_render     — UI tool, returns a Prefab layout + ref_id summary
  ngsiem_query_drilldown  — backend tool the UI calls on row click

Imports prefab_ui lazily; if the optional dependency isn't installed, this
package still imports cleanly but ``RENDER_AVAILABLE`` is False and the
module class is not exposed. The auto-discovery walker in registry.py
checks for ``BaseModule`` subclasses on the imported module — when
RENDER_AVAILABLE is False we don't expose one, so nothing registers.
"""

from __future__ import annotations

try:
    import prefab_ui  # noqa: F401
    RENDER_AVAILABLE = True
except ImportError:
    RENDER_AVAILABLE = False

if RENDER_AVAILABLE:
    from crowdstrike_mcp.modules.ngsiem_render._module import NGSIEMRenderModule
    __all__ = ["NGSIEMRenderModule", "RENDER_AVAILABLE"]
else:
    __all__ = ["RENDER_AVAILABLE"]
```

- [ ] **Step 2: Verify the package imports cleanly**

Run: `python -c "from crowdstrike_mcp.modules.ngsiem_render import RENDER_AVAILABLE; print('RENDER_AVAILABLE:', RENDER_AVAILABLE)"`
Expected: prints `RENDER_AVAILABLE: True` (since the dev environment has prefab_ui installed). The follow-on `from ._module import NGSIEMRenderModule` will fail with `ModuleNotFoundError: ... _module` because we haven't created it yet — temporarily add `pass` after `RENDER_AVAILABLE = True` to skip the import, OR proceed knowing the test will be deferred.

Cleaner: rewrite Step 1's branch as:

```python
if RENDER_AVAILABLE:
    try:
        from crowdstrike_mcp.modules.ngsiem_render._module import NGSIEMRenderModule
        __all__ = ["NGSIEMRenderModule", "RENDER_AVAILABLE"]
    except ImportError:
        # _module not yet created (during incremental implementation) or has its own broken dep
        __all__ = ["RENDER_AVAILABLE"]
else:
    __all__ = ["RENDER_AVAILABLE"]
```

This double-try lets us land Task 3 cleanly before `_module.py` exists in Task 7.

Re-run: `python -c "from crowdstrike_mcp.modules.ngsiem_render import RENDER_AVAILABLE; print(RENDER_AVAILABLE)"`
Expected: `True`

- [ ] **Step 3: Verify auto-discovery doesn't crash**

Run: `python -c "from crowdstrike_mcp.registry import discover_module_classes; print([c.__name__ for c in discover_module_classes()])"`
Expected: lists existing modules. `NGSIEMRenderModule` is NOT in the list yet (it doesn't exist).

- [ ] **Step 4: Commit**

```bash
git add src/crowdstrike_mcp/modules/ngsiem_render/__init__.py
git commit -m "feat(ngsiem-render): create package skeleton with RENDER_AVAILABLE gate"
```

---

## Task 4: Migrate `summary.py`

**Why:** Pure data-shaping code — moves under the new package without behavior changes. Doing it as its own task keeps the diff reviewable.

**Files:**
- Create: `src/crowdstrike_mcp/modules/ngsiem_render/summary.py`
- Read for migration source: `src/crowdstrike_mcp/prefab_pilot/summary.py`

- [ ] **Step 1: Copy the file**

```bash
cp src/crowdstrike_mcp/prefab_pilot/summary.py src/crowdstrike_mcp/modules/ngsiem_render/summary.py
```

- [ ] **Step 2: Verify import path**

Open `src/crowdstrike_mcp/modules/ngsiem_render/summary.py` and confirm there are no internal imports referring to `crowdstrike_mcp.prefab_pilot` (summary.py should have none — it's leaf code). If found, change them to `crowdstrike_mcp.modules.ngsiem_render`.

- [ ] **Step 3: Verify it imports**

Run: `python -c "from crowdstrike_mcp.modules.ngsiem_render.summary import summarize_events, WidgetType; print(WidgetType.SINGLE_VALUE)"`
Expected: `WidgetType.SINGLE_VALUE`

- [ ] **Step 4: Commit**

```bash
git add src/crowdstrike_mcp/modules/ngsiem_render/summary.py
git commit -m "feat(ngsiem-render): migrate summary.py from prefab_pilot"
```

---

## Task 5: Migrate `fallback.py`

**Files:**
- Create: `src/crowdstrike_mcp/modules/ngsiem_render/fallback.py`
- Read for migration source: `src/crowdstrike_mcp/prefab_pilot/fallback.py`

- [ ] **Step 1: Copy the file**

```bash
cp src/crowdstrike_mcp/prefab_pilot/fallback.py src/crowdstrike_mcp/modules/ngsiem_render/fallback.py
```

- [ ] **Step 2: Update internal imports**

Open `src/crowdstrike_mcp/modules/ngsiem_render/fallback.py`. Replace any
`from crowdstrike_mcp.prefab_pilot.summary import ...` with
`from crowdstrike_mcp.modules.ngsiem_render.summary import ...`.

- [ ] **Step 3: Verify it imports**

Run: `python -c "from crowdstrike_mcp.modules.ngsiem_render.fallback import summary_to_text; print('ok')"`
Expected: `ok`

- [ ] **Step 4: Commit**

```bash
git add src/crowdstrike_mcp/modules/ngsiem_render/fallback.py
git commit -m "feat(ngsiem-render): migrate fallback.py from prefab_pilot"
```

---

## Task 6: Migrate `mock_data.py`

**Files:**
- Create: `src/crowdstrike_mcp/modules/ngsiem_render/mock_data.py`
- Read for migration source: `src/crowdstrike_mcp/prefab_pilot/mock_data.py`

- [ ] **Step 1: Copy the file**

```bash
cp src/crowdstrike_mcp/prefab_pilot/mock_data.py src/crowdstrike_mcp/modules/ngsiem_render/mock_data.py
```

- [ ] **Step 2: Update any internal imports** (likely none — it's leaf code)

Same procedure as Task 5 Step 2 if any are found.

- [ ] **Step 3: Verify it imports**

Run: `python -c "from crowdstrike_mcp.modules.ngsiem_render.mock_data import generate_process_events; events = generate_process_events(count=3, seed=1); print(len(events))"`
Expected: `3`

- [ ] **Step 4: Commit**

```bash
git add src/crowdstrike_mcp/modules/ngsiem_render/mock_data.py
git commit -m "feat(ngsiem-render): migrate mock_data.py from prefab_pilot"
```

---

## Task 7: Migrate `layout.py` with `_APP_NAME` flip

**Why:** The drilldown wire-format hash is computed from `(app_name, tool_name)`. The integrated server's app name is `"crowdstrike-falcon"`, not `"crowdstrike-prefab-pilot"`. The constant flip is the integration's most behavior-visible change.

**Files:**
- Create: `src/crowdstrike_mcp/modules/ngsiem_render/layout.py`
- Read for migration source: `src/crowdstrike_mcp/prefab_pilot/layout.py:44`

- [ ] **Step 1: Copy the file**

```bash
cp src/crowdstrike_mcp/prefab_pilot/layout.py src/crowdstrike_mcp/modules/ngsiem_render/layout.py
```

- [ ] **Step 2: Update internal imports**

Open `src/crowdstrike_mcp/modules/ngsiem_render/layout.py`. Replace
`from crowdstrike_mcp.prefab_pilot.summary import QuerySummary, WidgetType` with
`from crowdstrike_mcp.modules.ngsiem_render.summary import QuerySummary, WidgetType`.

- [ ] **Step 3: Update `_APP_NAME`**

Find the line:

```python
_APP_NAME = "crowdstrike-prefab-pilot"
```

Change to:

```python
_APP_NAME = "crowdstrike-falcon"
```

The `_DRILLDOWN_BACKEND_NAME` constant directly below uses `_APP_NAME` and recomputes automatically.

- [ ] **Step 4: Verify the hash recomputes**

Run:

```bash
python -c "
from fastmcp.server.providers.addressing import hashed_backend_name
from crowdstrike_mcp.modules.ngsiem_render.layout import _DRILLDOWN_BACKEND_NAME
expected = hashed_backend_name('crowdstrike-falcon', 'ngsiem_query_drilldown')
print('match:', _DRILLDOWN_BACKEND_NAME == expected)
print('value:', _DRILLDOWN_BACKEND_NAME)
"
```

Expected: `match: True` and a hash-prefixed string ending in `_ngsiem_query_drilldown`.

- [ ] **Step 5: Verify it imports + builds a layout**

Run:

```bash
python -c "
from crowdstrike_mcp.modules.ngsiem_render.layout import build_ngsiem_query_layout
from crowdstrike_mcp.modules.ngsiem_render.summary import summarize_events
events = [{'ComputerName': 'H', 'event_simpleName': 'X', 'UserName': 'u', 'ImageFileName': 'i'}]
s = summarize_events(events)
layout = build_ngsiem_query_layout(events=events, query='q', summary=s)
print('type:', layout.type)
"
```

Expected: `type: Column`

- [ ] **Step 6: Commit**

```bash
git add src/crowdstrike_mcp/modules/ngsiem_render/layout.py
git commit -m "feat(ngsiem-render): migrate layout.py and flip _APP_NAME to crowdstrike-falcon"
```

---

## Task 8: Implement `NGSIEMRenderModule._module` skeleton

**Why:** Get the class skeleton compiling and auto-discoverable before adding tool implementations. Lets us land tools incrementally with passing tests at each step.

**Files:**
- Create: `src/crowdstrike_mcp/modules/ngsiem_render/_module.py`

- [ ] **Step 1: Write the failing test**

Create `tests/modules/__init__.py` (empty) and `tests/modules/ngsiem_render/__init__.py` (empty) if they don't exist.

Create `tests/modules/ngsiem_render/test_module.py`:

```python
"""Tests for NGSIEMRenderModule registration and tool wiring.

Tests use the auto-discovered class instantiated against a real FastMCPApp
to exercise the live registration path — same shape as production.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


def test_module_class_is_importable():
    from crowdstrike_mcp.modules.ngsiem_render import NGSIEMRenderModule
    assert NGSIEMRenderModule is not None


def test_module_registers_two_tools():
    from fastmcp.apps import FastMCPApp
    from crowdstrike_mcp.modules.ngsiem_render import NGSIEMRenderModule

    mock_client = MagicMock()
    app = FastMCPApp("test")
    module = NGSIEMRenderModule(mock_client)
    module.register_tools(app)

    assert "ngsiem_query_render" in module.tools
    assert "ngsiem_query_drilldown" in module.tools


@pytest.fixture
def anyio_backend():
    return "asyncio"
```

- [ ] **Step 2: Run test, expect failure**

Run: `pytest tests/modules/ngsiem_render/test_module.py::test_module_class_is_importable -v`
Expected: FAIL with `ImportError: cannot import name 'NGSIEMRenderModule'`.

- [ ] **Step 3: Write the skeleton**

Create `src/crowdstrike_mcp/modules/ngsiem_render/_module.py`:

```python
"""
NGSIEMRenderModule — UI tool that renders NGSIEM query results as Prefab.

Auto-discovered via registry.py. Holds an internal NGSIEMModule instance
to share the query engine without depending on auto-discovery instance
sharing (registry instantiates each module class with cls(client)).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.modules.ngsiem import NGSIEMModule

if TYPE_CHECKING:
    from fastmcp.apps import FastMCPApp


class NGSIEMRenderModule(BaseModule):
    """Render NGSIEM query results as interactive Prefab UI."""

    def __init__(self, client):
        super().__init__(client)
        self._ngsiem = NGSIEMModule(client)
        self._log("Initialized")

    def register_tools(self, server: "FastMCPApp") -> None:
        # Tool methods filled in by Tasks 9 and 10.
        self._add_tool(
            server,
            self.ngsiem_query_render,
            name="ngsiem_query_render",
            description=(
                "Render an NGSIEM/CQL query result as an interactive Prefab UI for the user. "
                "Use when the user asks to see, view, show, or visualize query results. "
                "Returns a brief summary plus a stored-response ref_id; call "
                "get_stored_response(ref_id=...) to inspect specific events."
            ),
        )
        self._add_tool(
            server,
            self.ngsiem_query_drilldown,
            name="ngsiem_query_drilldown",
            description="Backend tool the UI calls when the user clicks a result row.",
        )

    async def ngsiem_query_render(self, query: str, start_time: str = "1d", max_results: int = 100):
        """Placeholder — implemented in Task 9."""
        raise NotImplementedError("Implemented in Task 9")

    def ngsiem_query_drilldown(self, row: dict):
        """Placeholder — implemented in Task 10."""
        raise NotImplementedError("Implemented in Task 10")
```

- [ ] **Step 4: Run tests, expect pass**

Run: `pytest tests/modules/ngsiem_render/test_module.py -v`
Expected: both tests PASS.

- [ ] **Step 5: Verify auto-discovery picks it up**

Run: `python -c "from crowdstrike_mcp.registry import discover_module_classes; print([c.__name__ for c in discover_module_classes()])"`
Expected: includes `NGSIEMRenderModule` in the list.

- [ ] **Step 6: Commit**

```bash
git add src/crowdstrike_mcp/modules/ngsiem_render/_module.py tests/modules/__init__.py tests/modules/ngsiem_render/__init__.py tests/modules/ngsiem_render/test_module.py
git commit -m "feat(ngsiem-render): NGSIEMRenderModule skeleton with auto-discovery"
```

---

## Task 9: Implement `ngsiem_query_render`

**Why:** This is the core UI tool. It executes a query through `NGSIEMModule.execute_query`, summarizes, stores in `ResponseStore` for agent follow-up, builds the Prefab layout, and returns a `ToolResult` with both text fallback (summary + ref_id) and structured content (PrefabApp envelope).

**Files:**
- Modify: `src/crowdstrike_mcp/modules/ngsiem_render/_module.py`
- Modify: `tests/modules/ngsiem_render/test_module.py` — add tests

- [ ] **Step 1: Write failing tests**

Append to `tests/modules/ngsiem_render/test_module.py`:

```python
@pytest.mark.anyio
async def test_render_tool_returns_tool_result_with_text_and_structured_content(monkeypatch):
    from fastmcp.apps import FastMCPApp
    from crowdstrike_mcp.modules.ngsiem_render import NGSIEMRenderModule
    from crowdstrike_mcp.modules.ngsiem_render.mock_data import generate_process_events

    mock_client = MagicMock()
    module = NGSIEMRenderModule(mock_client)

    # Stub execute_query to return mock events deterministically.
    def fake_exec(query, start_time="1d", max_results=100, fields=None):
        return {
            "success": True,
            "events": generate_process_events(count=5, seed=1),
            "events_processed": 5, "events_matched": 5, "events_returned": 5,
            "query": query, "time_range": start_time,
        }
    monkeypatch.setattr(module._ngsiem, "execute_query", fake_exec)

    result = await module.ngsiem_query_render(query="q", start_time="1h")
    text = "\n".join(b.text for b in result.content if hasattr(b, "text"))
    assert "5 events" in text or "Events: 5" in text
    assert "ref_id" in text or "resp_" in text
    assert result.structured_content is not None
    assert "$prefab" in result.structured_content
    assert "view" in result.structured_content


@pytest.mark.anyio
async def test_render_tool_text_fallback_includes_ref_id_resolvable_via_response_store(monkeypatch):
    import re
    from crowdstrike_mcp.modules.ngsiem_render import NGSIEMRenderModule
    from crowdstrike_mcp.modules.ngsiem_render.mock_data import generate_process_events
    from crowdstrike_mcp.response_store import ResponseStore

    ResponseStore._reset()

    mock_client = MagicMock()
    module = NGSIEMRenderModule(mock_client)

    def fake_exec(query, start_time="1d", max_results=100, fields=None):
        return {"success": True, "events": generate_process_events(count=3, seed=1),
                "events_processed": 3, "events_matched": 3, "events_returned": 3,
                "query": query, "time_range": start_time}
    monkeypatch.setattr(module._ngsiem, "execute_query", fake_exec)

    result = await module.ngsiem_query_render(query="q")
    text = "\n".join(b.text for b in result.content if hasattr(b, "text"))
    match = re.search(r"resp_\d+", text)
    assert match is not None, f"no ref_id in fallback text:\n{text}"
    stored = ResponseStore.get(match.group(0))
    assert stored is not None
    assert stored.tool_name == "ngsiem_query_render"
```

- [ ] **Step 2: Run, expect failures**

Run: `pytest tests/modules/ngsiem_render/test_module.py -v`
Expected: the two new tests FAIL with `NotImplementedError: Implemented in Task 9`.

- [ ] **Step 3: Write the implementation**

In `src/crowdstrike_mcp/modules/ngsiem_render/_module.py`, replace the `ngsiem_query_render` placeholder with:

```python
async def ngsiem_query_render(
    self,
    query: str,
    start_time: str = "1d",
    max_results: int = 100,
):
    """Render an NGSIEM query result as Prefab UI.

    Returns a ToolResult carrying:
      - content: short text summary including a ResponseStore ref_id
      - structured_content: the PrefabApp envelope the UI host renders
    """
    from fastmcp.tools import ToolResult
    from mcp.types import TextContent

    from crowdstrike_mcp.modules.ngsiem_render.layout import build_ngsiem_query_layout
    from crowdstrike_mcp.modules.ngsiem_render.summary import summarize_events
    from crowdstrike_mcp.response_store import ResponseStore

    max_results = min(max(max_results, 1), 1000)
    result = self._ngsiem.execute_query(query, start_time=start_time, max_results=max_results)

    if not result.get("success"):
        error = result.get("error", "unknown error")
        return ToolResult(
            content=[TextContent(
                type="text",
                text=f"NGSIEM render query failed: {error}",
            )],
        )

    events = result.get("events") or []
    summary = summarize_events(events)

    ref_id = ResponseStore.store(
        data={"events": events, "query": result.get("query"), "time_range": result.get("time_range")},
        tool_name="ngsiem_query_render",
        metadata={"query": query, "start_time": start_time},
    )

    text_lines = [
        "Rendered NGSIEM query for the user.",
        f"Query: {query}",
        f"Time range: {start_time}",
        f"Events: {summary.row_count}",
    ]
    if summary.top_host is not None:
        host, count = summary.top_host
        text_lines.append(f"Top host: {host} ({count})")
    text_lines.append(f"To inspect specific events, call get_stored_response(ref_id=\"{ref_id}\").")

    layout = build_ngsiem_query_layout(events=events, query=query, summary=summary)

    return ToolResult(
        content=[TextContent(type="text", text="\n".join(text_lines))],
        structured_content=layout,
    )
```

- [ ] **Step 4: Run, expect pass**

Run: `pytest tests/modules/ngsiem_render/test_module.py -v`
Expected: all 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/ngsiem_render/_module.py tests/modules/ngsiem_render/test_module.py
git commit -m "feat(ngsiem-render): implement ngsiem_query_render tool with ref_id agent payload"
```

---

## Task 10: Implement `ngsiem_query_drilldown`

**Why:** Drilldown echoes the row dict back as text + structured content (spec D4 — inline-row carrier). Behavior matches the pilot's existing implementation.

**Files:**
- Modify: `src/crowdstrike_mcp/modules/ngsiem_render/_module.py`
- Modify: `tests/modules/ngsiem_render/test_module.py`

- [ ] **Step 1: Write failing test**

Append to `tests/modules/ngsiem_render/test_module.py`:

```python
def test_drilldown_returns_row_as_text_and_structured_content():
    from crowdstrike_mcp.modules.ngsiem_render import NGSIEMRenderModule

    mock_client = MagicMock()
    module = NGSIEMRenderModule(mock_client)
    row = {"ComputerName": "H-01", "event_simpleName": "ProcessRollup2"}
    result = module.ngsiem_query_drilldown(row)

    assert result.structured_content == row
    text = "\n".join(b.text for b in result.content if hasattr(b, "text"))
    assert "H-01" in text
    assert "ProcessRollup2" in text


def test_drilldown_with_non_dict_returns_typed_error():
    from crowdstrike_mcp.modules.ngsiem_render import NGSIEMRenderModule

    mock_client = MagicMock()
    module = NGSIEMRenderModule(mock_client)
    result = module.ngsiem_query_drilldown("not a dict")
    text = "\n".join(b.text for b in result.content if hasattr(b, "text"))
    assert "expected a row dict" in text
    assert "str" in text
```

- [ ] **Step 2: Run, expect failure**

Run: `pytest tests/modules/ngsiem_render/test_module.py::test_drilldown_returns_row_as_text_and_structured_content -v`
Expected: FAIL with `NotImplementedError: Implemented in Task 10`.

- [ ] **Step 3: Implement**

In `src/crowdstrike_mcp/modules/ngsiem_render/_module.py`, replace the `ngsiem_query_drilldown` placeholder with:

```python
def ngsiem_query_drilldown(self, row: dict):
    """Echo a clicked DataTable row back as text + structured content.

    The DataTable's onRowClick action ships the clicked row's full dict here
    via $event interpolation. We just return it — no second NGSIEM round-trip
    needed because the row already carries every field (after #/@ key
    sanitization) from the original event.
    """
    import json

    from fastmcp.tools import ToolResult
    from mcp.types import TextContent

    if not isinstance(row, dict):
        return ToolResult(
            content=[TextContent(
                type="text",
                text=f"ngsiem_query_drilldown expected a row dict, got {type(row).__name__}",
            )],
        )
    return ToolResult(
        content=[TextContent(type="text", text=json.dumps(row, indent=2, default=str))],
        structured_content=row,
    )
```

- [ ] **Step 4: Run, expect pass**

Run: `pytest tests/modules/ngsiem_render/test_module.py -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/ngsiem_render/_module.py tests/modules/ngsiem_render/test_module.py
git commit -m "feat(ngsiem-render): implement ngsiem_query_drilldown inline-row echo"
```

---

## Task 11: Swap server.py to FastMCPApp

**Why:** Spec D5 — adopting FastMCPApp makes `@app.ui()` available and standardizes the path for future UI tools. Gated on Task 1's spike.

**Files:**
- Modify: `src/crowdstrike_mcp/server.py:36` (import) and `:79` (instantiation)

**Precondition:** Task 1 spike PASSED. If it failed, **STOP** and revisit the spec.

- [ ] **Step 1: Capture baseline tool list**

Run: `pytest tests/test_smoke_tools_list.py -v 2>&1 | tee /tmp/smoke_baseline.txt`
Expected: PASS. Save the output to compare against post-swap.

- [ ] **Step 2: Update import**

In `src/crowdstrike_mcp/server.py`, find:

```python
from mcp.server.fastmcp import FastMCP
```

Change to:

```python
from fastmcp.apps import FastMCPApp
```

- [ ] **Step 3: Update instantiation**

In `src/crowdstrike_mcp/server.py:79`, find:

```python
self.server = FastMCP("crowdstrike-falcon")
```

Change to:

```python
self.server = FastMCPApp("crowdstrike-falcon")
```

- [ ] **Step 4: Re-run smoke test**

Run: `pytest tests/test_smoke_tools_list.py -v`
Expected: PASS — same tools list as baseline. If the test fails on `add_resource` or `resource(uri)`, fall back to spec R1 plan B (this means the spike was incomplete; document and re-spec).

- [ ] **Step 5: Run full suite**

Run: `pytest -x --timeout=30`
Expected: PASS. Any failure related to FastMCP type hints in modules is a real bug — fix in this task; type hints in `BaseModule.register_tools(server: FastMCP)` are not load-bearing (Python doesn't enforce), but if `isinstance(server, FastMCP)` checks exist anywhere they need to update to accept FastMCPApp too.

- [ ] **Step 6: Commit**

```bash
git add src/crowdstrike_mcp/server.py
git commit -m "feat(server): swap FastMCP to FastMCPApp for Prefab UI tool support"
```

---

## Task 12: Verify NGSIEMRenderModule loads via auto-discovery in real server

**Why:** Confirm end-to-end that the integrated server registers the render tools alongside everything else — not just in isolated unit tests.

**Files:** none modified; this is verification.

- [ ] **Step 1: Add a smoke test for the render tool's presence**

Append to `tests/test_smoke_tools_list.py` (or wherever the existing tools-list test lives — verify with `grep` first):

```python
def test_smoke_ngsiem_query_render_tool_registered_when_prefab_available():
    """Spec D5/D6 — when prefab_ui is installed, NGSIEMRenderModule is auto-
    discovered and its tools register on the main server."""
    from crowdstrike_mcp.modules.ngsiem_render import RENDER_AVAILABLE
    if not RENDER_AVAILABLE:
        import pytest
        pytest.skip("prefab_ui not installed in this environment")

    # Re-use the same registration path the test file already exercises.
    # If the existing test instantiates a FalconMCPServer or similar, follow
    # that pattern; if it uses get_available_modules directly, also fine.
    from unittest.mock import MagicMock
    from crowdstrike_mcp.registry import get_available_modules

    classes = get_available_modules(MagicMock())
    names = {m.__class__.__name__ for m in classes}
    assert "NGSIEMRenderModule" in names
```

If `tests/test_smoke_tools_list.py` already has a structure that this test wouldn't fit cleanly, add it to `tests/modules/ngsiem_render/test_module.py` instead.

- [ ] **Step 2: Run**

Run: `pytest tests/test_smoke_tools_list.py::test_smoke_ngsiem_query_render_tool_registered_when_prefab_available -v`
Expected: PASS.

- [ ] **Step 3: Run the full smoke suite**

Run: `pytest tests/test_smoke_tools_list.py -v`
Expected: PASS, all tools (including the two new render tools) listed.

- [ ] **Step 4: Commit**

```bash
git add tests/test_smoke_tools_list.py
git commit -m "test(ngsiem-render): smoke test confirms render module auto-discovers under FastMCPApp"
```

---

## Task 13: Add `CROWDSTRIKE_RENDER_MOCK` env flag

**Why:** Spec R2 — restore the pilot's "iterate without creds" affordance. When the env var is truthy, the render tool returns mock events without going through `execute_query`. Off by default; only useful for dev iteration.

**Files:**
- Modify: `src/crowdstrike_mcp/modules/ngsiem_render/_module.py`
- Modify: `tests/modules/ngsiem_render/test_module.py`

- [ ] **Step 1: Write failing test**

Append to `tests/modules/ngsiem_render/test_module.py`:

```python
@pytest.mark.anyio
async def test_render_mock_env_flag_short_circuits_execute_query(monkeypatch):
    """CROWDSTRIKE_RENDER_MOCK=1 returns mock events without calling execute_query."""
    from crowdstrike_mcp.modules.ngsiem_render import NGSIEMRenderModule

    mock_client = MagicMock()
    module = NGSIEMRenderModule(mock_client)

    called = {"flag": False}
    def boom(*args, **kwargs):
        called["flag"] = True
        raise AssertionError("execute_query should not be called when CROWDSTRIKE_RENDER_MOCK=1")
    monkeypatch.setattr(module._ngsiem, "execute_query", boom)
    monkeypatch.setenv("CROWDSTRIKE_RENDER_MOCK", "1")

    result = await module.ngsiem_query_render(query="anything")
    assert called["flag"] is False
    text = "\n".join(b.text for b in result.content if hasattr(b, "text"))
    assert "Events:" in text or "events" in text
```

- [ ] **Step 2: Run, expect failure**

Run: `pytest tests/modules/ngsiem_render/test_module.py::test_render_mock_env_flag_short_circuits_execute_query -v`
Expected: FAIL — `execute_query should not be called` assertion (because `boom` raises).

- [ ] **Step 3: Implement**

In `src/crowdstrike_mcp/modules/ngsiem_render/_module.py`, in `ngsiem_query_render`, before the `execute_query` call, add:

```python
import os
if os.environ.get("CROWDSTRIKE_RENDER_MOCK", "").strip().lower() in {"1", "true", "yes", "on"}:
    from crowdstrike_mcp.modules.ngsiem_render.mock_data import generate_process_events
    events_mock = generate_process_events(count=20, seed=1)
    result = {
        "success": True,
        "events": events_mock,
        "events_processed": len(events_mock),
        "events_matched": len(events_mock),
        "events_returned": len(events_mock),
        "query": query,
        "time_range": start_time,
    }
else:
    result = self._ngsiem.execute_query(query, start_time=start_time, max_results=max_results)
```

(Replace the existing direct `execute_query` call.)

- [ ] **Step 4: Run, expect pass**

Run: `pytest tests/modules/ngsiem_render/test_module.py -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/ngsiem_render/_module.py tests/modules/ngsiem_render/test_module.py
git commit -m "feat(ngsiem-render): CROWDSTRIKE_RENDER_MOCK env flag for credless dev iteration"
```

---

## Task 14: Migrate `test_summary.py`

**Why:** The pilot's summary tests are large and exhaustive. Move them under the new test path; rewrite imports.

**Files:**
- Create: `tests/modules/ngsiem_render/test_summary.py`
- Read for migration source: `tests/prefab_pilot/test_summary.py`

- [ ] **Step 1: Copy the test file**

```bash
cp tests/prefab_pilot/test_summary.py tests/modules/ngsiem_render/test_summary.py
```

- [ ] **Step 2: Rewrite imports**

In `tests/modules/ngsiem_render/test_summary.py`, replace every:

- `from crowdstrike_mcp.prefab_pilot.summary` → `from crowdstrike_mcp.modules.ngsiem_render.summary`
- `from crowdstrike_mcp.prefab_pilot.mock_data` → `from crowdstrike_mcp.modules.ngsiem_render.mock_data`
- `from crowdstrike_mcp.prefab_pilot.fallback` → `from crowdstrike_mcp.modules.ngsiem_render.fallback`

- [ ] **Step 3: Run tests**

Run: `pytest tests/modules/ngsiem_render/test_summary.py -v`
Expected: PASS — same tests, same assertions, just different import path.

- [ ] **Step 4: Commit**

```bash
git add tests/modules/ngsiem_render/test_summary.py
git commit -m "test(ngsiem-render): migrate test_summary.py from prefab_pilot"
```

---

## Task 15: Migrate `test_layout.py`

**Files:**
- Create: `tests/modules/ngsiem_render/test_layout.py`
- Read for migration source: `tests/prefab_pilot/test_layout.py`

- [ ] **Step 1: Copy**

```bash
cp tests/prefab_pilot/test_layout.py tests/modules/ngsiem_render/test_layout.py
```

- [ ] **Step 2: Rewrite imports** (same substitutions as Task 14 Step 2)

- [ ] **Step 3: Update the drilldown app-name fixture**

Find the test `test_layout_data_table_wires_row_click_to_drilldown_tool`. The line:

```python
expected_name = hashed_backend_name("crowdstrike-prefab-pilot", "ngsiem_query_drilldown")
```

Change to:

```python
expected_name = hashed_backend_name("crowdstrike-falcon", "ngsiem_query_drilldown")
```

This matches the new `_APP_NAME` constant from Task 7.

- [ ] **Step 4: Run tests**

Run: `pytest tests/modules/ngsiem_render/test_layout.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/modules/ngsiem_render/test_layout.py
git commit -m "test(ngsiem-render): migrate test_layout.py with crowdstrike-falcon app name"
```

---

## Task 16: Verify everything passes together

**Files:** none modified.

- [ ] **Step 1: Full test suite**

Run: `pytest -x --timeout=60`
Expected: all tests PASS, no warnings about unhandled deprecations from the FastMCPApp swap.

- [ ] **Step 2: Manual server boot smoke test**

Run: `python -m crowdstrike_mcp.server --help`
Expected: argparse help output, no traceback.

- [ ] **Step 3: Module list check**

Run: `python -c "from crowdstrike_mcp.registry import get_module_names; print(sorted(get_module_names()))"`
Expected: includes `'ngsiem_render'` in the sorted list.

- [ ] **Step 4: No commit** (verification only)

If anything fails, return to the responsible task; do not patch in this task.

---

## Task 17: Delete the pilot package

**Why:** Spec — the pilot was scaffolding. With the integration complete, leaving `prefab_pilot/` around invites drift and confusion.

**Files:**
- Delete: `src/crowdstrike_mcp/prefab_pilot/` (entire directory)
- Delete: `tests/prefab_pilot/` (entire directory)
- Delete: `scripts/spike_fastmcpapp.py`

**Precondition:** Task 16 PASSED — all tests green with the integrated tool. Verify before proceeding.

- [ ] **Step 1: Confirm no remaining imports of `crowdstrike_mcp.prefab_pilot`**

Run: `grep -rn "crowdstrike_mcp.prefab_pilot" src/ tests/`
Expected: no matches. If any appear, they are bugs from earlier tasks — fix before deleting.

- [ ] **Step 2: Delete the source package**

```bash
git rm -r src/crowdstrike_mcp/prefab_pilot/
```

- [ ] **Step 3: Delete the test package**

```bash
git rm -r tests/prefab_pilot/
```

- [ ] **Step 4: Delete the spike script**

```bash
git rm scripts/spike_fastmcpapp.py
```

- [ ] **Step 5: Re-run full suite to confirm nothing depended on the deleted code**

Run: `pytest -x --timeout=60`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git commit -m "chore(ngsiem-render): remove prefab_pilot scaffolding now that integration is complete"
```

---

## Task 18: Update pyproject extras (if applicable)

**Why:** If the pilot was wired up as a `prefab-pilot` install extra, that extra's name now misleads. Rename or repoint.

**Files:**
- Modify: `pyproject.toml` (only if it has a `prefab-pilot` extra)

- [ ] **Step 1: Inspect**

Run: `grep -n "prefab" pyproject.toml`
Expected: shows the extra definition if one exists.

- [ ] **Step 2: Decide based on what you find**

- *Extra name is `prefab-pilot`:* rename to `prefab-render` (or whatever fits the project's extras conventions). Update the extra's package contents — drop any references to `prefab_pilot/` paths.
- *Extra name is `prefab-ui` or similar generic:* leave the name; just verify the dependencies still match (`prefab_ui`, `fastmcp`, etc.).
- *No extra exists:* skip this task.

- [ ] **Step 3: Verify pip install still works**

Run: `pip install -e '.[prefab-render]'` (or whatever the renamed extra is)
Expected: clean install.

- [ ] **Step 4: Commit if changes were made**

```bash
git add pyproject.toml
git commit -m "chore: rename prefab-pilot extra to prefab-render to match integrated module"
```

---

## Task 19: Update README references

**Why:** If `README.md` or the pilot's own README documents the standalone `python -m crowdstrike_mcp.prefab_pilot.server` entry point, those instructions are now broken. Replace with the integrated path.

**Files:**
- Modify: `README.md` (top-level)
- Modify: any `README.md` inside `src/crowdstrike_mcp/modules/` if one exists

- [ ] **Step 1: Find references**

Run: `grep -rn "prefab_pilot\|prefab-pilot" README.md docs/ 2>&1 | head -20`
Expected: shows the references that need updating.

- [ ] **Step 2: Update or delete**

- Replace runnable examples that pointed at the standalone pilot server with examples using the main server: `python -m crowdstrike_mcp.server` (mock-mode dev: `CROWDSTRIKE_RENDER_MOCK=1 python -m crowdstrike_mcp.server`).
- Replace tool-name references (`ngsiem_query_demo` → `ngsiem_query_render`).
- Drop standalone-pilot installation instructions.

- [ ] **Step 3: Commit**

```bash
git add README.md docs/
git commit -m "docs: update prefab-render references to integrated server path"
```

---

## Self-Review

Spec coverage:

- D1 (agent-driven call site): Tool description in Task 8 directly addresses model-selection cues. ✓
- D2 (summary + ref_id): Task 9's text fallback assembly + ResponseStore.store. ✓
- D3 (separate tool, shared engine): Task 8 (separate tool registration), Task 9 (calls execute_query via internal NGSIEMModule). ✓
- D4 (inline-row drilldown): Task 10 echoes row dict, no ResponseStore lookup. ✓
- D5 (FastMCPApp adoption): Task 11. Gated on Task 1 spike. ✓
- D6 (sibling render module): Tasks 3, 8 (package + auto-discovered class). ✓
- R1 (FastMCPApp drop-in risk): Task 1 spike with clear pass/fail/stop branches. ✓
- R2 (lost standalone harness): Task 13 CROWDSTRIKE_RENDER_MOCK flag. ✓
- R3 (drilldown hash change): Task 7 + Task 15 fixture update. ✓
- R4 (row-click bug): Out of scope per spec; not addressed (correctly). ✓
- R5 (ref_id capture): Solved via direct `ResponseStore.store(...)` call in Task 9, simpler than the `format_text_response` API change the spec speculated about. ✓

Placeholder scan: every code step shows actual code, every command shows the exact invocation, no "TODO/TBD/etc."

Type consistency: `NGSIEMRenderModule.__init__(self, client)` matches auto-discovery contract everywhere. `_ngsiem` attribute used consistently in Tasks 8, 9, 10, 13. `_DRILLDOWN_BACKEND_NAME` and `_APP_NAME` consistent across Tasks 7 and 15. ResponseStore API matches what `response_store.py` actually exposes (`store(data, tool_name, metadata) -> str`). Test imports match the new package path everywhere.

---

**Plan complete and saved to `docs/superpowers/plans/2026-04-26-prefab-pilot-integration.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
