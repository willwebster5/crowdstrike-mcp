# Response Store Usability Round 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add full-record paging (`fields="*"`), schema hints in truncation notices, eviction tombstones with regeneration guidance, and actionable search-miss feedback to the response store.

**Architecture:** All changes live in the existing response-store stack: shared helpers (schema hint, fields-line formatting, metadata context, tombstones) go in root-level `src/crowdstrike_mcp/response_store.py`; the `get_stored_response` tool surface changes go in `src/crowdstrike_mcp/modules/response_store.py`; `src/crowdstrike_mcp/utils.py` only gains one argument at its `build_truncation_notice` call site. Dependency direction stays utils → response_store, modules → utils.

**Tech Stack:** Python 3.11+, pytest, ruff. Spec: `docs/superpowers/specs/2026-07-23-response-store-usability-round-2-design.md`.

**Conventions:** Run tests from the repo root (`/home/wwebster/projects/crowdstrike-mcp-work`). The venv is already `pip install -e .` (if imports resolve to site-packages instead of `src/`, re-run `pip install -e .`). The `mock_client` fixture and ResponseStore reset live in `tests/conftest.py`. `ResponseStore` state defaults to the `"local"` session partition in tests.

---

### Task 1: Shared schema helpers at root level

Move the schema-hint logic (currently private methods on `ResponseStoreModule`) into root-level `response_store.py`, add the capped fields-line formatter, and add a shared `metadata_context` helper. The module delegates to them.

**Files:**
- Modify: `src/crowdstrike_mcp/response_store.py` (add functions after `select_records`)
- Modify: `src/crowdstrike_mcp/modules/response_store.py` (delegate `_top_level_keys`/`_schema_hint`)
- Test: `tests/test_schema_helpers.py` (new)

- [ ] **Step 1: Write failing tests**

```python
"""Tests for shared schema helpers in response_store.py."""

from crowdstrike_mcp.response_store import (
    format_fields_line,
    metadata_context,
    schema_hint,
    top_level_keys,
)


class TestTopLevelKeys:
    def test_union_preserving_first_seen_order(self):
        records = [{"b": 1, "a": 2}, {"a": 3, "c": 4}, "not-a-dict"]
        assert top_level_keys(records) == ["b", "a", "c"]

    def test_empty(self):
        assert top_level_keys([]) == []


class TestSchemaHint:
    def test_nested_dicts_expand_one_level(self):
        records = [{"id": 1, "event": {"ip": "1.2.3.4", "user": "x"}}]
        assert schema_hint(records) == ["id", "event.ip", "event.user"]

    def test_flat_records(self):
        assert schema_hint([{"a": 1, "b": 2}]) == ["a", "b"]


class TestFormatFieldsLine:
    def test_under_caps_joins_all(self):
        assert format_fields_line(["a", "b"]) == "a, b"

    def test_entry_cap_appends_more_suffix(self):
        entries = [f"field_{i}" for i in range(50)]
        line = format_fields_line(entries, max_entries=40)
        assert "field_39" in line
        assert "field_40" not in line
        assert "(+10 more)" in line

    def test_char_cap_applies_before_entry_cap(self):
        entries = [f"very_long_field_name_number_{i:04d}" for i in range(40)]
        line = format_fields_line(entries, max_chars=100)
        assert len(line) <= 100 + len(" (+XX more)") + 4
        assert "more)" in line

    def test_empty_entries(self):
        assert format_fields_line([]) == ""


class TestMetadataContext:
    def test_picks_first_context_key(self):
        assert metadata_context({"query": "#type=x | tail(5)"}) == "query: #type=x | tail(5)"

    def test_detection_id_beats_query(self):
        md = {"query": "q", "detection_id": "abc:123"}
        assert metadata_context(md) == "detection_id: abc:123"

    def test_empty_metadata(self):
        assert metadata_context({}) == ""
        assert metadata_context(None) == ""
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_schema_helpers.py -v`
Expected: FAIL with `ImportError: cannot import name 'format_fields_line'`

- [ ] **Step 3: Implement in `src/crowdstrike_mcp/response_store.py`**

Insert after the `select_records` function (keep `_CONTEXT_KEYS` where it is; `metadata_context` replaces the inline loop in `build_truncation_notice` — see Step 4):

```python
def top_level_keys(records: list) -> list[str]:
    """Union of top-level keys across all dict records, preserving first-seen order."""
    seen: dict[str, None] = {}
    for r in records:
        if isinstance(r, dict):
            for k in r.keys():
                seen.setdefault(k, None)
    return list(seen.keys())


def schema_hint(records: list) -> list[str]:
    """Available field paths: top-level keys, with dict values expanded one level.

    For each top-level key seen across records, list ``parent.child`` entries
    when the value is a dict in any record, else the bare key. Helps callers
    discover real field paths without fetching a full record first.
    """
    keys = top_level_keys(records)
    if not keys:
        return []
    nested: dict[str, dict[str, None]] = {k: {} for k in keys}
    for r in records:
        if not isinstance(r, dict):
            continue
        for k, v in r.items():
            if isinstance(v, dict):
                for sk in v.keys():
                    nested[k].setdefault(sk, None)
    entries: list[str] = []
    for k in keys:
        subs = list(nested.get(k, {}).keys())
        if subs:
            entries.extend(f"{k}.{sk}" for sk in subs)
        else:
            entries.append(k)
    return entries


def format_fields_line(entries: list[str], max_entries: int = 40, max_chars: int = 600) -> str:
    """Join field entries into a display line capped by count and length.

    Whichever cap is hit first wins; omitted entries are summarized as
    ``(+N more)`` so the caller knows the list is truncated.
    """
    if not entries:
        return ""
    shown: list[str] = []
    length = 0
    for e in entries[:max_entries]:
        added = len(e) + (2 if shown else 0)  # ", " separator
        if shown and length + added > max_chars:
            break
        shown.append(e)
        length += added
    line = ", ".join(shown)
    omitted = len(entries) - len(shown)
    if omitted > 0:
        line += f" (+{omitted} more)"
    return line


def metadata_context(metadata: dict | None) -> str:
    """First useful ``key: value`` context pair from stored metadata, or ''."""
    for key in _CONTEXT_KEYS:
        val = (metadata or {}).get(key)
        if val:
            return f"{key}: {val}"
    return ""
```

Note: `metadata_context` references `_CONTEXT_KEYS`, which is currently defined *below* `ResponseStore` — move the `_CONTEXT_KEYS` definition up next to these helpers (above them), so it is defined before use at import time.

- [ ] **Step 4: Use `metadata_context` inside `build_truncation_notice`**

In `build_truncation_notice`, replace:

```python
    context_line = ""
    for key in _CONTEXT_KEYS:
        val = metadata.get(key)
        if val:
            context_line = f"\nTool: {tool_name} | {key}: {val}"
            break
```

with:

```python
    ctx = metadata_context(metadata)
    context_line = f"\nTool: {tool_name} | {ctx}" if ctx else ""
```

- [ ] **Step 5: Delegate in `src/crowdstrike_mcp/modules/response_store.py`**

Extend the existing import from `crowdstrike_mcp.response_store`:

```python
from crowdstrike_mcp.response_store import (
    ResponseStore,
    format_fields_line,
    schema_hint,
    select_records,
    top_level_keys,
)
```

Replace the bodies of the two static/class helpers with delegation (all call sites — `_format_metadata`, the all-null warning — keep working unchanged):

```python
    @staticmethod
    def _top_level_keys(records: list[dict]) -> list[str]:
        """Union of top-level keys across all dict records (shared helper)."""
        return top_level_keys(records)

    @classmethod
    def _schema_hint(cls, records: list[dict]) -> list[str]:
        """Available field paths in stored records (shared helper)."""
        return schema_hint(records)
```

Delete the now-unused private implementations' bodies only — keep the method names and docstring summaries as above.

- [ ] **Step 6: Run tests**

Run: `python -m pytest tests/test_schema_helpers.py tests/test_get_stored_response.py tests/test_get_stored_response_silent_nulls.py -v`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add src/crowdstrike_mcp/response_store.py src/crowdstrike_mcp/modules/response_store.py tests/test_schema_helpers.py
git commit -m "refactor(response-store): shared schema/context helpers at root level"
```

---

### Task 2: `fields="*"` wildcard → full-record paging

**Files:**
- Modify: `src/crowdstrike_mcp/modules/response_store.py`
- Test: `tests/test_wildcard_fields.py` (new)

- [ ] **Step 1: Write failing tests**

```python
"""Tests for fields="*" wildcard — full-record paging through the fields path."""

import asyncio
import json

import pytest

from crowdstrike_mcp.modules.response_store import ResponseStoreModule
from crowdstrike_mcp.response_store import ResponseStore


@pytest.fixture
def module(mock_client):
    return ResponseStoreModule(mock_client)


def _store(records):
    return ResponseStore.store({"events": records}, tool_name="ngsiem_query")


class TestWildcardFields:
    def test_wildcard_returns_full_records(self, module):
        ref = _store([{"a": 1, "b": {"c": 2}}, {"a": 3, "b": {"c": 4}}])
        result = asyncio.run(module.get_stored_response(ref_id=ref, fields="*"))
        data = json.loads(result)
        assert data == [{"a": 1, "b": {"c": 2}}, {"a": 3, "b": {"c": 4}}]

    def test_wildcard_mixed_with_fields_is_wildcard(self, module):
        ref = _store([{"a": 1, "b": 2}])
        result = asyncio.run(module.get_stored_response(ref_id=ref, fields="*,a"))
        assert json.loads(result) == [{"a": 1, "b": 2}]

    def test_wildcard_pages_with_offset_and_max_results(self, module):
        ref = _store([{"i": n} for n in range(10)])
        page1 = asyncio.run(module.get_stored_response(ref_id=ref, fields="*", max_results=4))
        assert "[page: records 0–3 of 10" in page1
        assert "next offset=4" in page1
        page2 = asyncio.run(
            module.get_stored_response(ref_id=ref, fields="*", max_results=4, offset=4)
        )
        assert "[page: records 4–7 of 10" in page2

    def test_wildcard_respects_byte_budget(self, module):
        big = "x" * 6000
        ref = _store([{"i": n, "blob": big} for n in range(6)])
        result = asyncio.run(module.get_stored_response(ref_id=ref, fields="*", max_results=6))
        assert "[page:" in result
        body = result.split("\n", 1)[1]
        assert len(body) <= ResponseStoreModule._PAGE_BYTE_BUDGET + 100

    def test_wildcard_no_all_null_warning_for_none_valued_records(self, module):
        ref = _store([{"a": None}, {"a": None}])
        result = asyncio.run(module.get_stored_response(ref_id=ref, fields="*"))
        assert "Warning" not in result
        assert json.loads(result) == [{"a": None}, {"a": None}]

    def test_wildcard_with_search_returns_full_matches(self, module):
        ref = _store([{"name": "alpha", "x": 1}, {"name": "beta", "x": 2}])
        result = asyncio.run(
            module.get_stored_response(ref_id=ref, search="beta", fields="*")
        )
        assert json.loads(result) == [{"name": "beta", "x": 2}]

    def test_wildcard_with_record_index_returns_single_record(self, module):
        ref = _store([{"a": 1}, {"a": 2}])
        result = asyncio.run(
            module.get_stored_response(ref_id=ref, record_index=1, fields="*")
        )
        assert json.loads(result) == {"a": 2}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_wildcard_fields.py -v`
Expected: FAIL — wildcard projections currently come back as `{"*": null}` dicts.

- [ ] **Step 3: Implement wildcard in `_project_fields` and skip the all-null check**

In `src/crowdstrike_mcp/modules/response_store.py`, add a helper next to `_project_fields` and make `_project_fields` wildcard-aware:

```python
    @staticmethod
    def _is_wildcard(fields_str: str) -> bool:
        """True if the fields spec requests full records (contains a bare "*")."""
        return "*" in [f.strip() for f in fields_str.split(",")]

    @staticmethod
    def _project_fields(record: dict, fields_str: str) -> dict:
        """Extract dot-path fields from a record. A "*" entry returns it whole."""
        field_list = [f.strip() for f in fields_str.split(",") if f.strip()]
        if "*" in field_list:
            return record
        result = {}
        for f in field_list:
            result[f] = _get_nested(record, f)
        return result
```

In the `fields`-only branch of `get_stored_response`, skip the all-null warning for wildcards — change:

```python
        if fields:
            projected_all = [self._project_fields(r, fields) for r in flat]
            window = projected_all[offset : offset + max_results]
            if window and self._all_projections_null(window):
```

to:

```python
        if fields:
            projected_all = [self._project_fields(r, fields) for r in flat]
            window = projected_all[offset : offset + max_results]
            if window and not self._is_wildcard(fields) and self._all_projections_null(window):
```

(The `record_index` and `search` branches already route through `_project_fields`, so they inherit wildcard behavior with no further changes.)

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_wildcard_fields.py -v`
Expected: ALL PASS

- [ ] **Step 5: Advertise the wildcard in the tool description**

In `register_tools`, in the `get_stored_response` description, replace the sentence beginning `"Paging: large fields/search results"` with:

```python
                "Full records: pass `fields=\"*\"` to page through complete "
                "records (combine with `offset`/`max_results`) instead of "
                "fetching them one `record_index` at a time.\n\n"
                "Paging: large fields/search results are returned one page at a "
                "time within a safe size budget. Each page prints a notice like "
                "`[page: records 0-41 of 200 ...; next offset=42]`; pass that "
                "`offset` to fetch the next page. Nothing is silently dropped."
```

- [ ] **Step 6: Run the module's full test set**

Run: `python -m pytest tests/test_wildcard_fields.py tests/test_get_stored_response.py tests/test_get_stored_response_array_index.py tests/test_get_stored_response_silent_nulls.py -v`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add src/crowdstrike_mcp/modules/response_store.py tests/test_wildcard_fields.py
git commit -m "feat(response-store): fields=\"*\" pages full records"
```

---

### Task 3: Schema hint + wildcard example in the truncation notice

**Files:**
- Modify: `src/crowdstrike_mcp/response_store.py` (`build_truncation_notice`)
- Modify: `src/crowdstrike_mcp/utils.py` (call site, one argument)
- Test: `tests/test_truncation_notice_schema.py` (new)

- [ ] **Step 1: Write failing tests**

```python
"""Truncation notice carries a capped schema hint and a wildcard example."""

from crowdstrike_mcp.response_store import build_truncation_notice
from crowdstrike_mcp.utils import LARGE_RESPONSE_THRESHOLD, format_text_response


def _notice(data):
    return build_truncation_notice(
        summary="summary",
        text_len=50_000,
        ref_id="resp_001",
        record_count=2,
        tool_name="ngsiem_query",
        metadata={"query": "#type=x"},
        data=data,
    )


class TestNoticeSchemaHint:
    def test_fields_line_lists_paths(self):
        notice = _notice({"events": [{"id": 1, "event": {"ip": "1.1.1.1"}}]})
        assert "Fields: id, event.ip" in notice

    def test_fields_line_capped_with_more_suffix(self):
        record = {f"field_{i:03d}": i for i in range(60)}
        notice = _notice({"events": [record]})
        assert "Fields: " in notice
        assert "(+20 more)" in notice

    def test_no_fields_line_without_records(self):
        assert "Fields:" not in _notice({"events": []})
        assert "Fields:" not in _notice(None)

    def test_wildcard_example_present(self):
        notice = _notice({"events": [{"id": 1}]})
        assert 'fields="*"' in notice


class TestFormatTextResponsePassesData:
    def test_truncated_response_notice_includes_schema(self):
        data = {"events": [{"id": 1, "name": "x"}]}
        text = "line\n" * (LARGE_RESPONSE_THRESHOLD // 4)
        result = format_text_response(
            text, tool_name="ngsiem_query", raw=True, structured_data=data
        )
        assert "RESPONSE TRUNCATED" in result
        assert "Fields: id, name" in result
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_truncation_notice_schema.py -v`
Expected: FAIL with `TypeError: build_truncation_notice() got an unexpected keyword argument 'data'`

- [ ] **Step 3: Implement in `build_truncation_notice`**

Add the keyword-only parameter `data: dict | None = None` to the signature, and build the schema line. The full updated function body (in `src/crowdstrike_mcp/response_store.py`):

```python
def build_truncation_notice(
    *,
    summary: str,
    text_len: int,
    ref_id: str,
    record_count: int,
    tool_name: str,
    metadata: dict | None,
    data: dict | None = None,
) -> str:
    """Build the truncation notice for a large, stored response.

    Authoring the get_stored_response usage hints is store-domain knowledge, so
    it lives here rather than in the generic text formatter. The record-key hint
    is driven by a generic ``record_key`` metadata field (``triggering_pid`` is
    accepted as a back-compat alias) — the formatter need not know either name.
    When ``data`` is provided, a capped ``Fields:`` line surfaces available
    field paths so the first extraction call is informed, not guessed.
    """
    metadata = metadata or {}

    ctx = metadata_context(metadata)
    context_line = f"\nTool: {tool_name} | {ctx}" if ctx else ""

    fields_line = ""
    if data is not None:
        entries = schema_hint(select_records(data))
        if entries:
            fields_line = f"\nFields: {format_fields_line(entries)}"

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
        f"Structured data stored as: {ref_id} ({record_count} records){context_line}{fields_line}",
        "",
        "To query this data use the get_stored_response tool:",
        f'  get_stored_response(ref_id="{ref_id}")                                → metadata overview',
        f'  get_stored_response(ref_id="{ref_id}", fields="source.ip,user.name")  → extract fields',
        f'  get_stored_response(ref_id="{ref_id}", fields="*")                    → full records (paged)',
        f'  get_stored_response(ref_id="{ref_id}", search="keyword")              → search records',
        *last_lines,
    ]
    return "\n".join(parts)
```

- [ ] **Step 4: Pass `data=` from `src/crowdstrike_mcp/utils.py`**

In `format_text_response`, extend the `build_truncation_notice` call:

```python
        result = build_truncation_notice(
            summary=summary,
            text_len=len(text),
            ref_id=ref_id,
            record_count=stored.record_count if stored else 0,
            tool_name=tool_name,
            metadata=metadata,
            data=structured_data,
        )
```

- [ ] **Step 5: Run tests**

Run: `python -m pytest tests/test_truncation_notice_schema.py tests/test_format_text_response_footer.py -v`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add src/crowdstrike_mcp/response_store.py src/crowdstrike_mcp/utils.py tests/test_truncation_notice_schema.py
git commit -m "feat(response-store): schema hint and wildcard example in truncation notice"
```

---

### Task 4: Eviction tombstones in `ResponseStore`

**Files:**
- Modify: `src/crowdstrike_mcp/response_store.py`
- Test: `tests/test_tombstones.py` (new)

- [ ] **Step 1: Write failing tests**

```python
"""Eviction tombstones: evicted refs keep tool/metadata so errors can guide regeneration."""

from datetime import timedelta

from crowdstrike_mcp.response_store import (
    ResponseStore,
    make_session_key,
    reset_response_session,
    set_response_session,
)


def _expire(ref_id):
    """Rewind a stored entry past the TTL (test-only internal access)."""
    entry = ResponseStore._sessions["local"][ref_id]
    entry.timestamp -= timedelta(seconds=ResponseStore._ttl_seconds + 1)


class TestTtlTombstone:
    def test_ttl_expiry_leaves_tombstone(self):
        ref = ResponseStore.store({"events": [{"a": 1}]}, "ngsiem_query", {"query": "#type=x"})
        _expire(ref)
        assert ResponseStore.get(ref) is None
        tomb = ResponseStore.get_tombstone(ref)
        assert tomb["reason"] == "ttl"
        assert tomb["tool_name"] == "ngsiem_query"
        assert tomb["metadata"] == {"query": "#type=x"}
        assert tomb["evicted_at"] is not None


class TestLruTombstone:
    def test_lru_displacement_leaves_tombstone(self):
        first = ResponseStore.store({"events": []}, "get_alerts", {"filter": "f"})
        for _ in range(ResponseStore._max_entries):
            ResponseStore.store({"events": []}, "ngsiem_query", {})
        assert ResponseStore.get(first) is None
        tomb = ResponseStore.get_tombstone(first)
        assert tomb["reason"] == "lru"
        assert tomb["tool_name"] == "get_alerts"


class TestTombstoneLifecycle:
    def test_unknown_ref_has_no_tombstone(self):
        assert ResponseStore.get_tombstone("resp_999") is None

    def test_live_ref_has_no_tombstone(self):
        ref = ResponseStore.store({"events": []}, "ngsiem_query", {})
        assert ResponseStore.get_tombstone(ref) is None

    def test_cap_drops_oldest_tombstones(self):
        refs = []
        for _ in range(ResponseStore._tombstone_cap + 10 + ResponseStore._max_entries):
            refs.append(ResponseStore.store({"events": []}, "ngsiem_query", {}))
        evicted = refs[: -ResponseStore._max_entries]
        capped_out = evicted[: -ResponseStore._tombstone_cap]
        kept = evicted[-ResponseStore._tombstone_cap :]
        assert all(ResponseStore.get_tombstone(r) is None for r in capped_out)
        assert all(ResponseStore.get_tombstone(r) is not None for r in kept)

    def test_clear_session_wipes_tombstones(self):
        token = set_response_session("cred123")
        try:
            ref = ResponseStore.store({"events": []}, "ngsiem_query", {})
            _entry = ResponseStore._sessions["cred123"][ref]
            _entry.timestamp -= timedelta(seconds=ResponseStore._ttl_seconds + 1)
            ResponseStore.get(ref)  # trigger TTL tombstone
            assert ResponseStore.get_tombstone(ref) is not None
            ResponseStore.clear_session("cred123")
            assert ResponseStore.get_tombstone(ref) is None
        finally:
            reset_response_session(token)

    def test_clear_credential_sessions_wipes_connection_tombstones(self):
        sk = make_session_key("cred456", "conn-1")
        token = set_response_session(sk)
        try:
            ref = ResponseStore.store({"events": []}, "ngsiem_query", {})
            entry = ResponseStore._sessions[sk][ref]
            entry.timestamp -= timedelta(seconds=ResponseStore._ttl_seconds + 1)
            ResponseStore.get(ref)
            assert ResponseStore.get_tombstone(ref) is not None
            ResponseStore.clear_credential_sessions("cred456")
            assert ResponseStore.get_tombstone(ref) is None
        finally:
            reset_response_session(token)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_tombstones.py -v`
Expected: FAIL with `AttributeError: ... has no attribute 'get_tombstone'`

- [ ] **Step 3: Implement tombstones in `ResponseStore`**

In `src/crowdstrike_mcp/response_store.py`:

Add class attributes next to `_counters`:

```python
    # session_id -> (ref_id -> tombstone dict), ordered oldest-first. A tombstone
    # records what an evicted ref *was* (tool + metadata, no payload) so a miss
    # can tell the caller how to regenerate the data. Wiped with the partition —
    # metadata can embed query strings, which must not outlive the credential.
    _tombstones: "dict[str, OrderedDict[str, dict]]" = {}
    _tombstone_cap: int = 50
```

Add the private recorder and public reader (below `list_refs`):

```python
    @classmethod
    def _add_tombstone(cls, session_id: str, sr: StoredResponse, reason: str) -> None:
        """Record an eviction (caller holds the lock). reason: 'lru' | 'ttl'."""
        stones = cls._tombstones.setdefault(session_id, OrderedDict())
        stones[sr.ref_id] = {
            "tool_name": sr.tool_name,
            "metadata": sr.metadata,
            "evicted_at": datetime.now(timezone.utc),
            "reason": reason,
        }
        while len(stones) > cls._tombstone_cap:
            stones.popitem(last=False)

    @classmethod
    def get_tombstone(cls, ref_id: str) -> dict | None:
        """Tombstone for an evicted ref in the current session, or None."""
        with cls._lock:
            stones = cls._tombstones.get(_session_id.get())
            if not stones:
                return None
            return stones.get(ref_id)
```

Hook the three eviction paths:

In `store()` — whole-session eviction drops that session's tombstones too:

```python
                while len(cls._sessions) >= cls._max_sessions:
                    old_sk, _ = cls._sessions.popitem(last=False)
                    cls._counters.pop(old_sk, None)
                    cls._tombstones.pop(old_sk, None)
```

In `store()` — LRU displacement leaves a tombstone:

```python
            if len(entries) >= cls._max_entries:
                _, evicted = entries.popitem(last=False)  # evict least-recently-used
                cls._add_tombstone(sk, evicted, "lru")
```

In `get()` — TTL expiry leaves a tombstone:

```python
            if cls._is_expired(sr):
                cls._add_tombstone(_session_id.get(), sr, "ttl")
                del entries[ref_id]
                return None
```

In `clear_session()` and `clear_credential_sessions()`, add alongside each existing `cls._counters.pop(...)`:

```python
            cls._tombstones.pop(session_id, None)
```

(and in the credential loop: `cls._tombstones.pop(sk, None)`).

In `_reset()`:

```python
            cls._tombstones.clear()
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_tombstones.py tests/test_response_store_sessions.py -v`
(If `tests/test_response_store_sessions.py` doesn't exist, run the whole suite instead: `python -m pytest tests/ -q`.)
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/response_store.py tests/test_tombstones.py
git commit -m "feat(response-store): eviction tombstones (lru/ttl) scoped to the session partition"
```

---

### Task 5: Tombstone-aware miss errors in `get_stored_response`

**Files:**
- Modify: `src/crowdstrike_mcp/modules/response_store.py`
- Test: `tests/test_tombstone_errors.py` (new)

- [ ] **Step 1: Write failing tests**

```python
"""get_stored_response miss errors use tombstones to guide regeneration."""

import asyncio
from datetime import timedelta

import pytest

from crowdstrike_mcp.modules.response_store import ResponseStoreModule
from crowdstrike_mcp.response_store import ResponseStore


@pytest.fixture
def module(mock_client):
    return ResponseStoreModule(mock_client)


def _expire(ref_id):
    entry = ResponseStore._sessions["local"][ref_id]
    entry.timestamp -= timedelta(seconds=ResponseStore._ttl_seconds + 1)


class TestTombstoneErrors:
    def test_ttl_expired_ref_names_tool_and_context(self, module):
        ref = ResponseStore.store(
            {"events": [{"a": 1}]}, "ngsiem_query", {"query": "#type=x | tail(5)"}
        )
        _expire(ref)
        result = asyncio.run(module.get_stored_response(ref_id=ref))
        assert "expired" in result
        assert "25-min TTL" in result
        assert "ngsiem_query" in result
        assert "#type=x | tail(5)" in result
        assert "re-run" in result

    def test_lru_evicted_ref_says_evicted(self, module):
        first = ResponseStore.store({"events": []}, "get_alerts", {"filter": "sev:high"})
        for _ in range(ResponseStore._max_entries):
            ResponseStore.store({"events": []}, "ngsiem_query", {})
        result = asyncio.run(module.get_stored_response(ref_id=first))
        assert "evicted to make room" in result
        assert "get_alerts" in result
        assert "sev:high" in result

    def test_unknown_ref_keeps_existing_error(self, module):
        ResponseStore.store({"events": []}, "ngsiem_query", {})
        result = asyncio.run(module.get_stored_response(ref_id="resp_999"))
        assert "not found" in result
        assert "Available: resp_001" in result
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_tombstone_errors.py -v`
Expected: FAIL — expired/evicted refs currently return the generic "not found" error.

- [ ] **Step 3: Implement the tombstone error path**

In `src/crowdstrike_mcp/modules/response_store.py`, extend the root-level import with `metadata_context` (added in Task 1):

```python
from crowdstrike_mcp.response_store import (
    ResponseStore,
    format_fields_line,
    metadata_context,
    schema_hint,
    select_records,
    top_level_keys,
)
```

Add a helper below `_stringify_record`:

```python
def _tombstone_error(ref_id: str, tomb: dict) -> str:
    """Actionable miss error for an evicted ref: what it was, how to regenerate."""
    tool = tomb.get("tool_name") or "unknown tool"
    ctx = metadata_context(tomb.get("metadata"))
    ctx_part = f" ({ctx})" if ctx else ""
    if tomb.get("reason") == "ttl":
        ttl_min = ResponseStore._ttl_seconds // 60
        cause = f"expired ({ttl_min}-min TTL)"
    else:
        cause = "was evicted to make room for newer responses"
    return (
        f"Reference '{ref_id}' {cause}. It was {tool}{ctx_part} — "
        "re-run that tool to regenerate the data."
    )
```

In `get_stored_response`, in the `if not stored:` block, consult the tombstone first:

```python
        stored = ResponseStore.get(ref_id)
        if not stored:
            tomb = ResponseStore.get_tombstone(ref_id)
            if tomb:
                return format_text_response(_tombstone_error(ref_id, tomb), raw=True)
            available = ResponseStore.list_refs()
            ...  # existing not-found handling unchanged
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_tombstone_errors.py tests/test_get_stored_response.py -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/response_store.py tests/test_tombstone_errors.py
git commit -m "feat(response-store): tombstone-aware miss errors with regeneration guidance"
```

---

### Task 6: Actionable search-miss feedback

**Files:**
- Modify: `src/crowdstrike_mcp/modules/response_store.py`
- Test: `tests/test_search_miss_feedback.py` (new)

- [ ] **Step 1: Write failing tests**

```python
"""Search misses report scan scope, match semantics, and available fields."""

import asyncio
import json

import pytest

from crowdstrike_mcp.modules.response_store import ResponseStoreModule
from crowdstrike_mcp.response_store import ResponseStore


@pytest.fixture
def module(mock_client):
    return ResponseStoreModule(mock_client)


class TestSearchMissFeedback:
    def test_miss_reports_scope_semantics_and_fields(self, module):
        ref = ResponseStore.store(
            {"events": [{"user": "alice", "ip": "1.1.1.1"}, {"user": "bob", "ip": "2.2.2.2"}]},
            tool_name="ngsiem_query",
        )
        result = asyncio.run(module.get_stored_response(ref_id=ref, search="jetbrain"))
        assert "No records matching 'jetbrain'" in result
        assert "searched 2 records" in result
        assert "case-insensitive substring" in result
        assert "Available fields: user, ip" in result
        assert "Tip:" in result

    def test_match_path_unchanged(self, module):
        ref = ResponseStore.store(
            {"events": [{"user": "alice"}]}, tool_name="ngsiem_query"
        )
        result = asyncio.run(module.get_stored_response(ref_id=ref, search="alice"))
        assert json.loads(result) == [{"user": "alice"}]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_search_miss_feedback.py -v`
Expected: FAIL — miss message is currently the bare `No records matching '...' in resp_NNN.`

- [ ] **Step 3: Implement the miss message**

In `get_stored_response`'s `search` branch, replace:

```python
            if not all_matches:
                return format_text_response(
                    f"No records matching '{search}' in {ref_id}.",
                    raw=True,
                )
```

with:

```python
            if not all_matches:
                lines = [
                    f"No records matching '{search}' in {ref_id} (searched {len(flat)} records).",
                    "Search is a case-insensitive substring match over all record values.",
                ]
                entries = schema_hint(flat)
                if entries:
                    lines.append(f"Available fields: {format_fields_line(entries)}")
                lines.append(
                    "Tip: try a shorter substring, or project candidate fields with fields=..."
                )
                return format_text_response("\n".join(lines), raw=True)
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_search_miss_feedback.py -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add src/crowdstrike_mcp/modules/response_store.py tests/test_search_miss_feedback.py
git commit -m "feat(response-store): actionable search-miss feedback"
```

---

### Task 7: Full-suite verification and lint

**Files:** none new

- [ ] **Step 1: Run the entire test suite**

Run: `python -m pytest tests/ -q`
Expected: ALL PASS, no skips introduced by this work

- [ ] **Step 2: Lint**

Run: `ruff check src/ tests/ && ruff format --check src/ tests/`
Expected: clean (fix any findings, re-run)

- [ ] **Step 3: Commit any lint fixes**

```bash
git add -u && git commit -m "style: lint fixes for response-store usability round 2" || echo "nothing to fix"
```
