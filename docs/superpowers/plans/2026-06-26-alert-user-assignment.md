# Alert User Assignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let `update_alert_status` assign an alert to a user (by user ID / email) and unassign the current user, while making `status` optional.

**Architecture:** Extend the existing `update_alert_status` MCP tool and its internal `_update_alert_status` helper in `src/crowdstrike_mcp/modules/alerts.py`. Assignment maps to additional `action_parameters` entries on the existing `update_alerts_v3` FalconPy call. No new tool, no new API call.

**Tech Stack:** Python, FalconPy SDK (`update_alerts_v3` / `PatchEntitiesAlertsV3`), pytest.

Spec: `docs/superpowers/specs/2026-06-26-alert-user-assignment-design.md`

---

## File Structure

- **Modify** `src/crowdstrike_mcp/modules/alerts.py`
  - `update_alert_status` (tool method, ~line 215): add `assign_to_user_id` and `unassign` params, make `status` optional, extend response formatting.
  - `_update_alert_status` (helper, ~line 405): make status optional, add validation + assign/unassign action params, return new fields.
  - Tool registration `description` (~line 99): mention assignment.
- **Create** `tests/test_alert_assignment.py` — unit tests for the new behavior.

---

## Task 1: Make `status` optional and validate "at least one action"

**Files:**
- Modify: `src/crowdstrike_mcp/modules/alerts.py` (`_update_alert_status` ~405-449, `update_alert_status` ~215-247)
- Test: `tests/test_alert_assignment.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_alert_assignment.py`:

```python
"""User assignment + unassignment for update_alert_status.

Exercises the new assign_to_user_id / unassign parameters and the
optional-status behavior added on top of the existing status/comment/tags
update path.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

NG = "bf7f666a6cb8419ea851663ecef09c24:ngsiem:bf7f666a6cb8419ea851663ecef09c24:aaaa"


@pytest.fixture
def alerts_module(mock_client):
    with patch("crowdstrike_mcp.modules.alerts.Alerts"):
        from crowdstrike_mcp.modules.alerts import AlertsModule

        module = AlertsModule(mock_client)
        mock_alerts = MagicMock()
        module._service = lambda cls: mock_alerts
        module._mock_alerts = mock_alerts
        return module


def _resp(code, body=None):
    return {"status_code": code, "body": body or {}}


def _action_params(mock_alerts):
    """Return the action_parameters list passed to update_alerts_v3."""
    return mock_alerts.update_alerts_v3.call_args.kwargs["action_parameters"]


def test_no_action_provided_is_error_without_api_call(alerts_module):
    m = alerts_module._mock_alerts

    out = asyncio.run(alerts_module.update_alert_status([NG]))

    assert "no action" in out.lower() or "nothing to update" in out.lower()
    m.update_alerts_v3.assert_not_called()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_alert_assignment.py -v`
Expected: FAIL — `update_alert_status` currently requires `status` (TypeError: missing positional arg) or no such guard exists.

- [ ] **Step 3: Make `status` optional in the tool method**

In `update_alert_status` change the signature and the result-handling. Replace:

```python
    async def update_alert_status(
        self,
        composite_ids: Annotated[list[str], "List of composite alert IDs to update"],
        status: Annotated[str, "New alert status ('new', 'in_progress', 'closed', 'reopened')"],
        comment: Annotated[Optional[str], "Comment for audit trail"] = None,
        tags: Annotated[Optional[list[str]], "Tags to add"] = None,
    ) -> str:
        """Update alert status, add comments and tags."""
        cleaned_ids = [extract_detection_id(cid) for cid in composite_ids]
        result = self._update_alert_status(cleaned_ids, status, comment, tags)
```

with:

```python
    async def update_alert_status(
        self,
        composite_ids: Annotated[list[str], "List of composite alert IDs to update"],
        status: Annotated[Optional[str], "New alert status ('new', 'in_progress', 'closed', 'reopened'). Optional — omit to leave status unchanged."] = None,
        comment: Annotated[Optional[str], "Comment for audit trail"] = None,
        tags: Annotated[Optional[list[str]], "Tags to add"] = None,
        assign_to_user_id: Annotated[Optional[str], "User ID / email to assign the alert to, e.g. 'analyst@example.com'"] = None,
        unassign: Annotated[bool, "Clear the current assignee. Mutually exclusive with assign_to_user_id."] = False,
    ) -> str:
        """Update alert status, comments, tags, and assignment."""
        cleaned_ids = [extract_detection_id(cid) for cid in composite_ids]
        result = self._update_alert_status(
            cleaned_ids, status, comment, tags, assign_to_user_id, unassign
        )
```

- [ ] **Step 4: Update the success-output block of the tool method**

Replace the existing `lines = [...]` block:

```python
        lines = [
            f"Successfully updated {result['updated_count']} alert(s)",
            f"New status: {result['new_status']}",
        ]
        if result.get("comment_added"):
            lines.append(f"Comment added: {comment}")
        if result.get("tags_added"):
            lines.append(f"Tags added: {', '.join(result['tags_added'])}")
```

with:

```python
        lines = [f"Successfully updated {result['updated_count']} alert(s)"]
        if result.get("new_status"):
            lines.append(f"New status: {result['new_status']}")
        if result.get("comment_added"):
            lines.append(f"Comment added: {comment}")
        if result.get("tags_added"):
            lines.append(f"Tags added: {', '.join(result['tags_added'])}")
        if result.get("assigned_to"):
            lines.append(f"Assigned to: {result['assigned_to']}")
        if result.get("unassigned"):
            lines.append("Unassigned")
```

Leave the `spurious_500_verified` block that follows unchanged.

- [ ] **Step 5: Update `_update_alert_status` signature and add validation**

Replace the start of `_update_alert_status`:

```python
    def _update_alert_status(self, composite_ids, status, comment=None, tags=None):
        try:
            alerts = self._service(Alerts)
            valid_statuses = ["new", "in_progress", "closed", "reopened"]
            if status.lower() not in valid_statuses:
                return {"success": False, "error": f"Invalid status: {status}. Must be one of: {valid_statuses}"}

            action_params = [{"name": "update_status", "value": status.lower()}]
            if comment:
                action_params.append({"name": "append_comment", "value": comment})
            if tags:
                action_params.extend({"name": "add_tag", "value": tag} for tag in tags)
```

with:

```python
    def _update_alert_status(self, composite_ids, status=None, comment=None, tags=None, assign_to_user_id=None, unassign=False):
        try:
            alerts = self._service(Alerts)

            if assign_to_user_id and unassign:
                return {"success": False, "error": "assign_to_user_id and unassign are mutually exclusive; provide only one."}

            if not any([status, comment, tags, assign_to_user_id, unassign]):
                return {"success": False, "error": "No action provided: supply at least one of status, comment, tags, assign_to_user_id, or unassign."}

            action_params = []
            if status:
                valid_statuses = ["new", "in_progress", "closed", "reopened"]
                if status.lower() not in valid_statuses:
                    return {"success": False, "error": f"Invalid status: {status}. Must be one of: {valid_statuses}"}
                action_params.append({"name": "update_status", "value": status.lower()})
            if comment:
                action_params.append({"name": "append_comment", "value": comment})
            if tags:
                action_params.extend({"name": "add_tag", "value": tag} for tag in tags)
            if assign_to_user_id:
                action_params.append({"name": "assign_to_user_id", "value": assign_to_user_id})
            elif unassign:
                # CrowdStrike API: the value passed to `unassign` is ignored.
                action_params.append({"name": "unassign", "value": ""})
```

- [ ] **Step 6: Update the spurious-500 guard and return dict in `_update_alert_status`**

The existing 500 guard calls `self._verify_status_applied(alerts, composite_ids, status.lower())`. Guard it so it only runs when a status is present. Replace:

```python
                if (
                    response["status_code"] == 500
                    and composite_ids
                    and all(parse_composite_id(c)["product_type"] == "thirdparty" for c in composite_ids)
                    and self._verify_status_applied(alerts, composite_ids, status.lower())
                ):
                    spurious_500_verified = True
```

with:

```python
                if (
                    response["status_code"] == 500
                    and status
                    and composite_ids
                    and all(parse_composite_id(c)["product_type"] == "thirdparty" for c in composite_ids)
                    and self._verify_status_applied(alerts, composite_ids, status.lower())
                ):
                    spurious_500_verified = True
```

Then replace the success return dict:

```python
            return {
                "success": True,
                "updated_count": len(composite_ids),
                "new_status": status.lower(),
                "comment_added": comment is not None,
                "tags_added": tags or [],
                "spurious_500_verified": spurious_500_verified,
            }
```

with:

```python
            return {
                "success": True,
                "updated_count": len(composite_ids),
                "new_status": status.lower() if status else None,
                "comment_added": comment is not None,
                "tags_added": tags or [],
                "assigned_to": assign_to_user_id,
                "unassigned": bool(unassign),
                "spurious_500_verified": spurious_500_verified,
            }
```

- [ ] **Step 7: Run the new test to verify it passes**

Run: `pytest tests/test_alert_assignment.py -v`
Expected: PASS (`test_no_action_provided_is_error_without_api_call`)

- [ ] **Step 8: Run the existing alert update tests to verify no regression**

Run: `pytest tests/test_update_alert_status_thirdparty.py -v`
Expected: PASS (all 4 — status-only path unchanged)

- [ ] **Step 9: Commit**

```bash
git add src/crowdstrike_mcp/modules/alerts.py tests/test_alert_assignment.py
git commit -m "feat(alerts): optional status + no-action guard in update_alert_status"
```

---

## Task 2: Assign and unassign behavior

**Files:**
- Test: `tests/test_alert_assignment.py`
- (implementation already added in Task 1 — these tests lock in the action-parameter wiring)

- [ ] **Step 1: Add the assign/unassign tests**

Append to `tests/test_alert_assignment.py`:

```python
def test_assign_only_emits_assign_action_no_status(alerts_module):
    m = alerts_module._mock_alerts
    m.update_alerts_v3.return_value = _resp(200, {"meta": {"writes": {"resources_affected": 1}}})

    out = asyncio.run(
        alerts_module.update_alert_status([NG], assign_to_user_id="analyst@example.com")
    )

    params = _action_params(m)
    assert {"name": "assign_to_user_id", "value": "analyst@example.com"} in params
    assert all(p["name"] != "update_status" for p in params)
    assert "Assigned to: analyst@example.com" in out
    assert "New status" not in out


def test_unassign_emits_unassign_action_with_ignored_value(alerts_module):
    m = alerts_module._mock_alerts
    m.update_alerts_v3.return_value = _resp(200, {"meta": {"writes": {"resources_affected": 1}}})

    out = asyncio.run(alerts_module.update_alert_status([NG], unassign=True))

    params = _action_params(m)
    assert {"name": "unassign", "value": ""} in params
    assert "Unassigned" in out


def test_status_comment_and_assign_combined(alerts_module):
    m = alerts_module._mock_alerts
    m.update_alerts_v3.return_value = _resp(200, {"meta": {"writes": {"resources_affected": 1}}})

    out = asyncio.run(
        alerts_module.update_alert_status(
            [NG], status="in_progress", comment="triaging", assign_to_user_id="analyst@example.com"
        )
    )

    names = [p["name"] for p in _action_params(m)]
    assert names == ["update_status", "append_comment", "assign_to_user_id"]
    assert "New status: in_progress" in out
    assert "Assigned to: analyst@example.com" in out


def test_assign_and_unassign_together_is_error(alerts_module):
    m = alerts_module._mock_alerts

    out = asyncio.run(
        alerts_module.update_alert_status(
            [NG], assign_to_user_id="analyst@example.com", unassign=True
        )
    )

    assert "mutually exclusive" in out.lower()
    m.update_alerts_v3.assert_not_called()
```

- [ ] **Step 2: Run the tests to verify they pass**

Run: `pytest tests/test_alert_assignment.py -v`
Expected: PASS (all 5 tests — the implementation from Task 1 satisfies them)

- [ ] **Step 3: Commit**

```bash
git add tests/test_alert_assignment.py
git commit -m "test(alerts): cover assign/unassign action wiring"
```

---

## Task 3: Update tool description and docs

**Files:**
- Modify: `src/crowdstrike_mcp/modules/alerts.py` (tool registration `description` ~line 99)
- Modify: `README.md` (only if it enumerates `update_alert_status` capabilities)

- [ ] **Step 1: Update the tool registration description**

In `_add_tool(... name="update_alert_status" ...)` replace:

```python
    description=("Update CrowdStrike alert status after triage/investigation. Supports status changes, comments for audit trail, and tags."),
```

with:

```python
    description=("Update CrowdStrike alert status after triage/investigation. Supports status changes, comments for audit trail, tags, and assigning/unassigning a user (by user ID / email). Status is optional, so the tool can reassign without changing status."),
```

- [ ] **Step 2: Update README if it lists this tool's capabilities**

Run: `grep -n "update_alert_status" README.md`
- If a line describes the tool's capabilities, edit it to mention user assignment.
- If there are no capability descriptions (only a name listing), make no change.

- [ ] **Step 3: Run the full alerts test suite**

Run: `pytest tests/test_alert_assignment.py tests/test_update_alert_status_thirdparty.py tests/test_alerts_endpoint_enrichment.py -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/crowdstrike_mcp/modules/alerts.py README.md
git commit -m "docs(alerts): note user assignment in update_alert_status"
```

---

## Self-Review Notes

- **Spec coverage:** assign by user ID (Task 1/2), unassign (Task 1/2), optional status (Task 1), at-least-one-action validation (Task 1), mutual exclusion (Task 1/2), response reporting (Task 1), preserved spurious-500 status path + accepted assign-only limitation (Task 1, no new verification path), tests (Task 1/2), docs (Task 3). All covered.
- **Type consistency:** result keys `new_status`, `assigned_to`, `unassigned`, `comment_added`, `tags_added`, `spurious_500_verified` are produced in `_update_alert_status` and consumed in `update_alert_status` with matching names. Action names match the FalconPy spec (`assign_to_user_id`, `unassign`, `update_status`, `append_comment`, `add_tag`).
- **Note on staging (dev env gotcha):** stage files explicitly in each commit (done above) — the Windows mount flips CRLF on broad `git add`.
