# Alert user assignment in `update_alert_status` — design

**Date:** 2026-06-26
**Status:** Approved, pending implementation plan

## Problem

The `update_alert_status` MCP tool (`src/crowdstrike_mcp/modules/alerts.py`) lets
an analyst change an alert's status and append comments/tags, but provides no way
to assign an alert to a user or to clear an existing assignment. The underlying
FalconPy call (`update_alerts_v3` / `PatchEntitiesAlertsV3`) already supports
`assign_to_user_id`, `assign_to_uuid`, `assign_to_name`, and `unassign` actions —
the MCP tool simply never emits them.

This feature exposes user assignment (by user ID / email) and unassignment through
the existing tool.

## Scope

In scope:
- Assign an alert to a user identified by user ID / email (`assign_to_user_id`).
- Unassign the currently assigned user (`unassign`).
- Make `status` optional so an analyst can reassign without forcing a status change.

Out of scope (can be added later if requested):
- Assignment by UUID (`assign_to_uuid`) or by display name (`assign_to_name`).
- A dedicated standalone `assign_alert` tool — assignment lives in the existing tool.
- New spurious-500 verification path for assign-only thirdparty updates.

## Tool surface changes

`update_alert_status` gains two optional parameters and relaxes one existing one:

| Parameter            | Type            | Change   | Notes |
|----------------------|-----------------|----------|-------|
| `status`             | `Optional[str]` | now optional (was required) | defaults to `None`; `update_status` action only emitted when provided |
| `assign_to_user_id`  | `Optional[str]` | new      | user ID / email, e.g. `analyst@example.com` |
| `unassign`           | `bool`          | new      | defaults to `False`; clears the current assignee |

`composite_ids`, `comment`, and `tags` are unchanged.

Making `status` optional is backward compatible: existing callers that pass a
status behave identically (the `update_status` action is still emitted first).

## Validation rules (`_update_alert_status`)

1. **At least one action required.** If none of `status`, `comment`, `tags`,
   `assign_to_user_id`, or `unassign` is provided, return a clear error
   (`update_alerts_v3` has no action to perform). Do not call the API.
2. **Assign / unassign mutually exclusive.** If both `assign_to_user_id` and
   `unassign` are set, return an error.
3. **Status validation only when present.** The existing
   `new`/`in_progress`/`closed`/`reopened` check runs only when a status is
   supplied.

## Action-parameter mapping

Appended to the existing `action_params` list in `_update_alert_status`:

```python
action_params = []
if status:
    action_params.append({"name": "update_status", "value": status.lower()})
if comment:
    action_params.append({"name": "append_comment", "value": comment})
if tags:
    action_params.extend({"name": "add_tag", "value": tag} for tag in tags)
if assign_to_user_id:
    action_params.append({"name": "assign_to_user_id", "value": assign_to_user_id})
elif unassign:
    # Per CrowdStrike API: the value passed to `unassign` is ignored.
    action_params.append({"name": "unassign", "value": ""})
```

The `unassign` value being ignored is confirmed in the FalconPy endpoint spec
(`_endpoint/_alerts.py`): "unassign … The value passed to this action is ignored."

## Response reporting

The result dict gains `assigned_to` and `unassigned` fields, and the tool's
output adds lines mirroring the existing comment/tags reporting:

- `Assigned to: analyst@example.com` when `assign_to_user_id` ran.
- `Unassigned` when `unassign` ran.

The `new_status` line is only shown when a status was provided.

## Spurious-500 thirdparty handling (issue #21)

The existing re-fetch verification (`_verify_status_applied`) is keyed on the
expected status. It is preserved unchanged for the status path. For assign-only
thirdparty updates there is no status to verify against; we accept this limitation
rather than build a new verification path now. If assign-only thirdparty updates
prove to hit the same spurious 500 in practice, a follow-up can add an
assignment-aware verification.

## Testing

Unit tests in the alerts test module, following existing patterns
(`tests/test_update_alert_status_thirdparty.py`):

- Assign-only: `assign_to_user_id` set, no status → emits only the assign action.
- Unassign: `unassign=True` → emits only the unassign action with ignored value.
- Combined: status + comment + `assign_to_user_id` → all actions emitted in order.
- Error: both `assign_to_user_id` and `unassign` set → mutual-exclusion error, no API call.
- Error: no action provided → error, no API call.
- Backward compatibility: existing status-only call path unchanged.

## Files touched

- `src/crowdstrike_mcp/modules/alerts.py` — tool signature, `_update_alert_status`, response formatting, tool description.
- `tests/` — new/extended alert update tests.
- `README.md` / tool docs — note the new assignment capability if tool capabilities are enumerated there.
