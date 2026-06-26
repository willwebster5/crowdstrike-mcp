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
