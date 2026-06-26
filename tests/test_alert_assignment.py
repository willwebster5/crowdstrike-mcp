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
