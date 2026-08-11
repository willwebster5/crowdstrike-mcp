"""Regression tests for the update_alerts_v3 action-value cap (issue #53).

The API rejects any action-parameter value of 1024+ characters with:

    HTTP 400 — invalid action value specified. must be less than 1024

That message names neither the offending field nor its length, and "action
value" reads like the status or the tag action rather than the comment — so the
cause is not obvious. Triage comments carrying IOCs and cross-source
verification clear 1024 easily, so this recurs.

These tests pin: the guard fires before the round trip, names the field and the
actual length, does not fire on values that fit, and applies to every action
value rather than just the comment.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from crowdstrike_mcp.modules.alerts import MAX_ACTION_VALUE_CHARS

CID = "abc:ind:def:123-0-456"


@pytest.fixture
def alerts_module(mock_client):
    with patch("crowdstrike_mcp.modules.alerts.Alerts") as MockAlerts:
        mock_alerts = MagicMock()
        MockAlerts.return_value = mock_alerts
        from crowdstrike_mcp.modules.alerts import AlertsModule

        module = AlertsModule(mock_client)
        module._service = lambda cls: mock_alerts
        module.alerts = mock_alerts
        mock_alerts.update_alerts_v3.return_value = {"status_code": 200, "body": {}}
        return module


class TestOversizedValuesAreRejectedLocally:
    def test_long_comment_is_rejected_before_the_api_call(self, alerts_module):
        result = alerts_module._update_alert_status([CID], comment="x" * 1500)

        assert result["success"] is False
        alerts_module.alerts.update_alerts_v3.assert_not_called()

    def test_message_names_the_field_and_the_actual_length(self, alerts_module):
        result = alerts_module._update_alert_status([CID], comment="x" * 1500)

        assert "comment" in result["error"]
        assert "1,500" in result["error"]
        assert "1,023" in result["error"]
        assert "477" in result["error"]  # how much to cut
        # The API's own wording is what made this hard to diagnose.
        assert "invalid action value" not in result["error"]

    def test_a_long_tag_is_caught_too(self, alerts_module):
        """The cap is per action value, not per comment."""
        result = alerts_module._update_alert_status([CID], tags=["t" * 2000])

        assert result["success"] is False
        assert "tags" in result["error"]
        alerts_module.alerts.update_alerts_v3.assert_not_called()

    def test_the_tool_surfaces_the_guard_message(self, alerts_module):
        out = asyncio.run(alerts_module.update_alert_status(composite_ids=[CID], comment="x" * 1500))

        assert "comment" in out
        assert "1,500" in out


class TestValuesThatFitAreUnaffected:
    def test_value_at_the_cap_is_allowed_through(self, alerts_module):
        result = alerts_module._update_alert_status([CID], comment="x" * MAX_ACTION_VALUE_CHARS)

        assert result["success"] is True
        alerts_module.alerts.update_alerts_v3.assert_called_once()

    def test_one_over_the_cap_is_rejected(self, alerts_module):
        """The API says 'less than 1024', so 1024 itself is not allowed."""
        result = alerts_module._update_alert_status([CID], comment="x" * (MAX_ACTION_VALUE_CHARS + 1))

        assert result["success"] is False

    def test_ordinary_update_still_works(self, alerts_module):
        result = alerts_module._update_alert_status([CID], status="closed", comment="short", tags=["a", "b"])

        assert result["success"] is True
        assert result["new_status"] == "closed"


class TestGuardHelper:
    def test_returns_none_when_everything_fits(self):
        from crowdstrike_mcp.modules.alerts import AlertsModule

        params = [{"name": "append_comment", "value": "ok"}, {"name": "add_tag", "value": "t"}]
        assert AlertsModule._oversized_action_value(params) is None

    def test_handles_a_missing_value_key(self):
        from crowdstrike_mcp.modules.alerts import AlertsModule

        assert AlertsModule._oversized_action_value([{"name": "unassign"}]) is None

    def test_unmapped_action_falls_back_to_its_api_name(self):
        from crowdstrike_mcp.modules.alerts import AlertsModule

        msg = AlertsModule._oversized_action_value([{"name": "some_future_action", "value": "x" * 2000}])
        assert "some_future_action" in msg
