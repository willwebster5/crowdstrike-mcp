"""Tests for correlation_list_rules / correlation_get_rule / correlation_export_rule.

Regression coverage for a field-name bug: the Falcon API's `enabled` field on a
correlation rule is always `false`, regardless of the rule's real state. The
real state lives in `status` ("active" / "inactive"). Rendering from `enabled`
mislabels every active rule as disabled.

Separately, a correlation rule object carries two distinct identifiers: `id`
(an internal/version id) and `rule_id` (the canonical id accepted by
get/export/update). The list tool must surface `rule_id` so its output can be
fed straight back into the other tools.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

# A rule that is genuinely running: enabled=False (always, per the API), but
# status="active" reflects reality. id and rule_id are deliberately different
# values, mirroring the real API response in the field report.
ACTIVE_RULE = {
    "id": "019f4cd327b77dee912d5bf1f4f0af90",
    "rule_id": "019c4919a4947081818e5b0293d5a58f",
    "name": "Microsoft - Entra ID - Account Lockout",
    "description": "Detects account lockouts.",
    "enabled": False,
    "status": "active",
    "severity": 60,
    "created_on": "2026-01-01T00:00:00Z",
    "updated_on": "2026-03-26T00:00:00Z",
    "created_by": "admin@example.com",
}

INACTIVE_RULE = {
    "id": "019f4cd327b77dee912d5bf1f4f0af91",
    "rule_id": "019c4919a4947081818e5b0293d5a58g",
    "name": "KnowBe4 - PhishER - Reporter EntraID Risky Sign-in",
    "description": "Disabled test rule.",
    "enabled": False,
    "status": "inactive",
    "severity": 40,
    "created_on": "2026-01-01T00:00:00Z",
    "updated_on": "2026-03-26T00:00:00Z",
    "created_by": "admin@example.com",
}


@pytest.fixture
def correlation_module(mock_client):
    """Create CorrelationModule with mocked API."""
    with patch("crowdstrike_mcp.modules.correlation.CorrelationRules") as MockCR:
        mock_cr = MagicMock()
        MockCR.return_value = mock_cr
        from crowdstrike_mcp.modules.correlation import CorrelationModule

        module = CorrelationModule(mock_client)
        module._get_correlation_service = lambda: mock_cr
        module.falcon = mock_cr
        return module


def _mock_query_and_get_rules(falcon_mock, rules):
    """Configure mock so _list_rules' query+batch-get flow returns `rules`."""
    ids = [r["rule_id"] for r in rules]
    falcon_mock.query_rules.return_value = {
        "status_code": 200,
        "body": {"resources": ids, "meta": {"pagination": {"total": len(ids)}}},
    }
    falcon_mock.get_rules.return_value = {
        "status_code": 200,
        "body": {"resources": rules},
    }


class TestListRulesStatusLabel:
    """The [ENABLED]/[DISABLED] label must come from `status`, not `enabled`."""

    def test_active_rule_is_labeled_active_despite_enabled_false(self, correlation_module):
        _mock_query_and_get_rules(correlation_module.falcon, [ACTIVE_RULE])
        result = asyncio.run(correlation_module.correlation_list_rules())
        assert "[ACTIVE]" in result
        assert "[DISABLED]" not in result

    def test_inactive_rule_is_labeled_inactive(self, correlation_module):
        _mock_query_and_get_rules(correlation_module.falcon, [INACTIVE_RULE])
        result = asyncio.run(correlation_module.correlation_list_rules())
        assert "[INACTIVE]" in result


class TestListRulesEnabledFilter:
    """The `enabled` filter param must actually filter (via `status`), not no-op."""

    def test_enabled_true_returns_only_active_status_rules(self, correlation_module):
        _mock_query_and_get_rules(correlation_module.falcon, [ACTIVE_RULE, INACTIVE_RULE])
        result = asyncio.run(correlation_module.correlation_list_rules(enabled=True))
        assert ACTIVE_RULE["name"] in result
        assert INACTIVE_RULE["name"] not in result

    def test_enabled_false_returns_only_inactive_status_rules(self, correlation_module):
        _mock_query_and_get_rules(correlation_module.falcon, [ACTIVE_RULE, INACTIVE_RULE])
        result = asyncio.run(correlation_module.correlation_list_rules(enabled=False))
        assert INACTIVE_RULE["name"] in result
        assert ACTIVE_RULE["name"] not in result


class TestListRulesEmitsRuleId:
    """The list tool must surface `rule_id` — the key get/export/update require."""

    def test_output_shows_rule_id_not_internal_id(self, correlation_module):
        _mock_query_and_get_rules(correlation_module.falcon, [ACTIVE_RULE])
        result = asyncio.run(correlation_module.correlation_list_rules())
        assert ACTIVE_RULE["rule_id"] in result
        assert ACTIVE_RULE["id"] not in result

    def test_structured_data_records_carry_rule_id(self, correlation_module):
        _mock_query_and_get_rules(correlation_module.falcon, [ACTIVE_RULE])
        result = correlation_module._list_rules()
        assert result["rules"][0]["rule_id"] == ACTIVE_RULE["rule_id"]


class TestGetRuleDoesNotMisreportEnabled:
    """correlation_get_rule must not surface the always-false `enabled` field
    as if it told the caller anything about whether the rule is running."""

    def test_get_rule_does_not_claim_enabled_false_for_active_rule(self, correlation_module):
        correlation_module.falcon.get_rules.return_value = {
            "status_code": 200,
            "body": {"resources": [ACTIVE_RULE]},
        }
        result = asyncio.run(correlation_module.correlation_get_rule(rule_ids=[ACTIVE_RULE["rule_id"]]))
        assert "Enabled: False" not in result
        assert "Status: active" in result


class TestExportRuleMetadataUsesRuleId:
    """correlation_export_rule's metadata.rule_id must be the rule's `rule_id`
    field, not its internal `id` field (they are different values)."""

    def test_export_metadata_rule_id_matches_rule_id_field(self, correlation_module):
        correlation_module.falcon.get_rules.return_value = {
            "status_code": 200,
            "body": {"resources": [ACTIVE_RULE]},
        }
        result = correlation_module._export_rule(ACTIVE_RULE["rule_id"])
        assert result["success"]
        assert result["export"]["metadata"]["rule_id"] == ACTIVE_RULE["rule_id"]
