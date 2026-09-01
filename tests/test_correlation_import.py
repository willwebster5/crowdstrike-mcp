"""Tests for correlation_import_to_iac tool — rule-to-YAML conversion."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest
import yaml

MOCK_RULE = {
    "id": "rule-uuid-123",
    "name": "AWS - CloudTrail - Suspicious IAM Activity",
    "description": "Detects suspicious IAM activity in AWS CloudTrail logs.",
    "enabled": True,
    "status": "active",
    "severity": 70,
    "search": {
        "filter": '#repo="cloudtrail" #Vendor="aws" event.action="CreateUser" | table([user.name, source.ip])',
        "lookback_window": "1h0m",
        "start": "1h",
    },
    "operation": {
        "schedule": {
            "definition": "@every 1h0m",
        },
    },
    "trigger": {
        "trigger_mode": "summary",
        "outcome": "detection",
    },
    "notification": {},
    "mitre_attack_ids": ["TA0003:T1136.001"],
    "created_on": "2026-01-01T00:00:00Z",
    "updated_on": "2026-03-26T00:00:00Z",
    "created_by": "admin@example.com",
    "updated_by": "admin@example.com",
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
        # Expose the mock for tests that configure return values via module.falcon
        module.falcon = mock_cr
        return module


def _mock_get_rules(falcon_mock, rule_data):
    """Configure mock to return a rule from get_rules."""
    falcon_mock.get_rules.return_value = {
        "status_code": 200,
        "body": {"resources": [rule_data]},
    }


class TestResourceIdGeneration:
    """Test resource_id auto-generation from rule name."""

    def test_generates_resource_id(self, correlation_module):
        result = correlation_module._generate_resource_id("AWS - CloudTrail - Suspicious IAM Activity", "aws")
        assert result == "aws_-_cloudtrail_-_suspicious_iam_activity"

    def test_strips_special_characters(self, correlation_module):
        result = correlation_module._generate_resource_id("Rule (with) [special] chars!", "aws")
        assert result == "rule_with_special_chars"

    def test_uses_override_when_provided(self, correlation_module):
        result = correlation_module._generate_resource_id("AWS - Some Rule", "aws", override="my_custom_id")
        assert result == "my_custom_id"


class TestRuleToYamlConversion:
    """Test converting API rule data to IaC YAML template."""

    def test_converts_basic_fields(self, correlation_module):
        template = correlation_module._rule_to_template(MOCK_RULE, "aws")
        assert template["name"] == "AWS - CloudTrail - Suspicious IAM Activity"
        assert template["description"] == MOCK_RULE["description"]
        assert template["severity"] == 70
        assert template["status"] == "active"

    def test_converts_search_fields(self, correlation_module):
        template = correlation_module._rule_to_template(MOCK_RULE, "aws")
        assert "search" in template
        assert template["search"]["filter"] == MOCK_RULE["search"]["filter"]
        assert template["search"]["lookback"] == "1h0m"
        assert template["search"]["outcome"] == "detection"
        assert template["search"]["trigger_mode"] == "summary"

    def test_converts_schedule(self, correlation_module):
        template = correlation_module._rule_to_template(MOCK_RULE, "aws")
        assert template["operation"]["schedule"]["definition"] == "@every 1h0m"

    def test_converts_mitre_attack(self, correlation_module):
        template = correlation_module._rule_to_template(MOCK_RULE, "aws")
        assert template["mitre_attack"] == ["TA0003:T1136.001"]

    def test_generates_resource_id_field(self, correlation_module):
        template = correlation_module._rule_to_template(MOCK_RULE, "aws")
        assert template["resource_id"] == "aws_-_cloudtrail_-_suspicious_iam_activity"

    def test_inactive_status_maps_to_disabled_status(self, correlation_module):
        rule = {**MOCK_RULE, "status": "inactive"}
        template = correlation_module._rule_to_template(rule, "aws")
        assert template["status"] == "disabled"

    def test_active_status_maps_to_active_even_when_enabled_is_false(self, correlation_module):
        # The Falcon API always returns enabled=False, regardless of whether
        # the rule is actually running — `status` is the field that carries
        # the real state, and must be what drives the IaC template.
        rule = {**MOCK_RULE, "enabled": False, "status": "active"}
        template = correlation_module._rule_to_template(rule, "aws")
        assert template["status"] == "active"


class TestDryRunMode:
    """Test dry_run returns YAML string without writing."""

    def test_dry_run_returns_yaml(self, correlation_module):
        _mock_get_rules(correlation_module.falcon, MOCK_RULE)
        result = asyncio.run(
            correlation_module.correlation_import_to_iac(
                rule_id="rule-uuid-123",
                vendor="aws",
                dry_run=True,
            )
        )
        assert "resource_id:" in result
        assert "aws_-_cloudtrail_-_suspicious_iam_activity" in result
        assert "search:" in result

    def test_dry_run_does_not_write_file(self, correlation_module, tmp_path):
        correlation_module._detections_repo_path = str(tmp_path)
        _mock_get_rules(correlation_module.falcon, MOCK_RULE)
        asyncio.run(
            correlation_module.correlation_import_to_iac(
                rule_id="rule-uuid-123",
                vendor="aws",
                dry_run=True,
            )
        )
        expected_file = tmp_path / "resources" / "detections" / "aws" / "aws_-_cloudtrail_-_suspicious_iam_activity.yaml"
        assert not expected_file.exists()


class TestFileWrite:
    """Test actual file writing when dry_run=False."""

    def test_writes_yaml_file(self, correlation_module, tmp_path):
        correlation_module._detections_repo_path = str(tmp_path)
        # Create the vendor directory
        (tmp_path / "resources" / "detections" / "aws").mkdir(parents=True)

        _mock_get_rules(correlation_module.falcon, MOCK_RULE)
        asyncio.run(
            correlation_module.correlation_import_to_iac(
                rule_id="rule-uuid-123",
                vendor="aws",
                dry_run=False,
            )
        )
        expected_file = tmp_path / "resources" / "detections" / "aws" / "aws_-_cloudtrail_-_suspicious_iam_activity.yaml"
        assert expected_file.exists()
        content = yaml.safe_load(expected_file.read_text())
        assert content["resource_id"] == "aws_-_cloudtrail_-_suspicious_iam_activity"
        assert content["severity"] == 70

    def test_refuses_overwrite_existing_file(self, correlation_module, tmp_path):
        correlation_module._detections_repo_path = str(tmp_path)
        target_dir = tmp_path / "resources" / "detections" / "aws"
        target_dir.mkdir(parents=True)
        (target_dir / "aws_-_cloudtrail_-_suspicious_iam_activity.yaml").write_text("existing")

        _mock_get_rules(correlation_module.falcon, MOCK_RULE)
        result = asyncio.run(
            correlation_module.correlation_import_to_iac(
                rule_id="rule-uuid-123",
                vendor="aws",
                dry_run=False,
            )
        )
        assert "already exists" in result.lower()

    def test_falls_back_to_dry_run_when_path_not_writable(self, correlation_module):
        correlation_module._detections_repo_path = None
        _mock_get_rules(correlation_module.falcon, MOCK_RULE)
        result = asyncio.run(
            correlation_module.correlation_import_to_iac(
                rule_id="rule-uuid-123",
                vendor="aws",
                dry_run=False,
            )
        )
        # Should return YAML as text since it can't write
        assert "resource_id:" in result
        assert "not configured" in result.lower() or "dry-run" in result.lower()


class TestVendorValidation:
    """Test vendor parameter validation."""

    def test_rejects_invalid_vendor(self, correlation_module):
        _mock_get_rules(correlation_module.falcon, MOCK_RULE)
        result = asyncio.run(
            correlation_module.correlation_import_to_iac(
                rule_id="rule-uuid-123",
                vendor="invalid_vendor",
                dry_run=True,
            )
        )
        assert "invalid" in result.lower() or "must be one of" in result.lower()


class TestToolRegistration:
    def test_registers_import_tool(self, mock_client):
        """Write tools register when allow_writes=True."""
        with patch("crowdstrike_mcp.modules.correlation.CorrelationRules") as MockCR:
            MockCR.return_value = MagicMock()
            from crowdstrike_mcp.modules.correlation import CorrelationModule

            module = CorrelationModule(mock_client)
            module.allow_writes = True
        server = MagicMock()
        module.register_tools(server)
        assert "correlation_import_to_iac" in module.tools
        assert "correlation_update_rule" in module.tools

    def test_skips_import_tool_when_writes_disabled(self, correlation_module):
        """Write tools are skipped when allow_writes=False (default)."""
        server = MagicMock()
        correlation_module.register_tools(server)
        assert "correlation_import_to_iac" not in correlation_module.tools
        assert "correlation_update_rule" not in correlation_module.tools
