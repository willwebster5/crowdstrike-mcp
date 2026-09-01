"""Tests for new case management tools added in FalconPy v1.6.1."""

import asyncio
from unittest.mock import MagicMock, create_autospec, patch

import pytest
from falconpy import CaseManagement


@pytest.fixture
def case_module(mock_client):
    """Create CaseManagementModule with mocked API.

    The mock is autospecced against the real falconpy CaseManagement class so
    that a typo'd method name (calling an attribute the SDK doesn't actually
    have) raises AttributeError in the test instead of silently succeeding.
    """
    with patch("crowdstrike_mcp.modules.case_management.CaseManagement") as MockCM:
        mock_cm = create_autospec(CaseManagement, instance=True)
        MockCM.return_value = mock_cm
        from crowdstrike_mcp.modules.case_management import CaseManagementModule

        module = CaseManagementModule(mock_client)
        module._service = lambda cls: mock_cm
        # Expose the mock for tests that configure return values via module.falcon
        module.falcon = mock_cm
        return module


class TestCaseQueryAccessTags:
    """Test case_query_access_tags tool."""

    def test_returns_tag_ids(self, case_module):
        case_module.falcon.query_access_tags.return_value = {
            "status_code": 200,
            "body": {
                "resources": ["tag-001", "tag-002"],
                "meta": {"pagination": {"total": 2}},
            },
        }
        result = asyncio.run(case_module.case_query_access_tags())
        assert "tag-001" in result
        assert "tag-002" in result

    def test_handles_empty_results(self, case_module):
        case_module.falcon.query_access_tags.return_value = {
            "status_code": 200,
            "body": {
                "resources": [],
                "meta": {"pagination": {"total": 0}},
            },
        }
        result = asyncio.run(case_module.case_query_access_tags())
        assert "no access tags" in result.lower() or "0" in result

    def test_handles_api_error(self, case_module):
        case_module.falcon.query_access_tags.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(case_module.case_query_access_tags())
        assert "failed" in result.lower()


class TestCaseGetAccessTags:
    """Test case_get_access_tags tool."""

    def test_returns_tag_details(self, case_module):
        case_module.falcon.get_access_tags.return_value = {
            "status_code": 200,
            "body": {"resources": [{"id": "tag-001", "name": "SOC-Team", "description": "SOC team access"}]},
        }
        result = asyncio.run(case_module.case_get_access_tags(tag_ids=["tag-001"]))
        assert "SOC-Team" in result
        assert "tag-001" in result

    def test_handles_api_error(self, case_module):
        case_module.falcon.get_access_tags.return_value = {
            "status_code": 404,
            "body": {"errors": [{"message": "Not found"}]},
        }
        result = asyncio.run(case_module.case_get_access_tags(tag_ids=["bad-id"]))
        assert "failed" in result.lower()


class TestCaseAggregateAccessTags:
    """Test case_aggregate_access_tags tool."""

    def test_returns_aggregation_data(self, case_module):
        case_module.falcon.get_access_tag_aggregations.return_value = {
            "status_code": 200,
            "body": {"resources": [{"name": "tag_count", "buckets": [{"label": "SOC", "count": 5}]}]},
        }
        result = asyncio.run(
            case_module.case_aggregate_access_tags(
                date_ranges=[],
                field="name",
                filter="",
                name="tag_count",
                type="terms",
            )
        )
        assert "tag_count" in result or "SOC" in result

    def test_handles_api_error(self, case_module):
        case_module.falcon.get_access_tag_aggregations.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "Internal error"}]},
        }
        result = asyncio.run(
            case_module.case_aggregate_access_tags(
                date_ranges=[],
                field="name",
                filter="",
                name="tag_count",
                type="terms",
            )
        )
        assert "failed" in result.lower()


class TestCaseGetRtrFileMetadata:
    """Test case_get_rtr_file_metadata tool."""

    def test_returns_file_metadata(self, case_module):
        case_module.falcon.get_rtr_file_metadata.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "file-001",
                        "file_name": "suspicious.exe",
                        "file_size": 1024,
                        "sha256": "abc123def456",
                    }
                ]
            },
        }
        result = asyncio.run(case_module.case_get_rtr_file_metadata(case_id="case-123"))
        assert "suspicious.exe" in result
        assert "file-001" in result

    def test_handles_no_files(self, case_module):
        case_module.falcon.get_rtr_file_metadata.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        result = asyncio.run(case_module.case_get_rtr_file_metadata(case_id="case-123"))
        assert "no rtr" in result.lower() or "0" in result

    def test_handles_api_error(self, case_module):
        case_module.falcon.get_rtr_file_metadata.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(case_module.case_get_rtr_file_metadata(case_id="case-123"))
        assert "failed" in result.lower()


class TestCaseGetRtrRecentFiles:
    """Test case_get_rtr_recent_files tool."""

    def test_returns_recent_files(self, case_module):
        case_module.falcon.retrieve_rtr_recent_file.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {
                        "id": "file-002",
                        "file_name": "collected.log",
                        "created_on": "2026-03-31T12:00:00Z",
                    }
                ]
            },
        }
        result = asyncio.run(case_module.case_get_rtr_recent_files(case_id="case-123"))
        assert "collected.log" in result

    def test_handles_api_error(self, case_module):
        case_module.falcon.retrieve_rtr_recent_file.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "Internal error"}]},
        }
        result = asyncio.run(case_module.case_get_rtr_recent_files(case_id="case-123"))
        assert "failed" in result.lower()


class TestCaseUploadFile:
    """Test case_upload_file tool."""

    def test_uploads_successfully(self, case_module, tmp_path):
        f = tmp_path / "report.md"
        f.write_text("hunt report contents")
        case_module.falcon.upload_file.return_value = {
            "status_code": 201,
            "body": {},
        }
        result = asyncio.run(
            case_module.case_upload_file(case_id="case-123", file_path=str(f))
        )
        assert "successfully" in result.lower()
        assert "report.md" in result

    def test_error_message_is_not_doubled(self, case_module, tmp_path):
        f = tmp_path / "report.md"
        f.write_text("hunt report contents")
        case_module.falcon.upload_file.return_value = {
            "status_code": 404,
            "body": {"errors": [{"message": "Not Found"}]},
        }
        result = asyncio.run(
            case_module.case_upload_file(case_id="case-123", file_path=str(f))
        )
        assert result.count("Failed to upload file") == 1

    def test_handles_missing_file(self, case_module):
        result = asyncio.run(
            case_module.case_upload_file(
                case_id="case-123", file_path="/no/such/file.md"
            )
        )
        assert "not found" in result.lower()


class TestToolRegistration:
    """Verify new tools register correctly."""

    def test_all_new_tools_register_as_read(self, case_module):
        server = MagicMock()
        server.tool.return_value = lambda fn: fn
        case_module.register_tools(server)
        assert "case_query_access_tags" in case_module.tools
        assert "case_get_access_tags" in case_module.tools
        assert "case_aggregate_access_tags" in case_module.tools
        assert "case_get_rtr_file_metadata" in case_module.tools
        assert "case_get_rtr_recent_files" in case_module.tools
