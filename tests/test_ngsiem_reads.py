"""Tests for FR 07 NGSIEM read-expansion tools."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def ngsiem_module(mock_client):
    """NGSIEMModule with the falconpy NGSIEM client mocked."""
    with patch("crowdstrike_mcp.modules.ngsiem.NGSIEM") as MockNGSIEM:
        mock_falcon = MagicMock()
        MockNGSIEM.return_value = mock_falcon
        from crowdstrike_mcp.modules.ngsiem import NGSIEMModule

        module = NGSIEMModule(mock_client)
        module._service = lambda cls: mock_falcon
        module.falcon = mock_falcon
        return module


class TestCallAndUnwrap:
    """The shared helper used by all 12 new tools."""

    def test_success_path_returns_resources(self, ngsiem_module):
        fake_method = MagicMock(
            return_value={
                "status_code": 200,
                "body": {"resources": [{"id": "a"}, {"id": "b"}]},
            }
        )
        result = ngsiem_module._call_and_unwrap(fake_method, "op_name", filter="x")
        assert result["success"] is True
        assert result["resources"] == [{"id": "a"}, {"id": "b"}]
        fake_method.assert_called_once_with(filter="x")

    def test_http_error_surfaces_body_message(self, ngsiem_module):
        fake_method = MagicMock(
            return_value={
                "status_code": 403,
                "body": {"errors": [{"message": "Forbidden"}]},
            }
        )
        result = ngsiem_module._call_and_unwrap(fake_method, "op_name")
        assert result["success"] is False
        assert "Forbidden" in result["error"]
        assert "403" in result["error"]

    def test_empty_resources_is_success(self, ngsiem_module):
        fake_method = MagicMock(
            return_value={
                "status_code": 200,
                "body": {"resources": []},
            }
        )
        result = ngsiem_module._call_and_unwrap(fake_method, "op_name")
        assert result["success"] is True
        assert result["resources"] == []

    def test_exception_is_captured(self, ngsiem_module):
        fake_method = MagicMock(side_effect=RuntimeError("boom"))
        result = ngsiem_module._call_and_unwrap(fake_method, "op_name")
        assert result["success"] is False
        assert "boom" in result["error"]


class TestListSavedQueries:
    def test_returns_compact_projection_by_default(self, ngsiem_module):
        ngsiem_module.falcon.list_saved_queries.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "q1", "name": "enrich_users", "last_modified": "2026-04-01", "query": "..." * 100, "extra": "ignored"},
                    {"id": "q2", "name": "enrich_hosts", "last_modified": "2026-04-02"},
                ]
            },
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_saved_queries())
        assert "q1" in result and "enrich_users" in result
        assert "q2" in result and "enrich_hosts" in result
        # Bulk body fields must not leak in compact mode
        assert "extra" not in result

    def test_detail_true_returns_full_records(self, ngsiem_module):
        ngsiem_module.falcon.list_saved_queries.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "q1", "name": "x", "last_modified": "t", "extra": "keep_me"},
                ]
            },
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_saved_queries(detail=True))
        assert "keep_me" in result

    def test_passes_filter_and_limit(self, ngsiem_module):
        ngsiem_module.falcon.list_saved_queries.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_list_saved_queries(filter="name:'enrich_*'", limit=25))
        kwargs = ngsiem_module.falcon.list_saved_queries.call_args.kwargs
        assert kwargs["filter"] == "name:'enrich_*'"
        assert kwargs["limit"] == 25

    def test_caps_limit_at_1000(self, ngsiem_module):
        ngsiem_module.falcon.list_saved_queries.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_list_saved_queries(limit=9999))
        kwargs = ngsiem_module.falcon.list_saved_queries.call_args.kwargs
        assert kwargs["limit"] == 1000

    def test_empty_result_message(self, ngsiem_module):
        ngsiem_module.falcon.list_saved_queries.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_saved_queries())
        assert "no" in result.lower() or "0" in result

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.list_saved_queries.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_saved_queries())
        assert "failed" in result.lower()


class TestGetSavedQueryTemplate:
    def test_returns_full_template(self, ngsiem_module):
        ngsiem_module.falcon.get_saved_query_template.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "q1", "name": "enrich_users", "query_string": "#repo=all | ..."},
                ]
            },
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_saved_query_template(id="q1"))
        assert "q1" in result
        assert "enrich_users" in result
        assert "#repo=all" in result

    def test_passes_id(self, ngsiem_module):
        ngsiem_module.falcon.get_saved_query_template.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_get_saved_query_template(id="abc"))
        kwargs = ngsiem_module.falcon.get_saved_query_template.call_args.kwargs
        assert kwargs["ids"] == "abc" or kwargs["ids"] == ["abc"]

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.get_saved_query_template.return_value = {
            "status_code": 404,
            "body": {"errors": [{"message": "Not found"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_saved_query_template(id="missing"))
        assert "failed" in result.lower()


class TestListLookupFiles:
    def test_returns_compact_projection(self, ngsiem_module):
        ngsiem_module.falcon.list_lookup_files.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "l1", "name": "blocked_domains.csv", "last_modified": "t1", "row_count": 400, "schema": "..." * 20},
                ]
            },
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_lookup_files())
        assert "l1" in result and "blocked_domains.csv" in result
        assert "row_count" not in result  # not in compact field set

    def test_detail_true_returns_full(self, ngsiem_module):
        ngsiem_module.falcon.list_lookup_files.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "l1", "name": "x", "row_count": 42},
                ]
            },
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_lookup_files(detail=True))
        assert "row_count" in result
        assert "42" in result

    def test_caps_limit(self, ngsiem_module):
        ngsiem_module.falcon.list_lookup_files.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_list_lookup_files(limit=9999))
        assert ngsiem_module.falcon.list_lookup_files.call_args.kwargs["limit"] == 1000


class TestGetLookupFile:
    """Issue #52: this endpoint is a DOWNLOAD, not a record fetch.

    The tests that lived here mocked a record with a strippable "content" field
    and a "row_count" — a shape the API never returns. falconpy hands back raw
    bytes, and the call 400'd before reaching any of that anyway (it was
    addressed by `ids`, where the API wants `filename`, and omitted the required
    `search_domain`). The old tests passed against a fiction, which is why the
    defect survived: mock the real shape or the test proves nothing.
    """

    CSV = b"domain,note\nfoo.example,a\nbar.example,b\n"

    def test_preview_by_default_reports_size_and_lines(self, ngsiem_module):
        ngsiem_module.falcon.get_lookup_file.return_value = self.CSV
        result = asyncio.run(ngsiem_module.ngsiem_get_lookup_file(filename="blocked_domains.csv"))
        assert "blocked_domains.csv" in result
        assert f"{len(self.CSV):,} bytes" in result
        assert "Lines: 3" in result
        assert "domain,note" in result  # header row is part of the preview

    def test_long_file_is_truncated_with_a_recoverable_ref(self, ngsiem_module):
        big = b"col\n" + b"\n".join(f"row{i}".encode() for i in range(500))
        ngsiem_module.falcon.get_lookup_file.return_value = big
        result = asyncio.run(ngsiem_module.ngsiem_get_lookup_file(filename="big.csv"))
        assert "row0" in result
        assert "row499" not in result
        assert "more lines" in result
        assert "resp_" in result  # full content stays reachable via get_stored_response

    def test_include_content_true_returns_whole_file(self, ngsiem_module):
        big = b"col\n" + b"\n".join(f"row{i}".encode() for i in range(20))
        ngsiem_module.falcon.get_lookup_file.return_value = big
        result = asyncio.run(ngsiem_module.ngsiem_get_lookup_file(filename="big.csv", include_content=True))
        assert "row0" in result
        assert "row19" in result

    def test_passes_filename_and_search_domain(self, ngsiem_module):
        ngsiem_module.falcon.get_lookup_file.return_value = self.CSV
        asyncio.run(ngsiem_module.ngsiem_get_lookup_file(filename="abc.csv"))
        kwargs = ngsiem_module.falcon.get_lookup_file.call_args.kwargs
        assert kwargs["filename"] == "abc.csv"
        assert kwargs["search_domain"] == "all"
        assert "ids" not in kwargs  # the API ignores it; this is what 400'd

    def test_undecodable_bytes_do_not_raise(self, ngsiem_module):
        ngsiem_module.falcon.get_lookup_file.return_value = b"\xff\xfe not utf-8"
        result = asyncio.run(ngsiem_module.ngsiem_get_lookup_file(filename="weird.bin"))
        assert "weird.bin" in result

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.get_lookup_file.return_value = {
            "status_code": 404,
            "body": {"errors": [{"message": "Not found"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_lookup_file(filename="missing"))
        assert "failed" in result.lower()
        assert "Not found" in result


class TestListDashboards:
    def test_compact_projection(self, ngsiem_module):
        ngsiem_module.falcon.list_dashboards.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "d1", "name": "Ingestion Overview", "last_modified": "t1", "widgets": ["..." * 50]},
                ]
            },
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_dashboards())
        assert "Ingestion Overview" in result
        assert "widgets" not in result

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.list_dashboards.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "boom"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_dashboards())
        assert "failed" in result.lower()


class TestListParsers:
    def test_compact_projection(self, ngsiem_module):
        ngsiem_module.falcon.list_parsers.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "p1", "name": "box-parser", "last_modified": "t", "script": "#" * 1000},
                ]
            },
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_parsers())
        assert "box-parser" in result
        assert "script" not in result

    def test_detail_true_returns_script(self, ngsiem_module):
        ngsiem_module.falcon.list_parsers.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "p1", "name": "box-parser", "script": "MARKER_STRING"},
                ]
            },
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_parsers(detail=True))
        assert "MARKER_STRING" in result


class TestGetParser:
    def test_returns_parser_detail(self, ngsiem_module):
        ngsiem_module.falcon.get_parser.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "p1", "name": "box-parser", "script": "MARKER_STRING"},
                ]
            },
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_parser(id="p1"))
        assert "p1" in result
        assert "MARKER_STRING" in result

    def test_passes_id(self, ngsiem_module):
        ngsiem_module.falcon.get_parser.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_get_parser(id="p1"))
        kwargs = ngsiem_module.falcon.get_parser.call_args.kwargs
        assert kwargs["ids"] == "p1" or kwargs["ids"] == ["p1"]

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.get_parser.return_value = {
            "status_code": 404,
            "body": {"errors": [{"message": "Not found"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_parser(id="missing"))
        assert "failed" in result.lower()


class TestListDataConnections:
    def test_compact_projection_with_state(self, ngsiem_module):
        ngsiem_module.falcon.list_data_connections.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "c1", "name": "box-prod", "state": "active", "last_modified": "t1", "config_blob": "..." * 100},
                    {"id": "c2", "name": "cato-prod", "state": "failed"},
                ]
            },
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_data_connections())
        assert "box-prod" in result and "active" in result
        assert "cato-prod" in result and "failed" in result
        assert "config_blob" not in result

    def test_passes_filter(self, ngsiem_module):
        ngsiem_module.falcon.list_data_connections.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_list_data_connections(filter="state:'failed'"))
        kwargs = ngsiem_module.falcon.list_data_connections.call_args.kwargs
        assert kwargs["filter"] == "state:'failed'"

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.list_data_connections.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_data_connections())
        assert "failed" in result.lower()


class TestGetDataConnection:
    def test_returns_connection_detail(self, ngsiem_module):
        ngsiem_module.falcon.get_connection_by_id.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "c1", "name": "box-prod", "state": "active", "config": {"endpoint": "https://x"}},
                ]
            },
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_data_connection(id="c1"))
        assert "box-prod" in result
        assert "endpoint" in result

    def test_passes_id(self, ngsiem_module):
        ngsiem_module.falcon.get_connection_by_id.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(ngsiem_module.ngsiem_get_data_connection(id="c1"))
        kwargs = ngsiem_module.falcon.get_connection_by_id.call_args.kwargs
        assert kwargs["ids"] == "c1" or kwargs["ids"] == ["c1"]


class TestGetProvisioningStatus:
    def test_returns_status(self, ngsiem_module):
        ngsiem_module.falcon.get_provisioning_status.return_value = {
            "status_code": 200,
            "body": {"resources": [{"provisioned": True, "region": "us-1"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_provisioning_status())
        assert "provisioned" in result
        assert "us-1" in result

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.get_provisioning_status.return_value = {
            "status_code": 500,
            "body": {"errors": [{"message": "boom"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_get_provisioning_status())
        assert "failed" in result.lower()


class TestListDataConnectors:
    def test_returns_connector_types(self, ngsiem_module):
        ngsiem_module.falcon.list_data_connectors.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "box", "name": "Box", "description": "Box cloud storage"},
                    {"id": "cato", "name": "Cato", "description": "Cato SASE"},
                ]
            },
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_data_connectors())
        assert "Box" in result and "Cato" in result
        # Verify detail=True: non-compact fields (description) must appear
        assert "Box cloud storage" in result
        assert "Cato SASE" in result

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.list_data_connectors.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_data_connectors())
        assert "failed" in result.lower()


class TestListConnectorConfigs:
    def test_compact_projection(self, ngsiem_module):
        ngsiem_module.falcon.list_connector_configs.return_value = {
            "status_code": 200,
            "body": {
                "resources": [
                    {"id": "cfg1", "name": "box-cfg", "last_modified": "t", "big_blob": "..." * 100},
                ]
            },
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_connector_configs())
        assert "box-cfg" in result
        assert "big_blob" not in result

    def test_handles_api_error(self, ngsiem_module):
        ngsiem_module.falcon.list_connector_configs.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(ngsiem_module.ngsiem_list_connector_configs())
        assert "failed" in result.lower()


class TestNgsiemReadToolRegistration:
    EXPECTED_NEW_TOOLS = [
        "ngsiem_list_saved_queries",
        "ngsiem_get_saved_query_template",
        "ngsiem_list_lookup_files",
        "ngsiem_get_lookup_file",
        "ngsiem_list_dashboards",
        "ngsiem_list_parsers",
        "ngsiem_get_parser",
        "ngsiem_list_data_connections",
        "ngsiem_get_data_connection",
        "ngsiem_get_provisioning_status",
        "ngsiem_list_data_connectors",
        "ngsiem_list_connector_configs",
    ]

    def test_all_tools_register_as_read(self, ngsiem_module):
        server = MagicMock()
        server.tool.return_value = lambda fn: fn
        ngsiem_module.register_tools(server)
        for name in self.EXPECTED_NEW_TOOLS:
            assert name in ngsiem_module.tools, f"{name} not registered"
        # And the pre-existing tool stays registered
        assert "ngsiem_query" in ngsiem_module.tools
