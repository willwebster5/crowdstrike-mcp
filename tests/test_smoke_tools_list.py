"""Smoke tests for MCP tool registration — verifies tool visibility with and without allow_writes."""

from contextlib import contextmanager
from unittest.mock import MagicMock, patch

# FalconPy service classes that modules import and instantiate in __init__.
# We patch these so no real auth is required.
_FALCONPY_PATCHES = [
    "crowdstrike_mcp.modules.alerts.Alerts",
    "crowdstrike_mcp.modules.cao_hunting.CAOHunting",
    "crowdstrike_mcp.modules.case_management.CaseManagement",
    "crowdstrike_mcp.modules.cloud_registration.CSPMRegistration",
    "crowdstrike_mcp.modules.cloud_security.CloudSecurity",
    "crowdstrike_mcp.modules.cloud_security.CloudSecurityDetections",
    "crowdstrike_mcp.modules.cloud_security.CloudSecurityAssets",
    "crowdstrike_mcp.modules.correlation.CorrelationRules",
    "crowdstrike_mcp.modules.correlation.APIHarnessV2",
    "crowdstrike_mcp.modules.hosts.Hosts",
    "crowdstrike_mcp.modules.idp.IdentityProtection",
    "crowdstrike_mcp.modules.ngsiem.NGSIEM",
    "crowdstrike_mcp.modules.response.Hosts",
    "crowdstrike_mcp.modules.rtr.RealTimeResponse",
    "crowdstrike_mcp.modules.spotlight.SpotlightEvaluationLogic",
]

# Expected tool sets — update these when adding/removing tools
EXPECTED_READ_TOOLS = {
    "get_alerts",
    "alert_analysis",
    "ngsiem_alert_analysis",
    "ngsiem_query",
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
    "host_lookup",
    "host_login_history",
    "host_network_history",
    "correlation_list_rules",
    "correlation_get_rule",
    "correlation_export_rule",
    "case_query",
    "case_get",
    "case_get_fields",
    "cao_search_queries",
    "cao_get_queries",
    "cao_search_guides",
    "cao_get_guides",
    "cao_aggregate",
    "cloud_list_accounts",
    "cloud_policy_settings",
    "cloud_get_risks",
    "cloud_get_iom_detections",
    "cloud_query_assets",
    "cloud_compliance_by_account",
    "cloud_get_risk_timeline",
    "case_query_access_tags",
    "case_get_access_tags",
    "case_aggregate_access_tags",
    "case_get_rtr_file_metadata",
    "case_get_rtr_recent_files",
    "correlation_list_templates",
    "correlation_get_template",
    "spotlight_supported_evaluations",
    "spotlight_query_vulnerabilities",
    "spotlight_get_vulnerabilities",
    "spotlight_vulnerabilities_combined",
    "spotlight_get_remediations",
    "spotlight_host_vulns",
    "identity_investigate_entity",
    "rtr_init_session",
    "rtr_list_sessions",
    "rtr_pulse_session",
    "rtr_execute_command",
    "rtr_check_command_status",
    "rtr_list_files",
    "rtr_get_extracted_file_contents",
    "get_stored_response",
    "list_stored_responses",
    "threatgraph_get_edge_types",
    "threatgraph_get_vertices",
    "threatgraph_get_edges",
    "threatgraph_get_ran_on",
    "threatgraph_get_summary",
}

EXPECTED_WRITE_TOOLS = {
    "update_alert_status",
    "correlation_update_rule",
    "correlation_import_to_iac",
    "host_contain",
    "host_lift_containment",
    "case_create",
    "case_update",
    "case_add_alert_evidence",
    "case_add_event_evidence",
    "case_add_tags",
    "case_delete_tags",
    "case_upload_file",
}

# prefab-render is an optional extra; the render tools only register when
# prefab_ui is importable. Add them to the expected read set only when the
# extra is available so CI (base install) doesn't expect tools the runtime
# won't load.
try:
    import prefab_ui  # noqa: F401

    EXPECTED_READ_TOOLS = EXPECTED_READ_TOOLS | {"ngsiem_query_render", "ngsiem_query_drilldown"}
except ImportError:
    pass


@contextmanager
def _patch_falconpy():
    """Patch all FalconPy service classes to MagicMock so no real auth is needed."""
    with (
        patch.multiple("crowdstrike_mcp.modules.alerts", Alerts=MagicMock()),
        patch.multiple("crowdstrike_mcp.modules.cao_hunting", CAOHunting=MagicMock()),
        patch.multiple("crowdstrike_mcp.modules.case_management", CaseManagement=MagicMock()),
        patch.multiple("crowdstrike_mcp.modules.cloud_registration", CSPMRegistration=MagicMock()),
        patch.multiple(
            "crowdstrike_mcp.modules.cloud_security",
            CloudSecurity=MagicMock(),
            CloudSecurityDetections=MagicMock(),
            CloudSecurityAssets=MagicMock(),
            APIHarnessV2=MagicMock(),
            HARNESS_AVAILABLE=True,
        ),
        patch.multiple("crowdstrike_mcp.modules.correlation", CorrelationRules=MagicMock(), APIHarnessV2=MagicMock()),
        patch.multiple("crowdstrike_mcp.modules.hosts", Hosts=MagicMock()),
        patch.multiple("crowdstrike_mcp.modules.idp", IdentityProtection=MagicMock()),
        patch.multiple("crowdstrike_mcp.modules.ngsiem", NGSIEM=MagicMock()),
        patch.multiple("crowdstrike_mcp.modules.response", Hosts=MagicMock()),
        patch.multiple("crowdstrike_mcp.modules.rtr", RealTimeResponse=MagicMock()),
        patch.multiple("crowdstrike_mcp.modules.spotlight", SpotlightEvaluationLogic=MagicMock()),
    ):
        yield


def _collect_tools(mock_client, allow_writes: bool) -> set[str]:
    """Instantiate all modules and collect registered tool names."""
    from crowdstrike_mcp.registry import get_available_modules

    with _patch_falconpy():
        modules = get_available_modules(mock_client, allow_writes=allow_writes)

    mock_server = MagicMock()
    mock_server.tool.return_value = lambda fn: fn

    for mod in modules:
        mod.register_tools(mock_server)

    return {name for mod in modules for name in mod.tools}


class TestToolsListSmoke:
    """Verify tool registration matches expected sets."""

    def test_readonly_mode_registers_only_read_tools(self, mock_client):
        """Default mode: only read tools visible, zero write tools."""
        tools = _collect_tools(mock_client, allow_writes=False)

        # All read tools should be present
        missing_read = EXPECTED_READ_TOOLS - tools
        assert not missing_read, f"Read tools missing in readonly mode: {missing_read}"

        # No write tools should be present
        leaked_write = EXPECTED_WRITE_TOOLS & tools
        assert not leaked_write, f"Write tools leaked in readonly mode: {leaked_write}"

    def test_write_mode_registers_all_tools(self, mock_client):
        """With allow_writes=True: all read + write tools visible."""
        tools = _collect_tools(mock_client, allow_writes=True)

        # All read tools should be present
        missing_read = EXPECTED_READ_TOOLS - tools
        assert not missing_read, f"Read tools missing in write mode: {missing_read}"

        # All write tools should be present
        missing_write = EXPECTED_WRITE_TOOLS - tools
        assert not missing_write, f"Write tools missing in write mode: {missing_write}"

    def test_no_unexpected_tools(self, mock_client):
        """No tools exist that aren't in either expected set (catches untracked tools)."""
        tools = _collect_tools(mock_client, allow_writes=True)
        all_expected = EXPECTED_READ_TOOLS | EXPECTED_WRITE_TOOLS
        unexpected = tools - all_expected
        assert not unexpected, f"Unexpected tools registered (add to expected sets): {unexpected}"

    def test_write_tools_not_in_read_set(self):
        """Sanity: no overlap between read and write expected sets."""
        overlap = EXPECTED_READ_TOOLS & EXPECTED_WRITE_TOOLS
        assert not overlap, f"Tool in both read and write sets: {overlap}"


def test_smoke_ngsiem_query_render_tool_registered_when_prefab_available():
    """Spec D5/D6 — when prefab_ui is installed, NGSIEMRenderModule is auto-
    discovered and its tools register on the main server."""
    from crowdstrike_mcp.modules.ngsiem_render import RENDER_AVAILABLE

    if not RENDER_AVAILABLE:
        import pytest

        pytest.skip("prefab_ui not installed in this environment")

    from unittest.mock import MagicMock

    from crowdstrike_mcp.registry import get_available_modules

    instances = get_available_modules(MagicMock())
    names = {m.__class__.__name__ for m in instances}
    assert "NGSIEMRenderModule" in names

    render_module = next(m for m in instances if m.__class__.__name__ == "NGSIEMRenderModule")
    assert "ngsiem_query_render" in render_module.tools
    assert "ngsiem_query_drilldown" in render_module.tools
