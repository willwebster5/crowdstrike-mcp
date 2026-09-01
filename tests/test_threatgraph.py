"""Tests for Threat Graph module."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest


class TestThreatGraphScopes:
    """Scope mappings for Threat Graph operations exist in api_scopes."""

    def test_entities_vertices_getv2_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes

        assert get_required_scopes("entities_vertices_getv2") == ["threatgraph:read"]

    def test_combined_edges_get_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes

        assert get_required_scopes("combined_edges_get") == ["threatgraph:read"]

    def test_combined_ran_on_get_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes

        assert get_required_scopes("combined_ran_on_get") == ["threatgraph:read"]

    def test_combined_summary_get_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes

        assert get_required_scopes("combined_summary_get") == ["threatgraph:read"]

    def test_queries_edgetypes_get_scope(self):
        from crowdstrike_mcp.common.api_scopes import get_required_scopes

        assert get_required_scopes("queries_edgetypes_get") == ["threatgraph:read"]


class TestEdgeTypeCache:
    """ThreatGraphEdgeTypeCache behavior: fetch-on-first-read, cache, invalidate."""

    def test_first_read_calls_fetcher_and_caches(self):
        from crowdstrike_mcp.resources.threatgraph_reference import ThreatGraphEdgeTypeCache

        fetch_calls = []

        def fake_fetcher():
            fetch_calls.append(1)
            return {"status_code": 200, "body": {"resources": ["accessed_by_session", "wrote_file"]}}

        cache = ThreatGraphEdgeTypeCache(fake_fetcher)
        body = cache.read()
        assert "accessed_by_session" in body
        assert "wrote_file" in body
        assert len(fetch_calls) == 1

    def test_second_read_uses_cache(self):
        from crowdstrike_mcp.resources.threatgraph_reference import ThreatGraphEdgeTypeCache

        fetch_calls = []

        def fake_fetcher():
            fetch_calls.append(1)
            return {"status_code": 200, "body": {"resources": ["x"]}}

        cache = ThreatGraphEdgeTypeCache(fake_fetcher)
        cache.read()
        cache.read()
        assert len(fetch_calls) == 1

    def test_fetch_failure_does_not_poison_cache(self):
        from crowdstrike_mcp.resources.threatgraph_reference import ThreatGraphEdgeTypeCache

        state = {"calls": 0, "fail": True}

        def fake_fetcher():
            state["calls"] += 1
            if state["fail"]:
                return {"status_code": 500, "body": {"errors": [{"message": "boom"}]}}
            return {"status_code": 200, "body": {"resources": ["ok"]}}

        cache = ThreatGraphEdgeTypeCache(fake_fetcher)
        first = cache.read()
        assert "500" in first or "error" in first.lower()

        state["fail"] = False
        second = cache.read()
        assert "ok" in second
        assert state["calls"] == 2

    def test_invalidate_forces_refetch(self):
        from crowdstrike_mcp.resources.threatgraph_reference import ThreatGraphEdgeTypeCache

        state = {"calls": 0, "payload": ["v1"]}

        def fake_fetcher():
            state["calls"] += 1
            return {"status_code": 200, "body": {"resources": list(state["payload"])}}

        cache = ThreatGraphEdgeTypeCache(fake_fetcher)
        first = cache.read()
        assert "v1" in first

        state["payload"] = ["v2"]
        cache.invalidate()
        second = cache.read()
        assert "v2" in second
        assert state["calls"] == 2


class TestEdgeTypeCacheClientScoping:
    """The edge-type cache must not leak across tenants sharing one ThreatGraphModule.

    ThreatGraphModule is instantiated once at server startup and shared across
    every session in HTTP mode. Without scoping the cache by client_id, the
    first tenant to read the edge-type resource permanently seeds the cache
    for every subsequent tenant on that process.
    """

    def test_cache_not_shared_across_client_ids(self):
        from crowdstrike_mcp.resources.threatgraph_reference import ThreatGraphEdgeTypeCache

        fetch_calls = []

        def fake_fetcher():
            fetch_calls.append(1)
            return {"status_code": 200, "body": {"resources": ["edge_from_fetch"]}}

        cache = ThreatGraphEdgeTypeCache(fake_fetcher)
        cache.read(client_id="tenant-a")
        cache.read(client_id="tenant-b")
        assert len(fetch_calls) == 2, "tenant B must not get tenant A's cached edge types"

    def test_cache_key_scoped_by_client_id(self):
        """One ThreatGraphModule instance, credentials swapped mid-session (as in
        HTTP mode), must not return tenant A's cached edge types to tenant B.

        Mirrors AlertsModule's test_cache_key_scoped_by_client_id
        (tests/test_ngsiem_timeout_fix.py), which proved the same fix for
        _ngsiem_event_cache.
        """
        with patch("crowdstrike_mcp.modules.threat_graph.ThreatGraph"):
            tenant_a = MagicMock()
            tenant_a.client_id = "tenant-a"
            tenant_a.auth_object = MagicMock()
            tenant_b = MagicMock()
            tenant_b.client_id = "tenant-b"
            tenant_b.auth_object = MagicMock()

            from crowdstrike_mcp.modules.threat_graph import ThreatGraphModule

            module = ThreatGraphModule(tenant_a)

            service_a = MagicMock()
            service_a.get_edge_types.return_value = {
                "status_code": 200,
                "body": {"resources": ["tenant_a_only_edge"]},
            }
            module._service = lambda cls: service_a
            first = module._edge_type_cache.read(module._get_client_id())
            assert "tenant_a_only_edge" in first

            # Swap the module's active credentials to tenant B without a cache hit.
            module.client = tenant_b
            service_b = MagicMock()
            service_b.get_edge_types.return_value = {
                "status_code": 200,
                "body": {"resources": ["tenant_b_only_edge"]},
            }
            module._service = lambda cls: service_b
            second = module._edge_type_cache.read(module._get_client_id())
            assert service_b.get_edge_types.called, "tenant B must not get tenant A's cached edge types"
            assert "tenant_b_only_edge" in second
            assert "tenant_a_only_edge" not in second


@pytest.fixture
def threatgraph_module(mock_client):
    """ThreatGraphModule with ThreatGraph service mocked."""
    with patch("crowdstrike_mcp.modules.threat_graph.ThreatGraph") as MockTG:
        mock_tg = MagicMock()
        MockTG.return_value = mock_tg
        from crowdstrike_mcp.modules.threat_graph import ThreatGraphModule

        module = ThreatGraphModule(mock_client)
        module._service = lambda cls: mock_tg
        module.falcon = mock_tg
        return module


class TestThreatGraphModuleScaffold:
    """Module loads, registers expected resource URI, inherits BaseModule."""

    def test_module_subclasses_base(self, threatgraph_module):
        from crowdstrike_mcp.modules.base import BaseModule

        assert isinstance(threatgraph_module, BaseModule)

    def test_registers_edge_types_resource(self, threatgraph_module):
        server = MagicMock()
        server.resource.return_value = lambda fn: fn
        threatgraph_module.register_resources(server)
        assert "falcon://reference/threatgraph-edge-types" in threatgraph_module.resources

    def test_auto_discovery_finds_class(self):
        from crowdstrike_mcp.registry import discover_module_classes

        names = [c.__name__ for c in discover_module_classes()]
        assert "ThreatGraphModule" in names


class TestThreatGraphGetEdgeTypes:
    def test_returns_edge_types(self, threatgraph_module):
        threatgraph_module.falcon.get_edge_types.return_value = {
            "status_code": 200,
            "body": {"resources": ["wrote_file", "accessed_by_session"]},
        }
        result = asyncio.run(threatgraph_module.threatgraph_get_edge_types())
        assert "wrote_file" in result
        assert "accessed_by_session" in result

    def test_invalidates_resource_cache(self, threatgraph_module):
        # Seed the cache
        threatgraph_module.falcon.get_edge_types.return_value = {
            "status_code": 200,
            "body": {"resources": ["old"]},
        }
        first_body = threatgraph_module._edge_type_cache.read(threatgraph_module._get_client_id())
        assert "old" in first_body

        # Change API response, then call the tool
        threatgraph_module.falcon.get_edge_types.return_value = {
            "status_code": 200,
            "body": {"resources": ["new"]},
        }
        asyncio.run(threatgraph_module.threatgraph_get_edge_types())

        # The cache should now reflect the new list on next resource read
        second_body = threatgraph_module._edge_type_cache.read(threatgraph_module._get_client_id())
        assert "new" in second_body
        assert "old" not in second_body

    def test_handles_api_error(self, threatgraph_module):
        threatgraph_module.falcon.get_edge_types.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(threatgraph_module.threatgraph_get_edge_types())
        assert "failed" in result.lower() or "forbidden" in result.lower()


class TestThreatGraphGetVertices:
    def test_returns_vertex_metadata(self, threatgraph_module):
        threatgraph_module.falcon.get_vertices_v2.return_value = {
            "status_code": 200,
            "body": {"resources": [{"id": "pid:aaa:111", "vertex_type": "process", "properties": {"name": "rclone.exe"}}]},
        }
        result = asyncio.run(threatgraph_module.threatgraph_get_vertices(ids=["pid:aaa:111"], vertex_type="process"))
        assert "pid:aaa:111" in result
        assert "rclone.exe" in result

    def test_passes_args_to_falconpy(self, threatgraph_module):
        threatgraph_module.falcon.get_vertices_v2.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(threatgraph_module.threatgraph_get_vertices(ids=["pid:aaa:111"], vertex_type="process", scope="customer", nano=True))
        kwargs = threatgraph_module.falcon.get_vertices_v2.call_args.kwargs
        assert kwargs["ids"] == ["pid:aaa:111"]
        assert kwargs["vertex_type"] == "process"
        assert kwargs["scope"] == "customer"
        assert kwargs["nano"] is True

    def test_default_scope_is_device(self, threatgraph_module):
        threatgraph_module.falcon.get_vertices_v2.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(threatgraph_module.threatgraph_get_vertices(ids=["x"], vertex_type="process"))
        kwargs = threatgraph_module.falcon.get_vertices_v2.call_args.kwargs
        assert kwargs["scope"] == "device"

    def test_requires_ids(self, threatgraph_module):
        result = asyncio.run(threatgraph_module.threatgraph_get_vertices(ids=[], vertex_type="process"))
        assert "ids" in result.lower() or "required" in result.lower()

    def test_403_includes_scope_guidance(self, threatgraph_module):
        threatgraph_module.falcon.get_vertices_v2.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Forbidden"}]},
        }
        result = asyncio.run(threatgraph_module.threatgraph_get_vertices(ids=["pid:aaa:111"], vertex_type="process"))
        assert "threatgraph:read" in result


class TestThreatGraphGetEdges:
    def test_returns_edges(self, threatgraph_module):
        threatgraph_module.falcon.get_edges.return_value = {
            "status_code": 200,
            "body": {"resources": [{"source_vertex_id": "pid:aaa:111", "target_vertex_id": "pid:bbb:222"}]},
        }
        result = asyncio.run(threatgraph_module.threatgraph_get_edges(ids=["pid:aaa:111"], edge_type="wrote_file"))
        assert "pid:aaa:111" in result
        assert "pid:bbb:222" in result

    def test_passes_args_to_falconpy(self, threatgraph_module):
        threatgraph_module.falcon.get_edges.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(
            threatgraph_module.threatgraph_get_edges(
                ids=["x"],
                edge_type="wrote_file",
                direction="primary",
                scope="customer",
                limit=50,
                offset="tok",
                nano=True,
            )
        )
        kwargs = threatgraph_module.falcon.get_edges.call_args.kwargs
        assert kwargs["ids"] == ["x"]
        assert kwargs["edge_type"] == "wrote_file"
        assert kwargs["direction"] == "primary"
        assert kwargs["scope"] == "customer"
        assert kwargs["limit"] == 50
        assert kwargs["offset"] == "tok"
        assert kwargs["nano"] is True

    def test_default_limit_is_100(self, threatgraph_module):
        threatgraph_module.falcon.get_edges.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(threatgraph_module.threatgraph_get_edges(ids=["x"], edge_type="wrote_file"))
        kwargs = threatgraph_module.falcon.get_edges.call_args.kwargs
        assert kwargs["limit"] == 100

    def test_limit_above_1000_rejected_before_api_call(self, threatgraph_module):
        result = asyncio.run(threatgraph_module.threatgraph_get_edges(ids=["x"], edge_type="wrote_file", limit=1001))
        assert threatgraph_module.falcon.get_edges.call_count == 0
        assert "1000" in result or "limit" in result.lower()

    def test_direction_omitted_when_none(self, threatgraph_module):
        threatgraph_module.falcon.get_edges.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(threatgraph_module.threatgraph_get_edges(ids=["x"], edge_type="wrote_file"))
        kwargs = threatgraph_module.falcon.get_edges.call_args.kwargs
        assert "direction" not in kwargs

    def test_400_invalid_edge_type_appends_hint(self, threatgraph_module):
        threatgraph_module.falcon.get_edges.return_value = {
            "status_code": 400,
            "body": {"errors": [{"message": "invalid edge_type 'bogus'"}]},
        }
        result = asyncio.run(threatgraph_module.threatgraph_get_edges(ids=["x"], edge_type="bogus"))
        assert "threatgraph_get_edge_types" in result or "threatgraph-edge-types" in result


class TestThreatGraphGetRanOn:
    def test_returns_ran_on(self, threatgraph_module):
        threatgraph_module.falcon.get_ran_on.return_value = {
            "status_code": 200,
            "body": {"resources": [{"aid": "host-1", "id": "pid:host-1:123"}]},
        }
        result = asyncio.run(threatgraph_module.threatgraph_get_ran_on(value="1.2.3.4", type="ip_address"))
        assert "host-1" in result

    def test_passes_args_to_falconpy(self, threatgraph_module):
        threatgraph_module.falcon.get_ran_on.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(
            threatgraph_module.threatgraph_get_ran_on(
                value="abc123",
                type="hash_sha256",
                scope="customer",
                limit=50,
                offset="tok",
                nano=True,
            )
        )
        kwargs = threatgraph_module.falcon.get_ran_on.call_args.kwargs
        assert kwargs["value"] == "abc123"
        assert kwargs["type"] == "hash_sha256"
        assert kwargs["scope"] == "customer"
        assert kwargs["limit"] == 50
        assert kwargs["offset"] == "tok"
        assert kwargs["nano"] is True

    def test_default_limit_and_scope(self, threatgraph_module):
        threatgraph_module.falcon.get_ran_on.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(threatgraph_module.threatgraph_get_ran_on(value="x", type="domain"))
        kwargs = threatgraph_module.falcon.get_ran_on.call_args.kwargs
        assert kwargs["limit"] == 100
        assert kwargs["scope"] == "device"

    def test_limit_above_1000_rejected(self, threatgraph_module):
        result = asyncio.run(threatgraph_module.threatgraph_get_ran_on(value="x", type="domain", limit=2000))
        assert threatgraph_module.falcon.get_ran_on.call_count == 0
        assert "1000" in result or "limit" in result.lower()

    def test_requires_value(self, threatgraph_module):
        result = asyncio.run(threatgraph_module.threatgraph_get_ran_on(value="", type="domain"))
        assert "value" in result.lower() or "required" in result.lower()

    def test_requires_type(self, threatgraph_module):
        result = asyncio.run(threatgraph_module.threatgraph_get_ran_on(value="x", type=""))
        assert "type" in result.lower() or "required" in result.lower()


class TestThreatGraphGetSummary:
    def test_returns_summary(self, threatgraph_module):
        threatgraph_module.falcon.get_summary.return_value = {
            "status_code": 200,
            "body": {"resources": [{"id": "pid:aaa:111", "summary": "rclone.exe -> cloudflare.com"}]},
        }
        result = asyncio.run(threatgraph_module.threatgraph_get_summary(ids=["pid:aaa:111"], vertex_type="process"))
        assert "pid:aaa:111" in result
        assert "rclone.exe" in result

    def test_passes_args_to_falconpy(self, threatgraph_module):
        threatgraph_module.falcon.get_summary.return_value = {
            "status_code": 200,
            "body": {"resources": []},
        }
        asyncio.run(
            threatgraph_module.threatgraph_get_summary(
                ids=["x"],
                vertex_type="process",
                scope="customer",
                nano=True,
            )
        )
        kwargs = threatgraph_module.falcon.get_summary.call_args.kwargs
        assert kwargs["ids"] == ["x"]
        assert kwargs["vertex_type"] == "process"
        assert kwargs["scope"] == "customer"
        assert kwargs["nano"] is True

    def test_requires_ids(self, threatgraph_module):
        result = asyncio.run(threatgraph_module.threatgraph_get_summary(ids=[], vertex_type="process"))
        assert "ids" in result.lower() or "required" in result.lower()


class TestThreatGraphRegistrationSurface:
    def test_registers_exactly_five_tools_at_read_tier(self, threatgraph_module):
        server = MagicMock()
        server.tool.return_value = lambda fn: fn
        threatgraph_module.register_tools(server)
        expected = {
            "threatgraph_get_vertices",
            "threatgraph_get_edges",
            "threatgraph_get_ran_on",
            "threatgraph_get_summary",
            "threatgraph_get_edge_types",
        }
        assert set(threatgraph_module.tools) == expected

    def test_write_tools_not_registered_when_disabled(self, threatgraph_module):
        # ThreatGraph is read-only; this guards against accidentally adding a
        # write tool in the future without opting in explicitly.
        threatgraph_module.allow_writes = False
        server = MagicMock()
        server.tool.return_value = lambda fn: fn
        threatgraph_module.register_tools(server)
        # All tools remain read-tier; allow_writes flip must not add or drop any.
        assert len(threatgraph_module.tools) == 5
