"""Tests for get_stored_response silent-null bug fixes.

Covers three fixes:
  1. Metadata overview surfaces available fields (top-level + one level of nesting).
  2. All-null field extraction emits a warning with discovered top-level keys.
  3. Tool description notes field-path differences between alert_analysis and ngsiem_query.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock

import pytest

from crowdstrike_mcp.modules.response_store import ResponseStoreModule
from crowdstrike_mcp.response_store import ResponseStore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def module(mock_client):
    """Create ResponseStoreModule (no FalconPy services needed)."""
    return ResponseStoreModule(mock_client)


def _store_alert_analysis_shaped() -> str:
    """Store an alert_analysis-shaped record (nested under Ngsiem.event)."""
    data = {
        "records": [
            {
                "@timestamp": "2026-04-10T12:00:00Z",
                "source": {"ip": "10.1.75.3"},
                "user": {"name": "alice"},
                "Ngsiem": {
                    "event": {
                        "usernames": ["alice"],
                        "source_ips": ["10.1.75.3"],
                        "action": "login",
                    }
                },
            },
            {
                "@timestamp": "2026-04-10T12:05:00Z",
                "source": {"ip": "10.1.75.4"},
                "user": {"name": "bob"},
                "Ngsiem": {
                    "event": {
                        "usernames": ["bob"],
                        "source_ips": ["10.1.75.4"],
                        "action": "logout",
                    }
                },
            },
        ]
    }
    return ResponseStore.store(data, tool_name="alert_analysis", metadata={"detection_id": "ngsiem:abc"})


def _store_ngsiem_flat() -> str:
    """Store an ngsiem_query-shaped record (flat dotted keys)."""
    data = {
        "events": [
            {"source.ip": "10.1.75.3", "Vendor.userIdentity.arn": "arn:aws:iam::123:user/alice"},
            {"source.ip": "10.1.75.4", "Vendor.userIdentity.arn": "arn:aws:iam::123:user/bob"},
        ]
    }
    return ResponseStore.store(data, tool_name="ngsiem_query")


# ---------------------------------------------------------------------------
# Fix 1: Metadata overview surfaces available fields
# ---------------------------------------------------------------------------


class TestMetadataOverviewSurfacesFields:
    def test_metadata_includes_top_level_keys(self, module):
        ref_id = _store_alert_analysis_shaped()
        result = asyncio.run(module.get_stored_response(ref_id=ref_id))
        # Should mention top-level keys from the records
        for key in ("@timestamp", "source", "user", "Ngsiem"):
            assert key in result, f"Expected top-level key {key!r} in metadata overview; got: {result}"

    def test_metadata_includes_nested_subkeys(self, module):
        ref_id = _store_alert_analysis_shaped()
        result = asyncio.run(module.get_stored_response(ref_id=ref_id))
        # Should surface one level of nesting for dicts: e.g., source.ip, user.name, Ngsiem.event
        assert "source.ip" in result
        assert "user.name" in result
        assert "Ngsiem.event" in result

    def test_metadata_flat_dotted_keys_surface_as_is(self, module):
        ref_id = _store_ngsiem_flat()
        result = asyncio.run(module.get_stored_response(ref_id=ref_id))
        assert "source.ip" in result
        assert "Vendor.userIdentity.arn" in result

    def test_metadata_not_shown_when_filters_applied(self, module):
        """Schema hint only appears on unfiltered metadata calls."""
        ref_id = _store_ngsiem_flat()
        result = asyncio.run(module.get_stored_response(ref_id=ref_id, record_index=0))
        # Should be the record JSON, not a schema hint section
        parsed = json.loads(result)
        assert parsed["source.ip"] == "10.1.75.3"

    def test_metadata_dedupes_across_records(self, module):
        """Top-level keys should be unioned across all records without duplication."""
        data = {
            "records": [
                {"a": 1, "b": {"x": 1}},
                {"a": 2, "c": 3},
            ]
        }
        ref_id = ResponseStore.store(data, tool_name="test")
        result = asyncio.run(module.get_stored_response(ref_id=ref_id))
        # All top-level keys from any record should appear
        assert "a" in result
        assert "b" in result
        assert "c" in result
        # And nested sub-key for the dict-valued field
        assert "b.x" in result


# ---------------------------------------------------------------------------
# Fix 2: All-null field extraction returns warning with available keys
# ---------------------------------------------------------------------------


class TestAllNullFieldsWarning:
    def test_all_null_fields_returns_warning(self, module):
        """Requesting CQL-style field names against alert_analysis data returns warning."""
        ref_id = _store_alert_analysis_shaped()
        result = asyncio.run(module.get_stored_response(ref_id=ref_id, fields="Vendor.userIdentity.arn,event.action"))
        # Should contain a warning, not just a JSON list of nulls
        lowered = result.lower()
        assert "null" in lowered or "warning" in lowered or "all requested fields" in lowered

    def test_all_null_warning_lists_available_top_level_keys(self, module):
        ref_id = _store_alert_analysis_shaped()
        result = asyncio.run(module.get_stored_response(ref_id=ref_id, fields="Vendor.userIdentity.arn,event.action"))
        # Warning should include actual top-level keys from the stored data
        for key in ("@timestamp", "source", "user", "Ngsiem"):
            assert key in result, f"Expected top-level key {key!r} in warning; got: {result}"

    def test_mixed_hits_do_not_trigger_warning(self, module):
        """If at least one field resolves for at least one record, no warning."""
        ref_id = _store_alert_analysis_shaped()
        # source.ip exists (nested), bogus.field does not
        result = asyncio.run(module.get_stored_response(ref_id=ref_id, fields="source.ip,bogus.field"))
        # Should still be JSON output (parseable), not a warning string
        parsed = json.loads(result)
        assert isinstance(parsed, list)
        assert parsed[0]["source.ip"] == "10.1.75.3"
        assert parsed[0]["bogus.field"] is None

    def test_all_null_warning_preserves_data(self, module):
        """Warning should still expose the null data (not destroy it)."""
        ref_id = _store_alert_analysis_shaped()
        result = asyncio.run(module.get_stored_response(ref_id=ref_id, fields="Vendor.userIdentity.arn,event.action"))
        # The requested field names should still be visible to the caller somewhere
        assert "Vendor.userIdentity.arn" in result
        assert "event.action" in result

    def test_ngsiem_flat_keys_still_hit_properly(self, module):
        """Sanity: requesting flat dotted keys on ngsiem_query data works without warning."""
        ref_id = _store_ngsiem_flat()
        result = asyncio.run(module.get_stored_response(ref_id=ref_id, fields="source.ip,Vendor.userIdentity.arn"))
        parsed = json.loads(result)
        assert parsed[0]["source.ip"] == "10.1.75.3"
        assert parsed[0]["Vendor.userIdentity.arn"].startswith("arn:aws:")

    def test_all_null_warning_caps_wide_key_list(self, module):
        """A wide schema's top-level key list is capped like the search-miss message."""
        wide_record = {f"k_{i:03d}": i for i in range(60)}
        ref_id = ResponseStore.store({"records": [wide_record]}, tool_name="test")
        result = asyncio.run(module.get_stored_response(ref_id=ref_id, fields="nope1,nope2"))
        assert "(+20 more)" in result


# ---------------------------------------------------------------------------
# Fix 3: Tool description documents field path differences
# ---------------------------------------------------------------------------


class TestToolDescriptionDocumentsFieldPaths:
    def test_description_mentions_alert_analysis_vs_ngsiem_paths(self, mock_client):
        """register_tools should pass a description covering field-path differences."""
        module = ResponseStoreModule(mock_client)
        server = MagicMock()
        captured = {}

        def fake_tool(**kwargs):
            # Capture whichever tool registration we care about
            if kwargs.get("name") == "get_stored_response":
                captured["description"] = kwargs.get("description", "")

            def decorator(fn):
                return fn

            return decorator

        server.tool.side_effect = fake_tool
        module.register_tools(server)

        desc = captured.get("description", "")
        # Description should mention differing field paths between tools
        assert "alert_analysis" in desc
        assert "ngsiem_query" in desc

    def test_description_recommends_record_index_for_schema_discovery(self, mock_client):
        module = ResponseStoreModule(mock_client)
        server = MagicMock()
        captured = {}

        def fake_tool(**kwargs):
            if kwargs.get("name") == "get_stored_response":
                captured["description"] = kwargs.get("description", "")

            def decorator(fn):
                return fn

            return decorator

        server.tool.side_effect = fake_tool
        module.register_tools(server)

        desc = captured.get("description", "")
        assert "record_index" in desc
