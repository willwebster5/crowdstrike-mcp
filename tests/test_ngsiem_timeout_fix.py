"""Tests for NGSIEM alert_analysis timeout fix — deadline, cache, parallel queries, graceful fallback."""

import time as _time
from unittest.mock import MagicMock, patch

import pytest

from crowdstrike_mcp.modules.alerts import AlertsModule


@pytest.fixture
def alerts_module(mock_client):
    """AlertsModule with NGSIEM available and APIs mocked."""
    with patch("crowdstrike_mcp.modules.alerts.Alerts"), patch("crowdstrike_mcp.modules.alerts._NGSIEM_AVAILABLE", True):
        module = AlertsModule(mock_client)
        mock_ngsiem = MagicMock()
        module._service = lambda cls: mock_ngsiem
        module._mock_ngsiem = mock_ngsiem
        return module


class TestExecuteNgsiemQueryDeadline:
    """_execute_ngsiem_query respects the deadline param and returns timed_out on expiry."""

    def test_expired_deadline_returns_timed_out_without_polling(self, alerts_module):
        """An already-expired deadline aborts before the poll loop starts."""
        alerts_module._mock_ngsiem.start_search.return_value = {
            "status_code": 200,
            "resources": {"id": "search-1"},
        }
        # Return status as not-done so the poll loop would normally keep running
        alerts_module._mock_ngsiem.get_search_status.return_value = {
            "status_code": 200,
            "body": {"done": False},
        }
        # Deadline already in the past
        expired_deadline = _time.time() - 1.0
        result = alerts_module._execute_ngsiem_query("test query", "1d", 10, deadline=expired_deadline)
        assert result["success"] is False
        assert result.get("timed_out") is True
        # stop_search should have been called to clean up
        alerts_module._mock_ngsiem.stop_search.assert_called_once()

    def test_default_deadline_is_inf_existing_callers_unaffected(self, alerts_module):
        """Calling without deadline= still works — default is float('inf')."""
        alerts_module._mock_ngsiem.start_search.return_value = {
            "status_code": 200,
            "resources": {"id": "search-1"},
        }
        alerts_module._mock_ngsiem.get_search_status.return_value = {
            "status_code": 200,
            "body": {"done": True, "events": [{"field": "value"}]},
        }
        # No deadline arg — should succeed normally
        result = alerts_module._execute_ngsiem_query("SELECT 1", "1d", 5)
        assert result["success"] is True
        assert result["events_matched"] == 1

    def test_queries_executed_list_populated(self, alerts_module):
        """CQL string is appended to queries_executed before start_search."""
        alerts_module._mock_ngsiem.start_search.return_value = {
            "status_code": 200,
            "resources": {"id": "search-1"},
        }
        alerts_module._mock_ngsiem.get_search_status.return_value = {
            "status_code": 200,
            "body": {"done": True, "events": []},
        }
        queries_executed = []
        alerts_module._execute_ngsiem_query("my CQL query", "1d", 5, queries_executed=queries_executed)
        assert len(queries_executed) == 1
        assert "my CQL query" in queries_executed[0]

    def test_queries_executed_none_does_not_crash(self, alerts_module):
        """queries_executed=None (default) causes no crash."""
        alerts_module._mock_ngsiem.start_search.return_value = {
            "status_code": 200,
            "resources": {"id": "search-1"},
        }
        alerts_module._mock_ngsiem.get_search_status.return_value = {
            "status_code": 200,
            "body": {"done": True, "events": []},
        }
        # Should not raise
        result = alerts_module._execute_ngsiem_query("SELECT 1", "1d", 5)
        assert result["success"] is True


class TestNgsiemEventCache:
    """_ngsiem_event_cache is instance-level and only caches successes."""

    def test_cache_initialized_on_module(self, alerts_module):
        assert hasattr(alerts_module, "_ngsiem_event_cache")
        assert isinstance(alerts_module._ngsiem_event_cache, dict)
        assert len(alerts_module._ngsiem_event_cache) == 0

    def test_two_instances_have_separate_caches(self, mock_client):
        with patch("crowdstrike_mcp.modules.alerts.Alerts"), patch("crowdstrike_mcp.modules.alerts._NGSIEM_AVAILABLE", True):
            m1 = AlertsModule(mock_client)
            m2 = AlertsModule(mock_client)
            key = (m1._get_client_id(), "key", "1d")
            m1._ngsiem_event_cache[key] = {"success": True}
            assert key not in m2._ngsiem_event_cache

    def test_cache_key_scoped_by_client_id(self, mock_client):
        """Two AlertsModule instances backed by different credentials must not share a cache entry.

        The cache is keyed by (client_id, composite_id, time_range), not just
        (composite_id, time_range): in HTTP mode this module instance is shared
        across every session, so without client_id scoping a composite_id
        collision between two tenants could return one tenant's NGSIEM events
        to another tenant's alert_analysis call.
        """
        with patch("crowdstrike_mcp.modules.alerts.Alerts"), patch("crowdstrike_mcp.modules.alerts._NGSIEM_AVAILABLE", True):
            tenant_a = MagicMock()
            tenant_a.client_id = "tenant-a"
            tenant_b = MagicMock()
            tenant_b.client_id = "tenant-b"
            module = AlertsModule(tenant_a)

            cached_for_a = {"success": True, "events": [{"tenant": "a"}]}
            module._ngsiem_event_cache[(module._get_client_id(), "cust:ngsiem:cust:same-id", "1d")] = cached_for_a

            # Swap the module's active credentials to tenant B without a cache hit.
            module.client = tenant_b
            execute_called = []
            module._execute_ngsiem_query = lambda *a, **kw: execute_called.append(1) or {"success": False, "events_matched": 0}
            module._get_related_ngsiem_events("cust:ngsiem:cust:same-id", time_range="1d", max_events=5)
            assert len(execute_called) > 0, "tenant B must not get tenant A's cached result for a colliding composite_id"


class TestParallelIndicatorQueries:
    """All 3 indicator queries fire in parallel; first match wins."""

    def test_all_three_indicator_queries_submitted(self, alerts_module):
        """ThreadPoolExecutor receives all 3 indicator query strings."""
        submitted_queries = []

        def fake_execute(query, *args, **kwargs):
            submitted_queries.append(query)
            return {"success": False, "events_matched": 0}

        alerts_module._execute_ngsiem_query = fake_execute

        alerts_module._get_related_ngsiem_events(
            "cust:ngsiem:cust:indicator-uuid",
            time_range="1d",
            max_events=5,
            deadline=_time.time() + 30,
            queries_executed=[],
        )
        # All 3 indicator query strings should have been submitted
        assert len(submitted_queries) >= 3

    def test_cache_hit_skips_queries(self, alerts_module):
        """Second call with same (detection_id, time_range) returns cached result."""
        cached = {"success": True, "events": [{"field": "value"}], "events_matched": 1, "query_used": "q"}
        cache_key = (alerts_module._get_client_id(), "cust:ngsiem:cust:indicator-uuid", "1d")
        alerts_module._ngsiem_event_cache[cache_key] = cached

        execute_called = []
        alerts_module._execute_ngsiem_query = lambda *a, **kw: execute_called.append(1) or {"success": False}

        result = alerts_module._get_related_ngsiem_events("cust:ngsiem:cust:indicator-uuid", time_range="1d", max_events=5)
        assert result == cached
        assert len(execute_called) == 0  # no queries fired

    def test_successful_result_stored_in_cache(self, alerts_module):
        """A successful result is stored in the cache for future calls."""
        indicator_event = {"Ngsiem.detection.id": "det-123", "@timestamp": "2026-04-15T10:00:00Z"}

        call_count = [0]

        def fake_execute(query, *args, **kwargs):
            call_count[0] += 1
            if "indicator.id" in query or "Ngsiem.indicator" in query or "@id" in query:
                return {"success": True, "events_matched": 1, "events": [indicator_event]}
            if "det-123" in query:
                return {"success": True, "events_matched": 1, "events": [indicator_event]}
            return {"success": False, "events_matched": 0}

        alerts_module._execute_ngsiem_query = fake_execute

        result = alerts_module._get_related_ngsiem_events("cust:ngsiem:cust:indicator-uuid", time_range="1d", max_events=5)
        assert result.get("success") is True
        cache_key = (alerts_module._get_client_id(), "cust:ngsiem:cust:indicator-uuid", "1d")
        assert cache_key in alerts_module._ngsiem_event_cache

    def test_failed_result_not_cached(self, alerts_module):
        """A failed/timed-out result is not stored in cache."""
        alerts_module._execute_ngsiem_query = lambda *a, **kw: {"success": False, "events_matched": 0}

        alerts_module._get_related_ngsiem_events("cust:ngsiem:cust:no-match", time_range="1d", max_events=5)
        cache_key = (alerts_module._get_client_id(), "cust:ngsiem:cust:no-match", "1d")
        assert cache_key not in alerts_module._ngsiem_event_cache

    def test_futures_timeout_returns_failure_not_exception(self, alerts_module):
        """FuturesTimeoutError is caught — function returns a failure dict, no exception raised."""

        def slow_execute(query, *args, **kwargs):
            _time.sleep(0.05)
            return {"success": False, "events_matched": 0}

        alerts_module._execute_ngsiem_query = slow_execute

        # Use an already-expired deadline so as_completed timeout fires immediately
        result = alerts_module._get_related_ngsiem_events(
            "cust:ngsiem:cust:indicator-uuid",
            time_range="1d",
            max_events=5,
            deadline=_time.time() - 1,  # already expired
        )
        # Should return a failure dict, not raise
        assert result.get("success") is False


class TestAnalyzeAlertGracefulFallback:
    """_analyze_alert returns raw metadata + enrichment_note on timeout instead of raising."""

    def test_graceful_fallback_on_enrichment_failure(self, alerts_module):
        """When NGSIEM enrichment fails, result has enrichment_note and raw alert — no exception."""
        alerts_module._get_alert_details = MagicMock(
            return_value={
                "success": True,
                "alert": {
                    "composite_id": "cust:ngsiem:cust:indicator-uuid",
                    "name": "Test Detection",
                },
            }
        )
        alerts_module._get_related_ngsiem_events = MagicMock(
            return_value={
                "success": False,
                "timed_out": True,
                "error": "Deadline exceeded",
            }
        )

        result = alerts_module._analyze_alert("cust:ngsiem:cust:indicator-uuid", max_events=5)
        assert result["success"] is True
        assert result["events"] is None
        assert result["enrichment_note"] is not None
        assert "timed out" in result["enrichment_note"].lower() or "failed" in result["enrichment_note"].lower()
        assert result["alert"]["name"] == "Test Detection"

    def test_queries_executed_attached_to_result(self, alerts_module):
        """ngsiem_queries_executed is always attached to result for ngsiem alerts."""
        alerts_module._get_alert_details = MagicMock(
            return_value={
                "success": True,
                "alert": {"composite_id": "cust:ngsiem:cust:indicator-uuid"},
            }
        )

        def fake_enrichment(*args, **kwargs):
            qe = kwargs.get("queries_executed")
            if qe is not None:
                qe.append('// MCP Query\nNgsiem.indicator.id = "indicator-uuid"')
            return {"success": False, "error": "no match"}

        alerts_module._get_related_ngsiem_events = fake_enrichment

        result = alerts_module._analyze_alert("cust:ngsiem:cust:indicator-uuid", max_events=5)
        assert "ngsiem_queries_executed" in result
        assert isinstance(result["ngsiem_queries_executed"], list)

    def test_non_ngsiem_alert_has_no_queries_executed(self, alerts_module):
        """endpoint alerts don't populate ngsiem_queries_executed."""
        alerts_module._get_alert_details = MagicMock(
            return_value={
                "success": True,
                "alert": {
                    "composite_id": "cust:thirdparty:cust:alert-id",
                },
            }
        )
        result = alerts_module._analyze_alert("cust:thirdparty:cust:alert-id", max_events=5)
        # thirdparty alerts don't call NGSIEM enrichment — no queries_executed key expected
        assert result.get("ngsiem_queries_executed") is None or result.get("ngsiem_queries_executed") == []

    def test_deadline_is_45_seconds_from_now(self, alerts_module):
        """The deadline passed to _get_related_ngsiem_events is approximately now + 45s."""
        received_deadline = []

        alerts_module._get_alert_details = MagicMock(
            return_value={
                "success": True,
                "alert": {"composite_id": "cust:ngsiem:cust:indicator-uuid"},
            }
        )

        def capture_deadline(*args, **kwargs):
            received_deadline.append(kwargs.get("deadline"))
            return {"success": False, "error": "no match"}

        alerts_module._get_related_ngsiem_events = capture_deadline

        before = _time.time()
        alerts_module._analyze_alert("cust:ngsiem:cust:indicator-uuid", max_events=5)
        after = _time.time()

        assert len(received_deadline) == 1
        deadline = received_deadline[0]
        assert before + 44 <= deadline <= after + 46
