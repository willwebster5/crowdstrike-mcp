"""
Alerts Module — unified alert retrieval and analysis across all detection types.

Tools:
  get_alerts             — Retrieve alerts across all detection types with filtering
  alert_analysis         — Deep-dive alert analysis with type-specific enrichment
  ngsiem_alert_analysis  — Alias for alert_analysis (backward compat)
  update_alert_status    — Update alert status, comments, tags, and user assignment

Cross-module dependency: AlertsModule creates its own NGSIEM service
instance using ``self.client.auth_object`` instead of depending on other modules.
They all share the same OAuth2 token.
"""

from __future__ import annotations

import asyncio
import json
import time as _time
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeoutError
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Annotated, Optional

from falconpy import Alerts

from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.utils import (
    PRODUCT_FQL_MAP,
    extract_detection_id,
    format_text_response,
    parse_composite_id,
    sanitize_input,
)

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

# Optional imports for cross-module enrichment
try:
    from falconpy import NGSIEM

    _NGSIEM_AVAILABLE = True
except ImportError:
    _NGSIEM_AVAILABLE = False


class AlertsModule(BaseModule):
    """Alert retrieval, analysis, and status management across all detection types."""

    def __init__(self, client):
        super().__init__(client)
        self._ngsiem_event_cache: dict[tuple[str, str], dict] = {}
        self._log("Initialized")

    def register_resources(self, server: FastMCP) -> None:
        from crowdstrike_mcp.resources.fql_guides import ALERT_FQL

        def _alert_fql():
            return ALERT_FQL

        server.resource(
            "falcon://fql/alerts",
            name="Alert FQL Syntax Guide",
            description="Documentation: Alert FQL filter syntax",
        )(_alert_fql)
        self.resources.append("falcon://fql/alerts")

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.get_alerts,
            name="get_alerts",
            description=(
                "Retrieve CrowdStrike alerts across ALL detection types (endpoint, NGSIEM, cloud security, identity, third-party) with filtering"
            ),
        )
        self._add_tool(
            server,
            self.alert_analysis,
            name="alert_analysis",
            description=(
                "Retrieve detailed alert metadata and type-specific enrichment "
                "by composite detection ID. Supports endpoint (ind), NGSIEM (ngsiem), "
                "cloud security (fcs), identity (ldt), and third-party (thirdparty) detections."
            ),
        )
        self._add_tool(
            server,
            self.alert_analysis,
            name="ngsiem_alert_analysis",
            description=("[ALIAS for alert_analysis] Retrieve detailed alert metadata and related security events by composite detection ID."),
        )
        self._add_tool(
            server,
            self.update_alert_status,
            name="update_alert_status",
            description=(
                "Update CrowdStrike alert status after triage/investigation. Supports status changes, "
                "comments for audit trail, tags, and assigning/unassigning a user (by user ID / email). "
                "Status is optional, so the tool can reassign without changing status."
            ),
            tier="write",
        )

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    async def get_alerts(
        self,
        severity: Annotated[str, "Minimum severity level"] = "ALL",
        time_range: Annotated[str, "Time range (e.g. '1h', '6h', '12h', '1d', '7d', '30d')"] = "1d",
        status: Annotated[str, "Filter by alert status"] = "all",
        pattern_name: Annotated[Optional[str], "Wildcard match on detection/alert name (server-side FQL)"] = None,
        product: Annotated[str, "Filter by detection source/product type"] = "all",
        max_results: Annotated[int, "Maximum alerts to return (default: 50, max: 1000)"] = 50,
        offset: Annotated[int, "Number of alerts to skip for pagination (default: 0)"] = 0,
        q: Annotated[Optional[str], "Free-text search across all alert metadata"] = None,
        summary_mode: Annotated[bool, "Return compact key-fields only (default: false)"] = False,
    ) -> str:
        """Retrieve alerts with flexible filtering across all detection types."""
        result = self._get_alerts(
            severity=severity,
            time_range=time_range,
            status=status,
            pattern_name=pattern_name,
            product=product,
            max_results=max_results,
            offset=offset,
            q=q,
        )

        if not result.get("success"):
            return format_text_response(
                f"Failed to retrieve alerts: {result.get('error')}",
                raw=True,
            )

        alerts_list = result["alerts"]
        lines = [
            f"Alerts Retrieved: {result['count']} (of {result['total_available']} total)",
            f"Filter: severity={severity}, time_range={time_range}, status={status}, product={product}",
        ]
        if pattern_name:
            lines.append(f"Pattern: {pattern_name}")
        if q:
            lines.append(f"Search: {q}")
        if result.get("offset", 0) > 0 or result.get("next_offset") is not None:
            lines.append(f"Offset: {result.get('offset', 0)} | Next: {result.get('next_offset', 'None')}")
        lines.append("")

        if not alerts_list:
            lines.append("No alerts found matching the filters.")
        else:
            for i, a in enumerate(alerts_list, 1):
                if summary_mode:
                    lines.append(f"{i}. [{a['severity']}] {a['name']} ({a.get('product_name', '')}) status={a['status']}")
                    lines.append(f"   ID: {a['composite_id']}")
                    tactic = a.get("tactic") or ""
                    technique = a.get("technique") or ""
                    if tactic or technique:
                        lines.append(f"   MITRE: {tactic} / {technique}")
                    hosts = a.get("host_names")
                    users = a.get("user_names")
                    if hosts:
                        lines.append(f"   Hosts: {', '.join(hosts)}")
                    if users:
                        lines.append(f"   Users: {', '.join(users)}")
                    lines.append("")
                else:
                    tags_str = f" [{', '.join(a['tags'])}]" if a.get("tags") else ""
                    assigned = f" -> {a['assigned_to']}" if a.get("assigned_to") else ""
                    product_tag = f" ({a['product_name']})" if a.get("product_name") else ""
                    lines.append(f"{i}. [{a['severity']}] {a['name']}{product_tag} (status: {a['status']}{assigned}{tags_str})")
                    lines.append(f"   ID: {a['composite_id']}")
                    lines.append(f"   Created: {a['created_timestamp']}")
                    if a.get("description"):
                        lines.append(f"   Description: {a['description']}")
                    lines.append("")

        return format_text_response(
            "\n".join(lines),
            tool_name="get_alerts",
            raw=True,
            structured_data=result,
            metadata={"filter": result.get("filter"), "q": q, "time_range": time_range},
        )

    async def alert_analysis(
        self,
        detection_id: Annotated[str, "The composite detection ID to analyze"],
        max_events: Annotated[int, "Maximum related events to retrieve (for NGSIEM)"] = 10,
        summary_mode: Annotated[bool, "Return compact key-fields only (default: false)"] = False,
    ) -> str:
        """Analyze an alert with type-specific enrichment."""
        detection_id = extract_detection_id(detection_id)
        result = await asyncio.to_thread(self._analyze_alert, detection_id, max_events)

        if not result.get("success"):
            return format_text_response(
                f"Failed to analyze alert: {result.get('error', 'Unknown error')}",
                raw=True,
            )

        response_text = self._format_alert_analysis_response(result, summary_mode=summary_mode)
        return format_text_response(
            response_text,
            tool_name="alert_analysis",
            raw=True,
            structured_data=result,
            metadata={
                "detection_id": detection_id,
                "triggering_pid": result.get("triggering_pid"),
            },
        )

    async def update_alert_status(
        self,
        composite_ids: Annotated[list[str], "List of composite alert IDs to update"],
        status: Annotated[Optional[str], "New alert status ('new', 'in_progress', 'closed', 'reopened'). Optional — omit to leave unchanged."] = None,
        comment: Annotated[Optional[str], "Comment for audit trail"] = None,
        tags: Annotated[Optional[list[str]], "Tags to add"] = None,
        assign_to_user_id: Annotated[Optional[str], "User ID / email to assign the alert to, e.g. 'analyst@example.com'"] = None,
        unassign: Annotated[bool, "Clear the current assignee. Mutually exclusive with assign_to_user_id."] = False,
    ) -> str:
        """Update alert status, comments, tags, and assignment."""
        cleaned_ids = [extract_detection_id(cid) for cid in composite_ids]
        result = self._update_alert_status(cleaned_ids, status, comment, tags, assign_to_user_id, unassign)

        if not result.get("success"):
            return format_text_response(
                f"Failed to update alerts: {result.get('error')}",
                raw=True,
            )

        lines = [f"Successfully updated {result['updated_count']} alert(s)"]
        if result.get("new_status"):
            lines.append(f"New status: {result['new_status']}")
        if result.get("comment_added"):
            lines.append(f"Comment added: {comment}")
        if result.get("tags_added"):
            lines.append(f"Tags added: {', '.join(result['tags_added'])}")
        if result.get("assigned_to"):
            lines.append(f"Assigned to: {result['assigned_to']}")
        if result.get("unassigned"):
            lines.append("Unassigned")
        if result.get("spurious_500_verified"):
            # Issue #21: CrowdStrike's update_alerts_v3 returns a bogus HTTP 500
            # for product=thirdparty IDs even though the write is applied.
            lines.append(
                "Note: CrowdStrike returned a spurious HTTP 500 for thirdparty alert(s); the update was verified applied by re-fetching (issue #21)."
            )

        return format_text_response("\n".join(lines), raw=True)

    # ------------------------------------------------------------------
    # Internal methods (logic from handlers/alerts.py)
    # ------------------------------------------------------------------

    def _get_alert_details(self, detection_id):
        try:
            alerts = self._service(Alerts)
            response = alerts.get_alerts_v2(composite_ids=[detection_id])
            if response["status_code"] != 200:
                return {"success": False, "error": format_api_error(response, "Failed to get alert", operation="get_alerts_v2")}
            resources = response.get("body", {}).get("resources", [])
            if not resources:
                return {"success": False, "error": f"Alert not found: {detection_id}"}
            return {"success": True, "alert": resources[0]}
        except Exception as e:
            return {"success": False, "error": f"Error retrieving alert: {str(e)}"}

    # Alerts v2 API severity uses 10/20/30/40/50, not 1-5.
    _SEVERITY_MAP = {
        "CRITICAL": 50,
        "HIGH": 40,
        "MEDIUM": 30,
        "LOW": 20,
        "INFORMATIONAL": 10,
    }

    def _get_alerts(self, severity="ALL", time_range="1d", status="all", pattern_name=None, product="all", max_results=50, offset=0, q=None):
        try:
            alerts = self._service(Alerts)
            # Input validation
            max_results = min(max(max_results, 1), 1000)
            offset = max(offset, 0)
            if q is not None and not q.strip():
                q = None

            time_units = {"h": "hours", "d": "days"}
            unit = time_range[-1]
            value = int(time_range[:-1])
            if unit not in time_units:
                return {"success": False, "error": f"Invalid time_range unit: {unit}. Use 'h' or 'd'."}

            start_dt = datetime.now() - timedelta(**{time_units[unit]: value})
            date_from = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

            filter_parts = [f"created_timestamp:>='{date_from}'"]

            if severity.upper() != "ALL":
                sev_value = self._SEVERITY_MAP.get(severity.upper())
                if sev_value is not None:
                    filter_parts.append(f"severity:>={sev_value}")

            if status.lower() != "all":
                filter_parts.append(f"status:'{status.lower()}'")

            # Server-side name filtering via FQL wildcard (case-insensitive)
            if pattern_name:
                sanitized = sanitize_input(pattern_name)
                sanitized = sanitized.replace("'", "")
                filter_parts.append(f"name:~*'*{sanitized}*'")

            if product.lower() != "all":
                fql_values = PRODUCT_FQL_MAP.get(product.lower())
                if fql_values:
                    product_list = ",".join(f"'{v}'" for v in fql_values)
                    filter_parts.append(f"product:[{product_list}]")

            filter_query = "+".join(filter_parts)

            fetch_limit = min(max_results, 1000)

            query_kwargs = {
                "filter": filter_query,
                "limit": fetch_limit,
                "offset": offset,
                "sort": "created_timestamp.desc",
            }
            if q:
                query_kwargs["q"] = q

            response = alerts.query_alerts_v2(**query_kwargs)

            if response["status_code"] != 200:
                return {"success": False, "error": format_api_error(response, "Failed to query alerts", operation="query_alerts_v2")}

            alert_ids = response.get("body", {}).get("resources", [])
            total_available = response.get("body", {}).get("meta", {}).get("pagination", {}).get("total", len(alert_ids))

            if not alert_ids:
                return {
                    "success": True,
                    "alerts": [],
                    "count": 0,
                    "total_available": total_available,
                    "offset": offset,
                    "next_offset": None,
                    "filter": filter_query,
                    "q": q,
                    "time_range": time_range,
                }

            details_response = alerts.get_alerts_v2(composite_ids=alert_ids)
            if details_response["status_code"] != 200:
                return {"success": False, "error": format_api_error(details_response, "Failed to get alert details", operation="get_alerts_v2")}

            alerts_data = details_response.get("body", {}).get("resources", [])

            alert_summaries = []
            for a in alerts_data:
                composite_id = a.get("composite_id", "")
                id_info = parse_composite_id(composite_id)

                raw_product = a.get("product", {})
                if isinstance(raw_product, dict):
                    api_product_name = raw_product.get("name", "")
                else:
                    api_product_name = str(raw_product) if raw_product else ""

                summary = {
                    "composite_id": composite_id,
                    "name": a.get("name", "Unknown"),
                    "severity": a.get("severity_name", "Unknown"),
                    "severity_value": a.get("severity", 0),
                    "status": a.get("status", "unknown"),
                    "created_timestamp": a.get("created_timestamp", ""),
                    "updated_timestamp": a.get("updated_timestamp", ""),
                    "assigned_to": a.get("assigned_to_name", ""),
                    "type": a.get("type", ""),
                    "product": id_info["product_type"],
                    "product_name": id_info["product_name"],
                    "api_product": api_product_name,
                    "tags": a.get("tags", []),
                    "description": a.get("description", "")[:200],
                    "tactic": a.get("tactic"),
                    "technique": a.get("technique"),
                    "host_names": a.get("host_names"),
                    "user_names": a.get("user_names"),
                }
                alert_summaries.append(summary)

            count = len(alert_summaries)
            next_offset = offset + count if (offset + count) < total_available else None

            return {
                "success": True,
                "alerts": alert_summaries,
                "count": count,
                "total_available": total_available,
                "offset": offset,
                "next_offset": next_offset,
                "filter": filter_query,
                "q": q,
                "time_range": time_range,
            }
        except Exception as e:
            return {"success": False, "error": f"Error retrieving alerts: {str(e)}"}

    def _update_alert_status(self, composite_ids, status=None, comment=None, tags=None, assign_to_user_id=None, unassign=False):
        try:
            alerts = self._service(Alerts)

            if assign_to_user_id and unassign:
                return {"success": False, "error": "assign_to_user_id and unassign are mutually exclusive; provide only one."}

            if not any([status, comment, tags, assign_to_user_id, unassign]):
                return {"success": False, "error": "No action provided: supply at least one of status, comment, tags, assign_to_user_id, or unassign."}

            action_params = []
            if status:
                valid_statuses = ["new", "in_progress", "closed", "reopened"]
                if status.lower() not in valid_statuses:
                    return {"success": False, "error": f"Invalid status: {status}. Must be one of: {valid_statuses}"}
                action_params.append({"name": "update_status", "value": status.lower()})
            if comment:
                action_params.append({"name": "append_comment", "value": comment})
            if tags:
                action_params.extend({"name": "add_tag", "value": tag} for tag in tags)
            if assign_to_user_id:
                action_params.append({"name": "assign_to_user_id", "value": assign_to_user_id})
            elif unassign:
                # CrowdStrike API: the value passed to `unassign` is ignored.
                action_params.append({"name": "unassign", "value": ""})

            response = alerts.update_alerts_v3(
                composite_ids=composite_ids,
                action_parameters=action_params,
            )

            spurious_500_verified = False
            if response["status_code"] != 200:
                # Issue #21: CrowdStrike's update_alerts_v3 returns a spurious
                # HTTP 500 for product=thirdparty composite IDs even though the
                # write is applied. Verify by re-fetching; treat a confirmed
                # status change as success. Scoped to all-thirdparty batches so
                # genuine errors for other products are never masked.
                if (
                    response["status_code"] == 500
                    and status
                    and composite_ids
                    and all(parse_composite_id(c)["product_type"] == "thirdparty" for c in composite_ids)
                    and self._verify_status_applied(alerts, composite_ids, status.lower())
                ):
                    spurious_500_verified = True
                else:
                    return {"success": False, "error": format_api_error(response, "Failed to update alerts", operation="update_alerts_v3")}

            return {
                "success": True,
                "updated_count": len(composite_ids),
                "new_status": status.lower() if status else None,
                "comment_added": comment is not None,
                "tags_added": tags or [],
                "assigned_to": assign_to_user_id,
                "unassigned": bool(unassign),
                "spurious_500_verified": spurious_500_verified,
            }
        except Exception as e:
            return {"success": False, "error": f"Error updating alerts: {str(e)}"}

    def _verify_status_applied(self, alerts, composite_ids, expected_status) -> bool:
        """Re-fetch the alerts and confirm every one reached ``expected_status``.

        Used to disambiguate CrowdStrike's spurious HTTP 500 on thirdparty
        updates (issue #21) from a genuine failure.
        """
        try:
            resp = alerts.get_alerts_v2(composite_ids=composite_ids)
            if resp.get("status_code") != 200:
                return False
            resources = resp.get("body", {}).get("resources", [])
            if len(resources) != len(composite_ids):
                return False
            return all(r.get("status") == expected_status for r in resources)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Multi-type alert analysis with enrichment routing
    # ------------------------------------------------------------------

    def _get_ngsiem_service(self):
        """Try to create an NGSIEM service instance. Returns None if unavailable."""
        if not _NGSIEM_AVAILABLE:
            return None
        try:
            return self._service(NGSIEM)
        except Exception as e:
            self._log(f"NGSIEM enrichment not available: {e}")
            return None

    def _get_related_ngsiem_events(
        self,
        composite_id,
        time_range="1d",
        max_events=10,
        deadline=float("inf"),
        queries_executed=None,
    ):
        """Get events related to an NGSIEM alert using CQL queries.

        Runs 3 indicator queries in parallel. Takes the first match. Falls back to
        failure dict if all queries fail or the deadline expires.
        """
        if not _NGSIEM_AVAILABLE:
            return {"success": False, "error": "NGSIEM enrichment not available"}

        # Cache check — avoid re-querying the same alert in a session
        cache_key = (composite_id, time_range)
        if cache_key in self._ngsiem_event_cache:
            return self._ngsiem_event_cache[cache_key]

        try:
            parts = composite_id.split(":")
            indicator_id = parts[-1] if len(parts) >= 4 else composite_id

            indicator_queries = [
                f'Ngsiem.indicator.id = "{indicator_id}"',
                f'@id = "{indicator_id}"',
                f'indicator.id = "{indicator_id}"',
            ]

            # Phase 1: Run all 3 indicator queries in parallel
            remaining = max(0.0, deadline - _time.time())
            indicator_event = None
            detection_id_from_event = None

            executor = ThreadPoolExecutor(max_workers=3)
            futures = {executor.submit(self._execute_ngsiem_query, q, time_range, 1, deadline, queries_executed): q for q in indicator_queries}
            try:
                for future in as_completed(futures, timeout=remaining):
                    result = future.result()
                    if result.get("success") and result.get("events_matched", 0) > 0:
                        events = result.get("events", [])
                        if events:
                            indicator_event = events[0]
                            detection_id_from_event = indicator_event.get("Ngsiem.detection.id") or indicator_event.get("detection.id")
                            break
            except FuturesTimeoutError:
                pass
            finally:
                executor.shutdown(wait=False)  # threads self-abort via deadline check

            if not detection_id_from_event:
                return {
                    "success": False,
                    "error": f"Could not find indicator event or extract detection ID. Tried queries: {indicator_queries}",
                    "events_matched": 0,
                }

            # Phase 2: Detection queries (sequential, within same deadline)
            detection_queries = [
                f'Ngsiem.detection.id = "{detection_id_from_event}"',
                f'detection.id = "{detection_id_from_event}"',
            ]

            for query in detection_queries:
                result = self._execute_ngsiem_query(query, time_range, max_events, deadline, queries_executed)
                if result.get("success") and result.get("events_matched", 0) > 0:
                    success_result = {
                        "success": True,
                        "events": result.get("events", []),
                        "events_matched": result.get("events_matched", 0),
                        "detection_id_used": detection_id_from_event,
                        "query_used": query,
                    }
                    self._ngsiem_event_cache[cache_key] = success_result
                    return success_result

            if indicator_event:
                success_result = {
                    "success": True,
                    "events": [indicator_event],
                    "events_matched": 1,
                    "detection_id_used": detection_id_from_event,
                    "note": "Only found the indicator event, no additional related events",
                }
                self._ngsiem_event_cache[cache_key] = success_result
                return success_result

            return {
                "success": False,
                "error": f"Found detection ID {detection_id_from_event} but no related events.",
                "events_matched": 0,
            }
        except Exception as e:
            return {"success": False, "error": f"Error getting related events: {str(e)}"}

    def _execute_ngsiem_query(
        self,
        query,
        start_time="1d",
        max_results=10,
        deadline=float("inf"),
        queries_executed=None,
    ):
        """Execute a CQL query using the NGSIEM service.

        Supports a caller-supplied ``deadline`` (epoch seconds) that triggers an
        early abort before the normal 60s timeout. When provided, ``queries_executed``
        receives the timestamped CQL string for debug inspection.
        """
        ngsiem = self._get_ngsiem_service()
        if not ngsiem:
            return {"success": False, "error": "NGSIEM enrichment not available"}

        timestamped_query = f"// MCP Query - {datetime.now().isoformat()}\n{query}"

        if queries_executed is not None:
            queries_executed.append(timestamped_query)

        try:
            response = ngsiem.start_search(
                repository="search-all",
                query_string=timestamped_query,
                start=start_time,
                is_live=False,
            )

            if response["status_code"] != 200:
                return {"success": False, "error": f"Search start failed: HTTP {response['status_code']}"}

            search_id = response.get("resources", {}).get("id")

            start = _time.time()
            timeout = 60

            while _time.time() - start < timeout:
                # Check caller-supplied deadline first (fires before 60s for NGSIEM alerts)
                if _time.time() >= deadline:
                    ngsiem.stop_search(repository="search-all", id=search_id)
                    return {"success": False, "timed_out": True, "error": "Deadline exceeded"}

                status_response = ngsiem.get_search_status(
                    repository="search-all",
                    search_id=search_id,
                )

                if status_response["status_code"] != 200:
                    return {"success": False, "error": f"Status check failed: HTTP {status_response['status_code']}"}

                body = status_response.get("body", {})
                done = body.get("done", False)
                cancelled = body.get("cancelled", False)

                if done or cancelled:
                    events = body.get("events", [])
                    events_matched = len(events)
                    if len(events) > max_results:
                        events = events[:max_results]
                    return {
                        "success": True,
                        "events_matched": events_matched,
                        "events_returned": len(events),
                        "events": events,
                    }

                if body.get("state") == "error":
                    return {"success": False, "error": f"Search error: {body.get('messages', [])}"}

                _time.sleep(2)

            ngsiem.stop_search(repository="search-all", id=search_id)
            return {"success": False, "error": f"Query timed out after {timeout} seconds"}

        except Exception as e:
            return {"success": False, "error": f"Query execution error: {str(e)}"}

    def _get_behaviors_for_alert(self, alert):
        """Get endpoint context via NGSIEM raw telemetry (replaces deprecated Detects API).

        The Detects API was decommissioned in March 2026. This method now queries
        NGSIEM for raw EDR events (ProcessRollup2) around the alert's device.
        """
        ngsiem = self._get_ngsiem_service()
        if not ngsiem:
            return {"success": False, "error": "NGSIEM enrichment not available — cannot enrich endpoint alert"}

        device_id = alert.get("device", {}).get("device_id", "")
        if not device_id:
            return {"success": False, "error": "No device_id in alert — cannot query endpoint telemetry"}

        query = f'#event_simpleName=ProcessRollup2 aid="{device_id}" | head(20)'

        try:
            result = self._execute_ngsiem_query(query, start_time="24h", max_results=20)
            if not result.get("success"):
                return {
                    "success": False,
                    "error": f"NGSIEM endpoint enrichment failed: {result.get('error', 'Unknown')}",
                }

            events = result.get("events", [])
            return {"success": True, "behaviors": events}
        except Exception as e:
            return {"success": False, "error": f"NGSIEM endpoint enrichment error: {str(e)}"}

    def _analyze_alert(self, detection_id, max_events=10):
        """Analyze an alert with type-specific enrichment routing."""
        alert_result = self._get_alert_details(detection_id)
        if not alert_result.get("success"):
            return alert_result

        alert = alert_result["alert"]
        id_info = parse_composite_id(detection_id)
        product_type = id_info["product_type"]
        product_name = id_info["product_name"]

        result = {
            "success": True,
            "alert": alert,
            "product_type": product_type,
            "product_name": product_name,
            "enrichment_type": None,
            "events": None,
            "behaviors": None,
            "enrichment_note": None,
            "triggering_pid": None,  # populated for endpoint alerts only
            "triggering_record_index": None,
            "triggering_process": None,
        }

        if product_type == "ngsiem" and _NGSIEM_AVAILABLE:
            result["enrichment_type"] = "ngsiem_events"
            deadline = _time.time() + 45
            queries_executed: list[str] = []
            events_result = self._get_related_ngsiem_events(
                detection_id,
                time_range="7d",
                max_events=max_events,
                deadline=deadline,
                queries_executed=queries_executed,
            )
            result["ngsiem_queries_executed"] = queries_executed
            if not events_result.get("success"):
                result["enrichment_note"] = (
                    "NGSIEM enrichment timed out or failed. Raw alert metadata returned. "
                    "Query directly via ngsiem_query with the indicator ID as a filter. "
                    f"Queries attempted: {len(queries_executed)}"
                )
                result["events"] = None
            else:
                result["events"] = events_result.get("events", [])
                result["events_matched"] = events_result.get("events_matched", 0)
                result["query_used"] = events_result.get("query_used", "")

        elif product_type == "cloud_security":
            result["enrichment_type"] = "cloud_security_raw"
            result["enrichment_note"] = (
                "Cloud security alert — full raw alert payload included for inspection. Automated cloud event enrichment will be added in a future update."
            )

        elif product_type == "endpoint":
            result["enrichment_type"] = "endpoint_behaviors"
            result["triggering_pid"] = id_info.get("target_process_id")
            result["triggering_record_index"] = None
            result["triggering_process"] = None
            try:
                behaviors_result = self._get_behaviors_for_alert(alert)
                if behaviors_result.get("success"):
                    behaviors = behaviors_result.get("behaviors", [])
                    # Sort by @timestamp ascending (chronological); None-safe key
                    behaviors.sort(key=lambda e: e.get("@timestamp") or "")
                    result["behaviors"] = behaviors
                    # Find the triggering record by TargetProcessId
                    target_pid = id_info.get("target_process_id")
                    if target_pid:
                        for idx, record in enumerate(behaviors):
                            if str(record.get("TargetProcessId", "")) == target_pid:
                                result["triggering_record_index"] = idx
                                result["triggering_process"] = {
                                    "ImageFileName": record.get("ImageFileName"),
                                    "CommandLine": record.get("CommandLine"),
                                    "TargetProcessId": record.get("TargetProcessId"),
                                    "record_index": idx,
                                }
                                break
                else:
                    result["enrichment_note"] = f"Endpoint behavior retrieval failed: {behaviors_result.get('error', 'Unknown')}"
            except Exception as e:
                result["enrichment_note"] = f"Endpoint enrichment error: {str(e)}"

        elif product_type == "identity":
            result["enrichment_type"] = "identity_metadata_only"
            result["enrichment_note"] = "Identity Protection alert — enrichment via GraphQL API planned for future update."

        elif product_type == "thirdparty":
            result["enrichment_type"] = "thirdparty_metadata_only"
            result["enrichment_note"] = (
                "Third-party integration alert — generated by an external connector "
                "(e.g., EntraID, Cato VPN, or other third-party source). "
                "These alerts are NOT tunable within CrowdStrike NGSIEM; "
                "tuning must be done in the originating third-party platform."
            )

        else:
            result["enrichment_type"] = "metadata_only"
            result["enrichment_note"] = f"Unknown product type '{id_info['product_prefix']}' — returning alert metadata only."

        return result

    def _format_alert_analysis_response(self, analysis, summary_mode=False):
        """Format the analyze_alert result into a readable text response."""
        alert = analysis["alert"]

        if summary_mode:
            return self._format_alert_analysis_summary(analysis)

        parts = []

        parts.append(f"## Alert Analysis ({analysis['product_name']})")
        parts.append("")

        parts.append("### Alert Metadata")
        parts.append(f"- **Name**: {alert.get('name', 'Unknown')}")
        parts.append(f"- **Composite ID**: {alert.get('composite_id', 'N/A')}")
        parts.append(f"- **Severity**: {alert.get('severity_name', 'Unknown')} ({alert.get('severity', 'N/A')})")
        parts.append(f"- **Status**: {alert.get('status', 'unknown')}")
        parts.append(f"- **Type**: {alert.get('type', 'N/A')}")
        parts.append(f"- **Product Type**: {analysis['product_name']} (`{analysis['product_type']}`)")

        raw_product = alert.get("product", {})
        if isinstance(raw_product, dict):
            api_product = raw_product.get("name", "N/A")
        else:
            api_product = str(raw_product) if raw_product else "N/A"
        parts.append(f"- **API Product**: {api_product}")

        pattern = alert.get("pattern", {})
        if isinstance(pattern, dict) and pattern:
            parts.append(f"- **Pattern**: {pattern.get('name', 'N/A')} (ID: {pattern.get('id', 'N/A')})")

        parts.append(f"- **Created**: {alert.get('created_timestamp', 'N/A')}")
        parts.append(f"- **Updated**: {alert.get('updated_timestamp', 'N/A')}")

        description = alert.get("description", "")
        if description:
            parts.append(f"- **Description**: {description}")

        tags = alert.get("tags", [])
        if tags:
            parts.append(f"- **Tags**: {', '.join(tags)}")

        assigned = alert.get("assigned_to_name", "")
        if assigned:
            parts.append(f"- **Assigned To**: {assigned}")
        parts.append("")

        # Triggering Process block — endpoint alerts only
        triggering_process = analysis.get("triggering_process")
        if triggering_process:
            total = len(analysis.get("behaviors") or [])
            parts.append("### Triggering Process")
            parts.append(f"- **Image**: {triggering_process.get('ImageFileName', 'N/A')}")
            parts.append(f"- **Command**: {triggering_process.get('CommandLine', 'N/A')}")
            parts.append(f"- **PID**: {triggering_process.get('TargetProcessId', 'N/A')}")
            parts.append(f"- **Record index**: {triggering_process.get('record_index', 'N/A')} (of {total} total, sorted by timestamp)")
            parts.append("")

        behaviors = alert.get("behaviors", [])
        if behaviors and isinstance(behaviors, list):
            parts.append("### MITRE ATT&CK Mapping")
            for behavior in behaviors[:5]:
                if isinstance(behavior, dict):
                    parts.append(f"- **{behavior.get('tactic', 'N/A')}**: {behavior.get('technique', 'N/A')}")
            parts.append("")

        device = alert.get("device")
        if device and isinstance(device, dict):
            parts.append("### Affected Device")
            parts.append(f"- Hostname: {device.get('hostname', 'N/A')}")
            parts.append(f"- User: {device.get('user_name', 'N/A')}")
            parts.append(f"- Platform: {device.get('platform_name', 'N/A')}")
            device_id = device.get("device_id", "")
            if device_id:
                parts.append(f"- Device ID: {device_id}")
            parts.append("")

        if analysis.get("enrichment_note"):
            parts.append("### Enrichment Note")
            parts.append(f"> {analysis['enrichment_note']}")
            parts.append("")

        events = analysis.get("events")
        if events:
            parts.append(f"### Related Events ({len(events)} events)")
            parts.append("")
            for i, event in enumerate(events, 1):
                parts.append(f"#### Event {i}")
                summary_fields = []
                for key in ["event.action", "@timestamp", "cloud.account.id", "source.ip", "Vendor.userIdentity.arn", "#event.outcome"]:
                    val = event.get(key)
                    if val:
                        short_key = key.lstrip("#").split(".")[-1]
                        summary_fields.append(f"{short_key}={val}")
                if summary_fields:
                    parts.append(f"  {' | '.join(summary_fields)}")
                parts.append("```json")
                parts.append(json.dumps(event, indent=2, default=str))
                parts.append("```")
                parts.append("")

        behaviors_data = analysis.get("behaviors")
        if behaviors_data:
            parts.append(f"### Endpoint Behaviors ({len(behaviors_data)} behaviors)")
            parts.append("")
            for i, behavior in enumerate(behaviors_data, 1):
                parts.append(f"#### Behavior {i}")
                summary_fields = []
                for key in ["tactic", "technique", "filename", "cmdline", "severity"]:
                    val = behavior.get(key)
                    if val:
                        val_str = str(val)[:80]
                        summary_fields.append(f"{key}={val_str}")
                if summary_fields:
                    parts.append(f"  {' | '.join(summary_fields)}")
                parts.append("```json")
                parts.append(json.dumps(behavior, indent=2, default=str))
                parts.append("```")
                parts.append("")

        if analysis.get("enrichment_type") == "cloud_security_raw":
            parts.append("### Raw Alert Payload (Cloud Security)")
            parts.append("```json")
            parts.append(json.dumps(alert, indent=2, default=str))
            parts.append("```")
            parts.append("")

        if analysis.get("enrichment_type") == "thirdparty_metadata_only":
            parts.append("### Raw Alert Payload (Third-Party)")
            parts.append("```json")
            parts.append(json.dumps(alert, indent=2, default=str))
            parts.append("```")
            parts.append("")

        has_raw_payload = analysis.get("enrichment_type") in ("cloud_security_raw", "thirdparty_metadata_only")
        if not events and not behaviors_data and not has_raw_payload:
            parts.append("### Related Events")
            parts.append("No related events found for this alert.")
            parts.append("")

        return "\n".join(parts)

    def _format_alert_analysis_summary(self, analysis):
        """Format a compact summary of an alert analysis."""
        alert = analysis["alert"]
        parts = []
        parts.append(f"## Alert Summary ({analysis['product_name']})")
        parts.append(f"- **Name**: {alert.get('name', 'Unknown')}")
        parts.append(f"- **ID**: {alert.get('composite_id', 'N/A')}")
        parts.append(f"- **Severity**: {alert.get('severity_name', 'Unknown')}")
        parts.append(f"- **Status**: {alert.get('status', 'unknown')}")
        parts.append(f"- **Tags**: {', '.join(alert.get('tags', [])) or 'None'}")

        behaviors = alert.get("behaviors", [])
        if behaviors and isinstance(behaviors, list):
            for b in behaviors[:3]:
                if isinstance(b, dict):
                    parts.append(f"- **MITRE**: {b.get('tactic', 'N/A')} / {b.get('technique', 'N/A')}")

        parts.append(f"- **Product**: {analysis['product_name']}")

        # Triggering Process block — endpoint alerts only
        triggering_process = analysis.get("triggering_process")
        if triggering_process:
            total = len(analysis.get("behaviors") or [])
            parts.append("### Triggering Process")
            parts.append(f"- **Image**: {triggering_process.get('ImageFileName', 'N/A')}")
            parts.append(f"- **Command**: {triggering_process.get('CommandLine', 'N/A')}")
            parts.append(f"- **PID**: {triggering_process.get('TargetProcessId', 'N/A')}")
            parts.append(f"- **Record index**: {triggering_process.get('record_index', 'N/A')} (of {total} total, sorted by timestamp)")
            parts.append("")

        events = analysis.get("events") or []
        total_events = analysis.get("events_matched", len(events))
        if events:
            parts.append(f"\n### Related Events (showing {min(5, len(events))} of {total_events})")
            for i, event in enumerate(events[:5], 1):
                ts = event.get("@timestamp", "")
                action = event.get("#event_simpleName") or event.get("event.action", "")
                host = event.get("ComputerName", "")
                user = event.get("UserName") or event.get("user.name", "")
                source = event.get("source")
                src_ip = source.get("ip", "") if isinstance(source, dict) else event.get("source.ip", "")
                parts.append(f"  {i}. {ts} | {action} | {host} | {user} | {src_ip}")
            if len(events) > 5:
                parts.append(f"\n  Showing 5 of {total_events} related events. Use summary_mode=false for full details.")

        behaviors_data = analysis.get("behaviors") or []
        if behaviors_data:
            parts.append(f"\n### Endpoint Behaviors (showing {min(5, len(behaviors_data))} of {len(behaviors_data)})")
            for i, b in enumerate(behaviors_data[:5], 1):
                ts = b.get("timestamp", "")
                tactic = b.get("tactic", "")
                technique = b.get("technique", "")
                filename = b.get("filename", "")
                cmdline = str(b.get("cmdline", ""))[:200]
                parts.append(f"  {i}. {ts} | {tactic}/{technique} | {filename} | {cmdline}")

        if analysis.get("enrichment_note"):
            parts.append(f"\n> {analysis['enrichment_note']}")

        return "\n".join(parts)
