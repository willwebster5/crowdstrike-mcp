"""
CaseManagement Module — case lifecycle management via the CaseManagement API.

Tools:
  case_query              — Query and list cases with FQL filtering
  case_get                — Get full case details by ID
  case_create             — Create a new case
  case_update             — Update case fields (status, severity, assignee)
  case_add_alert_evidence — Attach alerts as evidence
  case_add_event_evidence — Attach events as evidence
  case_add_tags           — Add tags to a case
  case_delete_tags        — Remove tags from a case
  case_upload_file        — Upload file attachment to a case
  case_get_fields         — List available case field definitions
  case_query_access_tags  — Query available access tags
  case_get_access_tags    — Get access tag details by ID
  case_aggregate_access_tags — Aggregate access tag data
  case_get_rtr_file_metadata — Get RTR-collected file metadata for a case
  case_get_rtr_recent_files  — Get recent RTR file activity for a case
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Annotated, Optional

from falconpy import CaseManagement

from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from fastmcp import FastMCP


class CaseManagementModule(BaseModule):
    """NG-SIEM Case lifecycle management — create, query, update, and link evidence."""

    def __init__(self, client):
        super().__init__(client)
        self._log("Initialized")

    def register_resources(self, server: FastMCP) -> None:
        from crowdstrike_mcp.resources.fql_guides import CASE_FQL

        def _case_fql():
            return CASE_FQL

        server.resource(
            "falcon://fql/cases",
            name="Case FQL Syntax Guide",
            description="Documentation: Case FQL filter syntax",
        )(_case_fql)
        self.resources.append("falcon://fql/cases")

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.case_query,
            name="case_query",
            description=(
                "Query and list NG-SIEM Cases with FQL filtering, free-text search, "
                "and pagination. Returns case summaries with status, severity, and assignee."
            ),
        )
        self._add_tool(
            server,
            self.case_get,
            name="case_get",
            description="Get full case details by ID(s) including evidence, tags, and timeline.",
        )
        self._add_tool(
            server,
            self.case_create,
            name="case_create",
            description=("Create a new NG-SIEM Case with name, description, severity, optional assignee, tags, and initial alert/event evidence."),
            tier="write",
        )
        self._add_tool(
            server,
            self.case_update,
            name="case_update",
            description=("Update case fields: status, severity, assignee, name, description. Handles optimistic concurrency automatically."),
            tier="write",
        )
        self._add_tool(
            server,
            self.case_add_alert_evidence,
            name="case_add_alert_evidence",
            description="Attach CrowdStrike alert composite IDs as evidence to an existing case.",
            tier="write",
        )
        self._add_tool(
            server,
            self.case_add_event_evidence,
            name="case_add_event_evidence",
            description="Attach NGSIEM event IDs as evidence to an existing case.",
            tier="write",
        )
        self._add_tool(
            server,
            self.case_add_tags,
            name="case_add_tags",
            description="Add tags to an existing case for categorization and filtering.",
            tier="write",
        )
        self._add_tool(
            server,
            self.case_delete_tags,
            name="case_delete_tags",
            description="Remove tags from an existing case.",
            tier="write",
        )
        self._add_tool(
            server,
            self.case_upload_file,
            name="case_upload_file",
            description="Upload a file attachment to an existing case.",
            tier="write",
        )
        self._add_tool(
            server,
            self.case_get_fields,
            name="case_get_fields",
            description="List available case field definitions and their types.",
        )
        self._add_tool(
            server,
            self.case_query_access_tags,
            name="case_query_access_tags",
            description="Query available case access tags with optional FQL filtering. Returns tag IDs for understanding case access controls.",
        )
        self._add_tool(
            server,
            self.case_get_access_tags,
            name="case_get_access_tags",
            description="Get access tag details by ID — name, description, and scope.",
        )
        self._add_tool(
            server,
            self.case_aggregate_access_tags,
            name="case_aggregate_access_tags",
            description="Aggregate case access tag data (counts, groupings by field).",
        )
        self._add_tool(
            server,
            self.case_get_rtr_file_metadata,
            name="case_get_rtr_file_metadata",
            description="Get metadata about RTR-collected files attached to a case — filename, size, hash, collection time.",
        )
        self._add_tool(
            server,
            self.case_get_rtr_recent_files,
            name="case_get_rtr_recent_files",
            description="Retrieve recent RTR file collection activity for a case.",
        )

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    async def case_query(
        self,
        filter: Annotated[Optional[str], "FQL filter expression (e.g. status:'open', severity:>=30)"] = None,
        q: Annotated[Optional[str], "Free-text search across all case metadata"] = None,
        status: Annotated[Optional[str], "Shortcut filter by case status ('open', 'in_progress', 'closed')"] = None,
        sort: Annotated[Optional[str], "Sort field.direction (e.g. 'severity.desc', 'name.asc', 'status.asc'). Omit for default ordering."] = None,
        max_results: Annotated[int, "Maximum cases to return (default: 50, max: 500)"] = 50,
    ) -> str:
        """Query and list cases with flexible filtering."""
        result = self._query_cases(
            filter=filter,
            q=q,
            status=status,
            sort=sort,
            max_results=max_results,
        )

        if not result.get("success"):
            return format_text_response(
                f"Failed to query cases: {result.get('error')}",
                raw=True,
            )

        cases = result["cases"]
        lines = [
            f"Cases Retrieved: {result['count']} (of {result['total_available']} total)",
        ]
        if filter:
            lines.append(f"Filter: {filter}")
        if status:
            lines.append(f"Status: {status}")
        if q:
            lines.append(f"Search: {q}")
        lines.append("")

        if not cases:
            lines.append("No cases found matching the filters.")
        else:
            for i, c in enumerate(cases, 1):
                assigned = f" -> {c['assigned_to']}" if c.get("assigned_to") else ""
                tags_str = f" [{', '.join(c['tags'])}]" if c.get("tags") else ""
                lines.append(f"{i}. [{c['severity_name']}] {c['name']} (status: {c['status']}{assigned}{tags_str})")
                lines.append(f"   ID: {c['id']}")
                lines.append(f"   Created: {c['created_on']}")
                if c.get("description"):
                    lines.append(f"   Description: {c['description']}")
                lines.append("")

        return format_text_response("\n".join(lines), raw=True)

    async def case_get(
        self,
        case_ids: Annotated[list[str], "List of case IDs to retrieve"],
    ) -> str:
        """Get full details for specific cases."""
        result = self._get_cases(case_ids)

        if not result.get("success"):
            return format_text_response(
                f"Failed to get cases: {result.get('error')}",
                raw=True,
            )

        lines = [f"Case Details ({result['count']} cases)", ""]

        for case in result.get("cases", []):
            lines.append(f"### {case.get('name', 'Unknown')}")
            lines.append(f"- **ID**: {case.get('id', 'N/A')}")
            lines.append(f"- **Status**: {case.get('status', 'N/A')}")
            lines.append(f"- **Severity**: {case.get('severity', 'N/A')}")
            lines.append(f"- **Created**: {case.get('created_on', 'N/A')}")
            lines.append(f"- **Updated**: {case.get('updated_on', 'N/A')}")
            if case.get("assigned_to_user_uuid"):
                lines.append(f"- **Assigned To UUID**: {case['assigned_to_user_uuid']}")
            if case.get("assigned_to_name"):
                lines.append(f"- **Assigned To**: {case['assigned_to_name']}")
            if case.get("description"):
                lines.append(f"- **Description**: {case['description']}")
            tags = case.get("tags", [])
            if tags:
                lines.append(f"- **Tags**: {', '.join(tags)}")
            if case.get("version"):
                lines.append(f"- **Version**: {case['version']}")

            lines.append("")
            lines.append("**Full Case JSON:**")
            lines.append("```json")
            lines.append(json.dumps(case, indent=2, default=str))
            lines.append("```")
            lines.append("")

        return format_text_response("\n".join(lines), raw=True)

    async def case_create(
        self,
        name: Annotated[str, "Case name/title"],
        description: Annotated[str, "Case description with investigation context"],
        severity: Annotated[int, "Severity level (10=Info, 20=Low, 30=Medium, 40=High, 50=Critical)"] = 30,
        assigned_to_user_uuid: Annotated[Optional[str], "UUID of user to assign (falls back to CASE_DEFAULT_ASSIGNEE env var)"] = None,
        alert_ids: Annotated[Optional[list[str]], "Alert composite IDs to attach as initial evidence"] = None,
        event_ids: Annotated[Optional[list[str]], "NGSIEM event IDs to attach as initial evidence"] = None,
        tags: Annotated[Optional[list[str]], "Tags to attach to the case"] = None,
    ) -> str:
        """Create a new NG-SIEM case."""
        result = self._create_case(
            name=name,
            description=description,
            severity=severity,
            assigned_to_user_uuid=assigned_to_user_uuid,
            alert_ids=alert_ids,
            event_ids=event_ids,
            tags=tags,
        )

        if not result.get("success"):
            return format_text_response(
                f"Failed to create case: {result.get('error')}",
                raw=True,
            )

        case = result["case"]
        lines = [
            "Case created successfully",
            f"- **ID**: {case.get('id', 'N/A')}",
            f"- **Name**: {case.get('name', name)}",
            f"- **Status**: {case.get('status', 'new')}",
            f"- **Severity**: {case.get('severity', severity)}",
        ]
        if case.get("assigned_to_user_uuid"):
            lines.append(f"- **Assigned To**: {case['assigned_to_user_uuid']}")
        if alert_ids:
            lines.append(f"- **Alerts Linked**: {len(alert_ids)}")
        if event_ids:
            lines.append(f"- **Events Linked**: {len(event_ids)}")
        if tags:
            lines.append(f"- **Tags**: {', '.join(tags)}")

        return format_text_response("\n".join(lines), raw=True)

    async def case_update(
        self,
        case_id: Annotated[str, "Case ID to update"],
        status: Annotated[Optional[str], "New status ('open', 'in_progress', 'closed', 'reopened')"] = None,
        severity: Annotated[Optional[int], "New severity (10/20/30/40/50)"] = None,
        assigned_to_user_uuid: Annotated[Optional[str], "UUID of user to reassign to"] = None,
        name: Annotated[Optional[str], "Updated case name"] = None,
        description: Annotated[Optional[str], "Updated description"] = None,
    ) -> str:
        """Update case fields with automatic optimistic concurrency handling."""
        result = self._update_case(
            case_id=case_id,
            status=status,
            severity=severity,
            assigned_to_user_uuid=assigned_to_user_uuid,
            name=name,
            description=description,
        )

        if not result.get("success"):
            return format_text_response(
                f"Failed to update case: {result.get('error')}",
                raw=True,
            )

        lines = [f"Case {case_id} updated successfully"]
        updates = result.get("updates", {})
        for field, value in updates.items():
            lines.append(f"- **{field}**: {value}")

        return format_text_response("\n".join(lines), raw=True)

    async def case_add_alert_evidence(
        self,
        case_id: Annotated[str, "Case ID to add evidence to"],
        alert_ids: Annotated[list[str], "Composite alert IDs to attach as evidence"],
    ) -> str:
        """Attach alert IDs as evidence to an existing case."""
        result = self._add_alert_evidence(case_id, alert_ids)

        if not result.get("success"):
            return format_text_response(
                f"Failed to add alert evidence: {result.get('error')}",
                raw=True,
            )

        return format_text_response(
            f"Successfully added {len(alert_ids)} alert(s) as evidence to case {case_id}",
            raw=True,
        )

    async def case_add_event_evidence(
        self,
        case_id: Annotated[str, "Case ID to add evidence to"],
        event_ids: Annotated[list[str], "NGSIEM event IDs to attach as evidence"],
    ) -> str:
        """Attach NGSIEM event IDs as evidence to an existing case."""
        result = self._add_event_evidence(case_id, event_ids)

        if not result.get("success"):
            return format_text_response(
                f"Failed to add event evidence: {result.get('error')}",
                raw=True,
            )

        return format_text_response(
            f"Successfully added {len(event_ids)} event(s) as evidence to case {case_id}",
            raw=True,
        )

    async def case_add_tags(
        self,
        case_id: Annotated[str, "Case ID to add tags to"],
        tags: Annotated[list[str], "Tags to add to the case"],
    ) -> str:
        """Add tags to an existing case."""
        result = self._add_tags(case_id, tags)

        if not result.get("success"):
            return format_text_response(
                f"Failed to add tags: {result.get('error')}",
                raw=True,
            )

        return format_text_response(
            f"Successfully added tags [{', '.join(tags)}] to case {case_id}",
            raw=True,
        )

    async def case_delete_tags(
        self,
        case_id: Annotated[str, "Case ID to remove tags from"],
        tags: Annotated[list[str], "Tags to remove from the case"],
    ) -> str:
        """Remove tags from an existing case."""
        result = self._delete_tags(case_id, tags)

        if not result.get("success"):
            return format_text_response(
                f"Failed to delete tags: {result.get('error')}",
                raw=True,
            )

        return format_text_response(
            f"Successfully removed tags [{', '.join(tags)}] from case {case_id}",
            raw=True,
        )

    async def case_upload_file(
        self,
        case_id: Annotated[str, "Case ID to attach the file to"],
        file_path: Annotated[str, "Absolute path to the file to upload"],
        description: Annotated[Optional[str], "File description"] = None,
    ) -> str:
        """Upload a file attachment to an existing case."""
        result = self._upload_file(case_id, file_path, description)

        if not result.get("success"):
            return format_text_response(
                f"Failed to upload file: {result.get('error')}",
                raw=True,
            )

        return format_text_response(
            f"Successfully uploaded '{os.path.basename(file_path)}' to case {case_id}",
            raw=True,
        )

    async def case_get_fields(self) -> str:
        """List available case field definitions."""
        result = self._get_fields()

        if not result.get("success"):
            return format_text_response(
                f"Failed to get fields: {result.get('error')}",
                raw=True,
            )

        fields = result.get("fields", [])
        lines = [f"Case Field Definitions ({len(fields)} fields)", ""]

        for f in fields:
            lines.append(f"- **{f.get('name', 'N/A')}** (ID: {f.get('id', 'N/A')})")
            if f.get("type"):
                lines.append(f"  Type: {f['type']}")
            if f.get("description"):
                lines.append(f"  Description: {f['description']}")

        if not fields:
            lines.append("```json")
            lines.append(json.dumps(result.get("raw", []), indent=2, default=str))
            lines.append("```")

        return format_text_response("\n".join(lines), raw=True)

    async def case_query_access_tags(
        self,
        filter: Annotated[Optional[str], "FQL filter expression for access tags"] = None,
        limit: Annotated[int, "Maximum tags to return (default: 100)"] = 100,
        offset: Annotated[int, "Pagination offset (default: 0)"] = 0,
    ) -> str:
        """Query available case access tags."""
        try:
            kwargs = {"limit": min(limit, 500), "offset": offset}
            if filter:
                kwargs["filter"] = filter

            falcon = self._service(CaseManagement)
            response = falcon.query_access_tags(**kwargs)

            if response["status_code"] != 200:
                return format_text_response(
                    f"Failed to query access tags: {format_api_error(response, 'Failed to query access tags', operation='queries_access_tags_get_v1')}",
                    raw=True,
                )

            tag_ids = response.get("body", {}).get("resources", [])
            total = response.get("body", {}).get("meta", {}).get("pagination", {}).get("total", len(tag_ids))

            lines = [f"Access Tags: {len(tag_ids)} returned (of {total} total)", ""]
            if not tag_ids:
                lines.append("No access tags found.")
            else:
                for i, tag_id in enumerate(tag_ids, 1):
                    lines.append(f"{i}. {tag_id}")

            return format_text_response("\n".join(lines), raw=True)
        except Exception as e:
            return format_text_response(f"Failed to query access tags: {e}", raw=True)

    async def case_get_access_tags(
        self,
        tag_ids: Annotated[list[str], "List of access tag IDs to retrieve"],
    ) -> str:
        """Get access tag details by ID."""
        try:
            falcon = self._service(CaseManagement)
            response = falcon.get_access_tags(ids=tag_ids)

            if response["status_code"] != 200:
                return format_text_response(
                    f"Failed to get access tags: {format_api_error(response, 'Failed to get access tags', operation='entities_access_tags_get_v1')}",
                    raw=True,
                )

            resources = response.get("body", {}).get("resources", [])
            lines = [f"Access Tag Details ({len(resources)} tags)", ""]

            for tag in resources:
                lines.append(f"### {tag.get('name', 'Unknown')}")
                lines.append(f"- **ID**: {tag.get('id', 'N/A')}")
                if tag.get("description"):
                    lines.append(f"- **Description**: {tag['description']}")
                lines.append("")
                lines.append("```json")
                lines.append(json.dumps(tag, indent=2, default=str))
                lines.append("```")
                lines.append("")

            if not resources:
                lines.append("No access tags found for the provided IDs.")

            return format_text_response("\n".join(lines), raw=True)
        except Exception as e:
            return format_text_response(f"Failed to get access tags: {e}", raw=True)

    async def case_aggregate_access_tags(
        self,
        date_ranges: Annotated[list, "Date range specifications for aggregation"],
        field: Annotated[str, "Field to aggregate on (e.g. 'name', 'id')"],
        filter: Annotated[str, "FQL filter to scope the aggregation"],
        name: Annotated[str, "Name for this aggregation result"],
        type: Annotated[str, "Aggregation type (e.g. 'terms', 'date_range', 'count')"],
    ) -> str:
        """Aggregate case access tag data."""
        try:
            body = [
                {
                    "date_ranges": date_ranges,
                    "field": field,
                    "filter": filter,
                    "name": name,
                    "type": type,
                }
            ]
            falcon = self._service(CaseManagement)
            response = falcon.aggregate_access_tags(body=body)

            if response["status_code"] != 200:
                err = format_api_error(response, "Failed to aggregate access tags", operation="aggregates_access_tags_post_v1")
                return format_text_response(f"Failed to aggregate access tags: {err}", raw=True)

            resources = response.get("body", {}).get("resources", [])
            lines = ["Access Tag Aggregation Results", ""]
            lines.append("```json")
            lines.append(json.dumps(resources, indent=2, default=str))
            lines.append("```")

            return format_text_response("\n".join(lines), raw=True)
        except Exception as e:
            return format_text_response(f"Failed to aggregate access tags: {e}", raw=True)

    async def case_get_rtr_file_metadata(
        self,
        case_id: Annotated[str, "Case ID to retrieve RTR file metadata for"],
    ) -> str:
        """Get metadata about RTR-collected files attached to a case."""
        try:
            falcon = self._service(CaseManagement)
            response = falcon.get_rtr_file_metadata(body={"case_id": case_id})

            if response["status_code"] != 200:
                err = format_api_error(response, "Failed to get RTR file metadata", operation="entities_get_rtr_file_metadata_post_v1")
                return format_text_response(f"Failed to get RTR file metadata: {err}", raw=True)

            resources = response.get("body", {}).get("resources", [])
            lines = [f"RTR File Metadata for Case {case_id} ({len(resources)} files)", ""]

            if not resources:
                lines.append("No RTR files found for this case.")
            else:
                for i, f in enumerate(resources, 1):
                    lines.append(f"{i}. **{f.get('file_name', 'Unknown')}**")
                    lines.append(f"   - ID: {f.get('id', 'N/A')}")
                    if f.get("file_size"):
                        lines.append(f"   - Size: {f['file_size']} bytes")
                    if f.get("sha256"):
                        lines.append(f"   - SHA256: {f['sha256']}")
                    if f.get("created_on"):
                        lines.append(f"   - Collected: {f['created_on']}")
                    lines.append("")

            lines.append("```json")
            lines.append(json.dumps(resources, indent=2, default=str))
            lines.append("```")

            return format_text_response("\n".join(lines), raw=True)
        except Exception as e:
            return format_text_response(f"Failed to get RTR file metadata: {e}", raw=True)

    async def case_get_rtr_recent_files(
        self,
        case_id: Annotated[str, "Case ID to retrieve recent RTR files for"],
    ) -> str:
        """Retrieve recent RTR file collection activity for a case."""
        try:
            falcon = self._service(CaseManagement)
            response = falcon.get_rtr_recent_files(body={"case_id": case_id})

            if response["status_code"] != 200:
                err = format_api_error(response, "Failed to get RTR recent files", operation="entities_retrieve_rtr_recent_file_post_v1")
                return format_text_response(f"Failed to get RTR recent files: {err}", raw=True)

            resources = response.get("body", {}).get("resources", [])
            lines = [f"Recent RTR Files for Case {case_id} ({len(resources)} files)", ""]

            if not resources:
                lines.append("No recent RTR files found for this case.")
            else:
                for i, f in enumerate(resources, 1):
                    lines.append(f"{i}. **{f.get('file_name', 'Unknown')}**")
                    lines.append(f"   - ID: {f.get('id', 'N/A')}")
                    if f.get("created_on"):
                        lines.append(f"   - Collected: {f['created_on']}")
                    lines.append("")

            lines.append("```json")
            lines.append(json.dumps(resources, indent=2, default=str))
            lines.append("```")

            return format_text_response("\n".join(lines), raw=True)
        except Exception as e:
            return format_text_response(f"Failed to get RTR recent files: {e}", raw=True)

    # ------------------------------------------------------------------
    # Internal methods
    # ------------------------------------------------------------------

    _SEVERITY_NAMES = {
        10: "Informational",
        20: "Low",
        30: "Medium",
        40: "High",
        50: "Critical",
    }

    def _query_cases(self, filter=None, q=None, status=None, sort=None, max_results=50):
        try:
            falcon = self._service(CaseManagement)
            # Build FQL filter
            if status and not filter:
                filter = f"status:'{status}'"
            elif status and filter:
                filter = f"{filter}+status:'{status}'"

            kwargs = {
                "limit": min(max_results, 500),
            }
            if sort:
                kwargs["sort"] = sort
            if filter:
                kwargs["filter"] = filter
            if q:
                kwargs["q"] = q

            response = falcon.query_case_ids(**kwargs)

            if response["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(
                        response,
                        "Failed to query cases",
                        operation="queries_cases_get_v1",
                    ),
                }

            case_ids = response.get("body", {}).get("resources", [])
            total_available = response.get("body", {}).get("meta", {}).get("pagination", {}).get("total", len(case_ids))

            if not case_ids:
                return {"success": True, "cases": [], "count": 0, "total_available": 0}

            # Hydrate with full details
            details_response = falcon.get_cases(body={"ids": case_ids})
            if details_response["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(
                        details_response,
                        "Failed to get case details",
                        operation="entities_cases_post_v2",
                    ),
                }

            cases_data = details_response.get("body", {}).get("resources", [])

            summaries = []
            for c in cases_data:
                sev = c.get("severity", 0)
                summaries.append(
                    {
                        "id": c.get("id", ""),
                        "name": c.get("name", "Unknown"),
                        "description": (c.get("description") or "")[:200],
                        "status": c.get("status", "unknown"),
                        "severity": sev,
                        "severity_name": self._SEVERITY_NAMES.get(sev, f"Unknown({sev})"),
                        "created_on": c.get("created_on", ""),
                        "updated_on": c.get("updated_on", ""),
                        "assigned_to": c.get("assigned_to_name", ""),
                        "tags": c.get("tags", []),
                    }
                )

            return {
                "success": True,
                "cases": summaries,
                "count": len(summaries),
                "total_available": total_available,
            }
        except Exception as e:
            return {"success": False, "error": f"Error querying cases: {str(e)}"}

    def _get_cases(self, case_ids):
        try:
            falcon = self._service(CaseManagement)
            response = falcon.get_cases(body={"ids": case_ids})

            if response["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(
                        response,
                        "Failed to get cases",
                        operation="entities_cases_post_v2",
                    ),
                }

            resources = response.get("body", {}).get("resources", [])
            if not resources:
                return {"success": False, "error": f"No cases found for IDs: {case_ids}"}

            return {"success": True, "cases": resources, "count": len(resources)}
        except Exception as e:
            return {"success": False, "error": f"Error getting cases: {str(e)}"}

    def _create_case(self, name, description, severity=30, assigned_to_user_uuid=None, alert_ids=None, event_ids=None, tags=None):
        try:
            falcon = self._service(CaseManagement)
            # Resolve assignee: explicit > env var > None
            assignee = assigned_to_user_uuid or os.environ.get("CASE_DEFAULT_ASSIGNEE")

            body = {
                "name": name,
                "description": description,
                "severity": severity,
            }

            if assignee:
                body["assigned_to_user_uuid"] = assignee

            if tags:
                body["tags"] = tags

            # Build evidence block
            evidence = {}
            if alert_ids:
                evidence["alerts"] = [{"id": aid} for aid in alert_ids]
            if event_ids:
                evidence["events"] = [{"id": eid} for eid in event_ids]
            if evidence:
                body["evidence"] = evidence

            response = falcon.create_case(body=body)

            if response["status_code"] not in (200, 201):
                return {
                    "success": False,
                    "error": format_api_error(
                        response,
                        "Failed to create case",
                        operation="entities_cases_put_v2",
                    ),
                }

            resources = response.get("body", {}).get("resources", [])
            case = resources[0] if resources else body

            return {"success": True, "case": case}
        except Exception as e:
            return {"success": False, "error": f"Error creating case: {str(e)}"}

    def _update_case(self, case_id, status=None, severity=None, assigned_to_user_uuid=None, name=None, description=None):
        try:
            falcon = self._service(CaseManagement)
            # Fetch current case to get version for optimistic concurrency
            current = self._get_cases([case_id])
            if not current.get("success"):
                return {"success": False, "error": f"Cannot fetch case for update: {current.get('error')}"}

            case_data = current["cases"][0]
            version = case_data.get("version", 0)

            fields = {}
            updates = {}
            if status is not None:
                fields["status"] = status
                updates["status"] = status
            if severity is not None:
                fields["severity"] = severity
                updates["severity"] = severity
            if assigned_to_user_uuid is not None:
                fields["assigned_to_user_uuid"] = assigned_to_user_uuid
                updates["assigned_to_user_uuid"] = assigned_to_user_uuid
            if name is not None:
                fields["name"] = name
                updates["name"] = name
            if description is not None:
                fields["description"] = description
                updates["description"] = description

            if not fields:
                return {"success": False, "error": "No fields to update. Provide at least one field."}

            body = {
                "id": case_id,
                "fields": fields,
                "expected_version": version,
            }

            response = falcon.update_case_fields(body=body)

            if response["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(
                        response,
                        "Failed to update case",
                        operation="entities_cases_patch_v2",
                    ),
                }

            return {"success": True, "case_id": case_id, "updates": updates}
        except Exception as e:
            return {"success": False, "error": f"Error updating case: {str(e)}"}

    def _add_alert_evidence(self, case_id, alert_ids):
        try:
            falcon = self._service(CaseManagement)
            body = {
                "id": case_id,
                "alerts": [{"id": aid} for aid in alert_ids],
            }
            response = falcon.add_case_alert_evidence(body=body)

            if response["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(
                        response,
                        "Failed to add alert evidence",
                        operation="entities_alert_evidence_post_v1",
                    ),
                }

            return {"success": True}
        except Exception as e:
            return {"success": False, "error": f"Error adding alert evidence: {str(e)}"}

    def _add_event_evidence(self, case_id, event_ids):
        try:
            falcon = self._service(CaseManagement)
            body = {
                "id": case_id,
                "events": [{"id": eid} for eid in event_ids],
            }
            response = falcon.add_case_event_evidence(body=body)

            if response["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(
                        response,
                        "Failed to add event evidence",
                        operation="entities_event_evidence_post_v1",
                    ),
                }

            return {"success": True}
        except Exception as e:
            return {"success": False, "error": f"Error adding event evidence: {str(e)}"}

    def _add_tags(self, case_id, tags):
        try:
            falcon = self._service(CaseManagement)
            body = {"id": case_id, "tags": tags}
            response = falcon.add_case_tags(body=body)

            if response["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(
                        response,
                        "Failed to add tags",
                        operation="entities_case_tags_post_v1",
                    ),
                }

            return {"success": True}
        except Exception as e:
            return {"success": False, "error": f"Error adding tags: {str(e)}"}

    def _delete_tags(self, case_id, tags):
        try:
            falcon = self._service(CaseManagement)
            # delete_case_tags uses query params: id + tag (repeated)
            response = falcon.delete_case_tags(id=case_id, tag=tags)

            if response["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(
                        response,
                        "Failed to delete tags",
                        operation="entities_case_tags_delete_v1",
                    ),
                }

            return {"success": True}
        except Exception as e:
            return {"success": False, "error": f"Error deleting tags: {str(e)}"}

    def _upload_file(self, case_id, file_path, description=None):
        try:
            falcon = self._service(CaseManagement)
            if not os.path.isfile(file_path):
                return {"success": False, "error": f"File not found: {file_path}"}

            kwargs = {"file": file_path, "case_id": case_id}
            if description:
                kwargs["description"] = description

            response = falcon.upload_file(**kwargs)

            if response["status_code"] not in (200, 201):
                return {
                    "success": False,
                    "error": format_api_error(
                        response,
                        "Failed to upload file",
                        operation="entities_files_upload_post_v1",
                    ),
                }

            return {"success": True}
        except Exception as e:
            return {"success": False, "error": f"Error uploading file: {str(e)}"}

    def _get_fields(self):
        try:
            falcon = self._service(CaseManagement)
            # Query field IDs first
            query_response = falcon.query_fields()

            if query_response["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(
                        query_response,
                        "Failed to query fields",
                        operation="queries_fields_get_v1",
                    ),
                }

            field_ids = query_response.get("body", {}).get("resources", [])
            if not field_ids:
                return {"success": True, "fields": [], "raw": []}

            # Get field details
            details_response = falcon.get_fields(ids=field_ids)

            if details_response["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(
                        details_response,
                        "Failed to get field details",
                        operation="entities_fields_get_v1",
                    ),
                }

            fields = details_response.get("body", {}).get("resources", [])
            return {"success": True, "fields": fields, "raw": fields}
        except Exception as e:
            return {"success": False, "error": f"Error getting fields: {str(e)}"}
