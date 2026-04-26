"""
Spotlight Module — vulnerability evaluation and Spotlight Vulnerabilities API.

Tools:
  spotlight_supported_evaluations    — Supported evaluation logic (coverage, platforms)
  spotlight_query_vulnerabilities    — Find vulnerability IDs by FQL filter
  spotlight_get_vulnerabilities      — Fetch full vulnerability records by ID
  spotlight_vulnerabilities_combined — One-shot query+get (recommended default)
  spotlight_get_remediations         — Remediation instructions by remediation ID
  spotlight_host_vulns               — Triage shortcut: open vulns for a specific host
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated, Optional

try:
    from falconpy import SpotlightEvaluationLogic

    SPOTLIGHT_EVAL_AVAILABLE = True
except ImportError:
    SPOTLIGHT_EVAL_AVAILABLE = False

try:
    from falconpy import SpotlightVulnerabilities

    SPOTLIGHT_VULNS_AVAILABLE = True
except ImportError:
    SPOTLIGHT_VULNS_AVAILABLE = False

from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from fastmcp import FastMCP


class SpotlightModule(BaseModule):
    """Spotlight vulnerability evaluation logic queries."""

    def __init__(self, client):
        super().__init__(client)
        if not SPOTLIGHT_EVAL_AVAILABLE and not SPOTLIGHT_VULNS_AVAILABLE:
            raise ImportError(
                "Neither SpotlightEvaluationLogic nor SpotlightVulnerabilities available. Ensure crowdstrike-falconpy >= 1.6.1 is installed."
            )
        self._log("Initialized")

    def register_resources(self, server: FastMCP) -> None:
        from crowdstrike_mcp.resources.fql_guides import SPOTLIGHT_VULN_FQL

        def _spotlight_vuln_fql():
            return SPOTLIGHT_VULN_FQL

        server.resource(
            "falcon://fql/spotlight-vulnerabilities",
            name="Spotlight Vulnerabilities FQL Syntax",
            description="Documentation: FQL filter syntax for Spotlight vulnerability queries",
        )(_spotlight_vuln_fql)
        self.resources.append("falcon://fql/spotlight-vulnerabilities")

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.spotlight_supported_evaluations,
            name="spotlight_supported_evaluations",
            description=(
                "Get supported vulnerability evaluation logic — assessment methods, "
                "OS/platform coverage, and evaluation criteria. Use to check if Spotlight "
                "can evaluate a specific CVE or what platforms are covered."
            ),
        )
        self._add_tool(
            server,
            self.spotlight_query_vulnerabilities,
            name="spotlight_query_vulnerabilities",
            description=(
                "Find vulnerability IDs matching an FQL filter. Use to locate open "
                "CVEs by host (`aid`), CVE ID, severity, or age. Returns IDs only — "
                "use spotlight_get_vulnerabilities or spotlight_vulnerabilities_combined "
                "for full records."
            ),
        )
        self._add_tool(
            server,
            self.spotlight_get_vulnerabilities,
            name="spotlight_get_vulnerabilities",
            description=(
                "Fetch full vulnerability records by ID: CVE metadata, severity, host "
                "info, exploit status, affected apps. Pair with spotlight_query_vulnerabilities."
            ),
        )
        self._add_tool(
            server,
            self.spotlight_vulnerabilities_combined,
            name="spotlight_vulnerabilities_combined",
            description=(
                "Query vulnerabilities with full record projection in one call. "
                "Default tool for 'show me open CVEs matching X' — returns CVE, "
                "severity, host, status, and affected apps. Prefer this over the "
                "query/get split unless paginating very large result sets."
            ),
        )
        self._add_tool(
            server,
            self.spotlight_get_remediations,
            name="spotlight_get_remediations",
            description=(
                "Get remediation instructions (vendor patches, config changes) "
                "by remediation ID. Pair with vulnerability records returned by "
                "spotlight_vulnerabilities_combined."
            ),
        )
        self._add_tool(
            server,
            self.spotlight_host_vulns,
            name="spotlight_host_vulns",
            description=(
                "Triage shortcut: list open vulnerabilities on a specific host by "
                "device_id (aid). Pre-filters status:'open' unless include_closed=True. "
                "Optional min_severity floor. Use this for 'is this host vulnerable?' "
                "during live alert triage."
            ),
        )

    async def spotlight_supported_evaluations(
        self,
        filter: Annotated[Optional[str], "FQL filter expression (e.g. platform:'Windows')"] = None,
    ) -> str:
        """Get combined supported evaluation logic."""
        try:
            kwargs = {}
            if filter:
                kwargs["filter"] = filter

            falcon = self._service(SpotlightEvaluationLogic)
            response = falcon.combined_supported_evaluation(**kwargs)

            if response["status_code"] != 200:
                err = format_api_error(response, "Failed to get evaluations", operation="combinedSupportedEvaluationExt")
                return format_text_response(f"Failed to get supported evaluations: {err}", raw=True)

            resources = response.get("body", {}).get("resources", [])
            lines = [f"Spotlight Supported Evaluations ({len(resources)} results)", ""]

            if not resources:
                lines.append("No evaluation logic found matching the filter.")
            else:
                for i, ev in enumerate(resources, 1):
                    lines.append(f"{i}. **{ev.get('name', 'Unknown')}**")
                    lines.append(f"   - ID: {ev.get('id', 'N/A')}")
                    if ev.get("platforms"):
                        lines.append(f"   - Platforms: {', '.join(ev['platforms'])}")
                    if ev.get("cve_ids"):
                        lines.append(f"   - CVEs: {', '.join(ev['cve_ids'][:10])}")
                    lines.append("")

            lines.append("```json")
            lines.append(json.dumps(resources, indent=2, default=str))
            lines.append("```")

            return format_text_response("\n".join(lines), raw=True)
        except Exception as e:
            return format_text_response(f"Failed to get supported evaluations: {e}", raw=True)

    async def spotlight_query_vulnerabilities(
        self,
        filter: Annotated[str, "FQL filter expression (required). See falcon://fql/spotlight-vulnerabilities."],
        limit: Annotated[int, "Max IDs to return (default 50, max 500)"] = 50,
        after: Annotated[Optional[str], "Pagination token from a prior call"] = None,
        sort: Annotated[Optional[str], "Sort expression (e.g. 'created_timestamp|desc')"] = None,
    ) -> str:
        """Find vulnerability IDs matching an FQL filter."""
        result = self._query_vulnerabilities(filter=filter, limit=limit, after=after, sort=sort)

        if not result.get("success"):
            return format_text_response(f"Failed to query vulnerabilities: {result.get('error')}", raw=True)

        ids = result["ids"]
        lines = [
            f"Spotlight Vulnerability IDs: {len(ids)} returned (total={result.get('total', 'unknown')})",
            "",
        ]
        if result.get("after"):
            lines.append(f"Next page token: `{result['after']}`")
            lines.append("")
        if not ids:
            lines.append("No vulnerabilities matched the filter.")
        else:
            for i, vid in enumerate(ids, 1):
                lines.append(f"{i}. {vid}")
        return format_text_response("\n".join(lines), raw=True)

    async def spotlight_get_vulnerabilities(
        self,
        ids: Annotated[list[str], "Vulnerability IDs (from spotlight_query_vulnerabilities)"],
    ) -> str:
        """Fetch full vulnerability records by ID."""
        result = self._get_vulnerabilities(ids)
        if not result.get("success"):
            return format_text_response(f"Failed to get vulnerabilities: {result.get('error')}", raw=True)

        resources = result["resources"]
        lines = [f"Spotlight Vulnerabilities: {len(resources)} records", ""]
        if not resources:
            lines.append("No records returned.")
        else:
            for i, v in enumerate(resources, 1):
                cve = v.get("cve", {}) or {}
                host = v.get("host_info", {}) or {}
                lines.append(f"{i}. **{cve.get('id', 'UNKNOWN CVE')}** [{cve.get('severity', '?')}] score={cve.get('base_score', '?')}")
                lines.append(f"   Host: {host.get('hostname', '?')} ({host.get('platform_name', '?')})")
                lines.append(f"   Status: {v.get('status', '?')} | Created: {v.get('created_timestamp', '?')}")
                if cve.get("exploit_status") is not None:
                    lines.append(f"   Exploit status: {cve['exploit_status']}")
                if v.get("apps"):
                    app_names = [a.get("product_name_version", "") for a in v["apps"][:3]]
                    lines.append(f"   Apps: {'; '.join(a for a in app_names if a)}")
                lines.append("")
        return format_text_response("\n".join(lines), raw=True)

    async def spotlight_vulnerabilities_combined(
        self,
        filter: Annotated[str, "FQL filter expression (required)"],
        limit: Annotated[int, "Max results (default 50, max 500)"] = 50,
        facet: Annotated[Optional[list[str]], "Facets to include (default: cve, host_info)"] = None,
        after: Annotated[Optional[str], "Pagination token"] = None,
        sort: Annotated[Optional[str], "Sort expression"] = None,
    ) -> str:
        """Query + get in one call; the recommended default for vuln lookups."""
        result = self._vulnerabilities_combined(filter=filter, limit=limit, facet=facet, after=after, sort=sort)
        if not result.get("success"):
            return format_text_response(f"Failed to query vulnerabilities: {result.get('error')}", raw=True)
        return self._format_vuln_list(result, header="Spotlight Vulnerabilities (combined)")

    async def spotlight_get_remediations(
        self,
        ids: Annotated[list[str], "Remediation IDs (from a vulnerability record's remediation.ids list)"],
    ) -> str:
        """Fetch remediation instructions by ID."""
        result = self._get_remediations(ids)
        if not result.get("success"):
            return format_text_response(f"Failed to get remediations: {result.get('error')}", raw=True)
        resources = result["resources"]
        lines = [f"Spotlight Remediations: {len(resources)} records", ""]
        if not resources:
            lines.append("No remediations returned.")
        else:
            for i, rem in enumerate(resources, 1):
                lines.append(f"{i}. **{rem.get('title', 'Untitled')}** ({rem.get('id', 'N/A')})")
                if rem.get("action"):
                    lines.append(f"   Action: {rem['action']}")
                if rem.get("reference"):
                    lines.append(f"   Reference: {rem['reference']}")
                lines.append("")
        return format_text_response("\n".join(lines), raw=True)

    async def spotlight_host_vulns(
        self,
        device_id: Annotated[str, "Falcon device/agent ID (aid) to list vulns for"],
        cve_id: Annotated[Optional[str], "Filter to a single CVE (e.g. 'CVE-2024-1234'). Use for 'is this host affected by X?' triage."] = None,
        include_closed: Annotated[bool, "If True, include closed/remediated vulns (default False)"] = False,
        min_severity: Annotated[Optional[str], "Minimum severity: CRITICAL | HIGH | MEDIUM | LOW"] = None,
        limit: Annotated[int, "Max results (default 50, max 500)"] = 50,
    ) -> str:
        """Triage shortcut: all (open) vulnerabilities for a single host."""
        if not device_id:
            return format_text_response("Failed: device_id is required", raw=True)

        filter_parts = [f"aid:'{device_id}'"]
        if cve_id:
            filter_parts.append(f"cve.id:'{cve_id}'")
        if not include_closed:
            filter_parts.append("status:'open'")
        if min_severity:
            severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if min_severity.upper() in severity_order:
                idx = severity_order.index(min_severity.upper())
                allowed = severity_order[idx:]
                filter_parts.append(f"cve.severity:[{','.join(repr(s) for s in allowed)}]")

        filter_str = "+".join(filter_parts)
        result = self._vulnerabilities_combined(filter=filter_str, limit=limit)
        if not result.get("success"):
            return format_text_response(f"Failed to get host vulnerabilities: {result.get('error')}", raw=True)
        return self._format_vuln_list(result, header=f"Vulnerabilities on host {device_id}")

    def _query_vulnerabilities(self, filter, limit=50, after=None, sort=None):
        if not SPOTLIGHT_VULNS_AVAILABLE:
            return {"success": False, "error": "SpotlightVulnerabilities client not available"}
        if not filter:
            return {"success": False, "error": "filter is required (e.g. status:'open')"}
        try:
            svc = self._service(SpotlightVulnerabilities)
            kwargs = {"filter": filter, "limit": min(limit, 500)}
            if after:
                kwargs["after"] = after
            if sort:
                kwargs["sort"] = sort
            r = svc.query_vulnerabilities(**kwargs)
            if r["status_code"] != 200:
                return {"success": False, "error": format_api_error(r, "Failed to query vulnerabilities", operation="query_vulnerabilities")}
            body = r.get("body", {})
            ids = body.get("resources", [])
            meta = body.get("meta", {}).get("pagination", {})
            return {
                "success": True,
                "ids": ids,
                "total": meta.get("total", len(ids)),
                "after": meta.get("after"),
            }
        except Exception as e:
            return {"success": False, "error": f"Error querying vulnerabilities: {e}"}

    def _get_vulnerabilities(self, ids):
        if not SPOTLIGHT_VULNS_AVAILABLE:
            return {"success": False, "error": "SpotlightVulnerabilities client not available"}
        if not ids:
            return {"success": False, "error": "ids list is required"}
        try:
            svc = self._service(SpotlightVulnerabilities)
            r = svc.get_vulnerabilities(ids=ids)
            if r["status_code"] != 200:
                return {"success": False, "error": format_api_error(r, "Failed to get vulnerabilities", operation="get_vulnerabilities")}
            return {"success": True, "resources": r.get("body", {}).get("resources", [])}
        except Exception as e:
            return {"success": False, "error": f"Error getting vulnerabilities: {e}"}

    @staticmethod
    def _project_vuln(v: dict) -> dict:
        cve = v.get("cve", {}) or {}
        host = v.get("host_info", {}) or {}
        return {
            "id": v.get("id", ""),
            "cve_id": cve.get("id", ""),
            "severity": cve.get("severity", ""),
            "base_score": cve.get("base_score"),
            "exploit_status": cve.get("exploit_status"),
            "status": v.get("status", ""),
            "hostname": host.get("hostname", ""),
            "platform": host.get("platform_name", ""),
            "created_timestamp": v.get("created_timestamp", ""),
            "apps": [a.get("product_name_version", "") for a in (v.get("apps") or [])[:5]],
            "remediation_ids": (v.get("remediation") or {}).get("ids", []),
        }

    def _format_vuln_list(self, result: dict, header: str) -> str:
        items = result["vulns"]
        lines = [f"{header}: {len(items)} returned (total={result.get('total', 'unknown')})", ""]
        if result.get("after"):
            lines.append(f"Next page token: `{result['after']}`")
            lines.append("")
        if not items:
            lines.append("No vulnerabilities matched the filter.")
        else:
            for i, v in enumerate(items, 1):
                lines.append(f"{i}. **{v['cve_id'] or '(no CVE)'}** [{v['severity']}] score={v['base_score']} exploit={v['exploit_status']}")
                lines.append(f"   Host: {v['hostname']} ({v['platform']}) | Status: {v['status']} | Created: {v['created_timestamp']}")
                if v["apps"]:
                    lines.append(f"   Apps: {'; '.join(a for a in v['apps'] if a)}")
                lines.append("")
        return format_text_response("\n".join(lines), raw=True)

    def _vulnerabilities_combined(self, filter, limit=50, facet=None, after=None, sort=None):
        if not SPOTLIGHT_VULNS_AVAILABLE:
            return {"success": False, "error": "SpotlightVulnerabilities client not available"}
        if not filter:
            return {"success": False, "error": "filter is required"}
        try:
            svc = self._service(SpotlightVulnerabilities)
            kwargs = {
                "filter": filter,
                "limit": min(limit, 500),
                "facet": facet if facet else ["cve", "host_info"],
            }
            if after:
                kwargs["after"] = after
            if sort:
                kwargs["sort"] = sort
            r = svc.query_vulnerabilities_combined(**kwargs)
            if r["status_code"] != 200:
                err = format_api_error(
                    r,
                    "Failed to query vulnerabilities combined",
                    operation="query_vulnerabilities_combined",
                )
                return {"success": False, "error": err}
            body = r.get("body", {})
            resources = body.get("resources", [])
            meta = body.get("meta", {}).get("pagination", {})
            return {
                "success": True,
                "vulns": [self._project_vuln(v) for v in resources],
                "total": meta.get("total", len(resources)),
                "after": meta.get("after"),
            }
        except Exception as e:
            return {"success": False, "error": f"Error in combined query: {e}"}

    def _get_remediations(self, ids):
        if not SPOTLIGHT_VULNS_AVAILABLE:
            return {"success": False, "error": "SpotlightVulnerabilities client not available"}
        if not ids:
            return {"success": False, "error": "ids list is required"}
        try:
            svc = self._service(SpotlightVulnerabilities)
            r = svc.get_remediations_v2(ids=ids)
            if r["status_code"] != 200:
                return {"success": False, "error": format_api_error(r, "Failed to get remediations", operation="get_remediations_v2")}
            return {"success": True, "resources": r.get("body", {}).get("resources", [])}
        except Exception as e:
            return {"success": False, "error": f"Error getting remediations: {e}"}
