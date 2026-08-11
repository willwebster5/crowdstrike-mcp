"""
Cloud Security Module — cloud risks, IOM detections, assets, compliance, and timelines.

Tools:
  cloud_get_risks             — Cloud security risks ranked by score
  cloud_get_iom_detections    — IOM detections with MITRE and remediation
  cloud_query_assets          — Cloud asset inventory across providers
  cloud_compliance_by_account — Compliance posture by account/region
  cloud_get_risk_timeline     — Enriched risk/change timeline for one asset (GCRN)
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated, Optional

from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

try:
    from falconpy import CloudSecurity

    CLOUD_SECURITY_AVAILABLE = True
except ImportError:
    CLOUD_SECURITY_AVAILABLE = False

try:
    from falconpy import CloudSecurityDetections

    DETECTIONS_AVAILABLE = True
except ImportError:
    DETECTIONS_AVAILABLE = False

try:
    from falconpy import CloudSecurityAssets

    ASSETS_AVAILABLE = True
except ImportError:
    ASSETS_AVAILABLE = False

try:
    from falconpy import APIHarnessV2

    HARNESS_AVAILABLE = True
except ImportError:
    HARNESS_AVAILABLE = False


# Falconpy operation id for GET /cloud-security-timeline/entities/cloud-risks-enriched-timeline/v1.
# As of falconpy 1.6.1 the endpoint is not wrapped as a native operation, so we call it via
# APIHarnessV2.command(override=TIMELINE_OVERRIDE, ...). The operation id below is the
# anticipated swagger operationId used for scope lookup; when falconpy adds the native
# operation (tracked as follow-up in the FR08 design doc), replace the override call
# with `harness.command(TIMELINE_OPERATION_ID, parameters=...)`.
TIMELINE_OPERATION_ID = "GetCloudRisksEnrichedTimeline"
TIMELINE_OVERRIDE = "GET,/cloud-security-timeline/entities/cloud-risks-enriched-timeline/v1"


def _apply_since_to_risks(risks: list[dict], since: str) -> list[dict]:
    """Drop risk events older than ``since``; drop risk instances that become empty."""
    # Lexicographic comparison is safe for ISO-8601 with a consistent Z suffix, as emitted
    # by GetCloudRisksEnrichedTimeline. If the upstream format ever drifts (offset form,
    # naive timestamps), parse to datetime first.
    out: list[dict] = []
    for r in risks:
        kept = [e for e in r["events"] if e["occurred_at"] >= since]
        if kept:
            out.append({**r, "events": kept})
    return out


def _apply_since_to_changes(changes: list[dict], since: str) -> list[dict]:
    """Drop configuration_change resource_events older than ``since``; drop changes that become empty."""
    # Lexicographic comparison is safe for ISO-8601 with a consistent Z suffix, as emitted
    # by GetCloudRisksEnrichedTimeline. If the upstream format ever drifts (offset form,
    # naive timestamps), parse to datetime first.
    out: list[dict] = []
    for c in changes:
        kept = [ev for ev in c["resource_events"] if ev["timestamp"] >= since]
        if kept:
            out.append({**c, "resource_events": kept})
    return out


def _build_merged_timeline(risks: list[dict], changes: list[dict], max_results: int) -> list[dict]:
    """Event-level merge: one row per risk event and per configuration_change resource_event.

    Each row carries at minimum: kind ('risk' or 'change'), timestamp, source_id, plus
    kind-specific context (event_type + rule_name + severity for risk rows; event_name
    + asset_revision + user_id + user_name for change rows). Rows are sorted descending
    by timestamp; on tied timestamps, risk rows precede change rows (a risk_reopened
    event belongs above the config change that triggered it). Trimmed to ``max_results``.

    Risk instances with no events emit a single synthetic row at ``last_seen`` tagged
    event_type='risk_current_state' and carrying ``synthetic: True`` so downstream
    renderers can distinguish them from real events.
    """
    rows: list[dict] = []

    for r in risks:
        if r["events"]:
            for e in r["events"]:
                rows.append(
                    {
                        "kind": "risk",
                        "event_type": e["event_type"],
                        "timestamp": e["occurred_at"],
                        "source_id": r["id"],
                        "rule_name": r["rule_name"],
                        "severity": r["severity"],
                    }
                )
        else:
            rows.append(
                {
                    "kind": "risk",
                    "event_type": "risk_current_state",
                    "timestamp": r["last_seen"],
                    "source_id": r["id"],
                    "rule_name": r["rule_name"],
                    "severity": r["severity"],
                    "synthetic": True,
                }
            )

    for c in changes:
        for ev in c["resource_events"]:
            rows.append(
                {
                    "kind": "change",
                    "event_name": ev["event_name"],
                    "timestamp": ev["timestamp"],
                    "source_id": c["id"],
                    "asset_revision": c["asset_revision"],
                    "user_id": ev["user_id"],
                    "user_name": ev["user_name"],
                }
            )

    # Secondary key: risks before changes on tied timestamps so a risk_reopened event
    # renders above the config change that triggered it. Making it explicit converts
    # what was stable-sort-incidental into a documented contract.
    _kind_order = {"risk": 0, "change": 1}
    rows.sort(
        key=lambda row: (row["timestamp"], -_kind_order[row["kind"]]),
        reverse=True,
    )
    return rows[:max_results]


class CloudSecurityModule(BaseModule):
    """Cloud security posture and detection data."""

    def __init__(self, client):
        super().__init__(client)

        if not any([CLOUD_SECURITY_AVAILABLE, DETECTIONS_AVAILABLE, ASSETS_AVAILABLE]):
            raise ImportError("No cloud security FalconPy classes available. Ensure crowdstrike-falconpy >= 1.6.0 is installed.")

        available = [
            n
            for n, flag in [
                ("CloudSecurity", CLOUD_SECURITY_AVAILABLE),
                ("Detections", DETECTIONS_AVAILABLE),
                ("Assets", ASSETS_AVAILABLE),
            ]
            if flag
        ]
        self._log(f"Initialized ({', '.join(available)})")

    def register_resources(self, server: FastMCP) -> None:
        from crowdstrike_mcp.resources.fql_guides import CLOUD_ASSETS_FQL, CLOUD_IOM_FQL, CLOUD_RISKS_FQL

        def _make_fn(text):
            def fn():
                return text

            return fn

        for uri, content in [
            ("falcon://fql/cloud-risks", CLOUD_RISKS_FQL),
            ("falcon://fql/cloud-iom", CLOUD_IOM_FQL),
            ("falcon://fql/cloud-assets", CLOUD_ASSETS_FQL),
        ]:
            server.resource(uri, name=uri.split("/")[-1], description=f"FQL syntax: {uri}")(_make_fn(content))
            self.resources.append(uri)

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.cloud_get_risks,
            name="cloud_get_risks",
            description=(
                "Query cloud security risks ranked by score. "
                "Shows misconfigurations, unused identities, and exposure risks "
                "across AWS/Azure/GCP with severity, status, and asset details."
            ),
        )
        self._add_tool(
            server,
            self.cloud_get_iom_detections,
            name="cloud_get_iom_detections",
            description=(
                "Query IOM (Indicator of Misconfiguration) detections from CSPM. "
                "Returns evaluations with MITRE ATT&CK mappings, compliance framework "
                "references (CIS, NIST, PCI, etc.), and remediation steps."
            ),
        )
        self._add_tool(
            server,
            self.cloud_query_assets,
            name="cloud_query_assets",
            description=(
                "Query cloud asset inventory across AWS/Azure/GCP. "
                "Returns resource details including type, region, tags, configuration, "
                "and status. Use resource_id to look up a specific asset by ID "
                "(e.g. security group, EC2 instance, RDS instance)."
            ),
        )
        self._add_tool(
            server,
            self.cloud_compliance_by_account,
            name="cloud_compliance_by_account",
            description=("Get compliance posture aggregated by account and region. Shows compliance control results with resource counts and severities."),
        )
        if HARNESS_AVAILABLE:
            self._add_tool(
                server,
                self.cloud_get_risk_timeline,
                name="cloud_get_risk_timeline",
                description=(
                    "Retrieve the Falcon Cloud Security enriched timeline for a cloud "
                    "asset by GCRN: risk-instance history (open/close/reopen events), "
                    "configuration changes, and the actors behind them. Answers "
                    "'how did this risk get here?' for a single asset."
                ),
            )

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    async def cloud_get_risks(
        self,
        severity: Annotated[Optional[str], "Filter by severity level ('critical', 'high', 'medium', 'low')"] = None,
        status: Annotated[Optional[str], "Filter by risk status ('open', 'resolved')"] = None,
        provider: Annotated[Optional[str], "Filter by cloud provider ('aws', 'azure', 'gcp')"] = None,
        account_id: Annotated[Optional[str], "Filter by specific cloud account ID"] = None,
        max_results: Annotated[int, "Maximum risks to return (default: 50)"] = 50,
    ) -> str:
        """Query cloud security risks with filtering."""
        result = self._get_cloud_risks(severity, status, provider, account_id, max_results)

        if not result.get("success"):
            return format_text_response(f"Failed to get cloud risks: {result.get('error')}", raw=True)

        risks = result["risks"]
        lines = [
            f"Cloud Security Risks: {result['count']} returned (of {result['total']} total, sorted by score desc)",
            "",
        ]

        if not risks:
            lines.append("No cloud risks found matching the filters.")
        else:
            for i, r in enumerate(risks, 1):
                lines.append(f"{i}. [{r['severity']}] {r['rule_name']} (score: {r['score']})")
                lines.append(f"   {r['provider']} | Account: {r['account_id']} | Asset: {r['asset_type']} ({r['asset_id']})")
                lines.append(f"   Status: {r['status']} | Category: {r['service_category']}")
                if r.get("rule_description"):
                    lines.append(f"   {r['rule_description'][:200]}")
                lines.append("")

        return format_text_response(
            "\n".join(lines),
            tool_name="cloud_get_risks",
            raw=True,
            structured_data={"risks": risks},
            metadata={"severity": severity, "status": status, "provider": provider, "account_id": account_id},
        )

    async def cloud_get_iom_detections(
        self,
        severity: Annotated[Optional[str], "Filter by severity level"] = None,
        provider: Annotated[Optional[str], "Filter by cloud provider"] = None,
        account_id: Annotated[Optional[str], "Filter by cloud account ID"] = None,
        resource_type: Annotated[Optional[str], "Filter by resource type (e.g. 'AWS::EC2::SecurityGroup')"] = None,
        max_results: Annotated[int, "Maximum detections to return (default: 20)"] = 20,
    ) -> str:
        """Query IOM detections with MITRE and compliance mappings."""
        result = self._get_iom_detections(severity, provider, account_id, resource_type, max_results)

        if not result.get("success"):
            return format_text_response(f"Failed to get IOM detections: {result.get('error')}", raw=True)

        detections = result["detections"]
        lines = [
            f"IOM Detections: {result['count']} returned (of {result['total']} total evaluations)",
            "",
        ]

        if not detections:
            lines.append("No IOM detections found matching the filters.")
        else:
            for i, d in enumerate(detections, 1):
                lines.append(f"{i}. [{d['severity']}] {d['rule_name']} (status: {d['status']})")
                lines.append(f"   {d['cloud_provider']} | Account: {d['account_id']} | Region: {d['region']}")
                lines.append(f"   Resource: {d['resource_type']} ({d['resource_id']})")
                if d.get("mitre_technique_id"):
                    lines.append(f"   MITRE: {d['mitre_tactic']} / {d['mitre_technique']} ({d['mitre_technique_id']})")
                if d.get("compliance_controls"):
                    lines.append(f"   Compliance: {'; '.join(d['compliance_controls'][:3])}")
                if d.get("remediation"):
                    lines.append(f"   Remediation: {d['remediation'][:200]}")
                if d.get("console_url"):
                    lines.append(f"   Console: {d['console_url']}")
                lines.append("")

        return format_text_response(
            "\n".join(lines),
            tool_name="cloud_get_iom_detections",
            raw=True,
            structured_data={"records": detections},
            metadata={"severity": severity, "provider": provider, "account_id": account_id, "resource_type": resource_type},
        )

    async def cloud_query_assets(
        self,
        provider: Annotated[Optional[str], "Filter by cloud provider"] = None,
        account_id: Annotated[Optional[str], "Filter by cloud account ID"] = None,
        resource_type: Annotated[Optional[str], "Filter by resource type (e.g. 'AWS::EC2::Instance')"] = None,
        region: Annotated[Optional[str], "Filter by region (e.g. 'us-east-1')"] = None,
        resource_id: Annotated[Optional[str], "Filter by specific resource ID"] = None,
        max_results: Annotated[int, "Maximum assets to return (default: 20)"] = 20,
    ) -> str:
        """Query cloud asset inventory."""
        result = self._query_assets(provider, account_id, resource_type, region, resource_id, max_results)

        if not result.get("success"):
            return format_text_response(f"Failed to query assets: {result.get('error')}", raw=True)

        assets = result["assets"]
        lines = [
            f"Cloud Assets: {result['count']} returned (of {result['total']} total)",
            "",
        ]

        if not assets:
            lines.append("No assets found matching the filters.")
        else:
            for i, a in enumerate(assets, 1):
                active_str = "active" if a.get("active") else "inactive"
                lines.append(f"{i}. [{a['cloud_provider']}] {a['resource_type']} ({active_str})")
                lines.append(f"   ID: {a['resource_id']}")
                if a.get("resource_name"):
                    lines.append(f"   Name: {a['resource_name']}")
                lines.append(f"   Account: {a['account_id']} | Region: {a['region']} | Service: {a['service']}")
                if a.get("tags"):
                    tags_str = ", ".join(f"{k}={v}" for k, v in list(a["tags"].items())[:5])
                    lines.append(f"   Tags: {tags_str}")
                if a.get("cloud_context"):
                    ctx = a["cloud_context"]
                    ctx_parts = []
                    if "publicly_exposed" in ctx:
                        ctx_parts.append(f"publicly_exposed={ctx['publicly_exposed']}")
                    if ctx_parts:
                        lines.append(f"   Cloud Context: {', '.join(ctx_parts)}")
                if a.get("configuration"):
                    lines.append(f"   Configuration: {json.dumps(a['configuration'], default=str)}")
                if a.get("relationships"):
                    for rel in a["relationships"][:5]:
                        lines.append(f"   Relationship: {rel.get('relationship_name', '')} {rel.get('resource_type', '')} ({rel.get('resource_id', '')})")
                lines.append("")

        return format_text_response(
            "\n".join(lines),
            tool_name="cloud_query_assets",
            raw=True,
            structured_data={"records": assets},
            metadata={"provider": provider, "account_id": account_id, "resource_type": resource_type, "region": region},
        )

    async def cloud_compliance_by_account(
        self,
        max_results: Annotated[int, "Maximum entries to return (default: 50)"] = 50,
    ) -> str:
        """Get compliance posture aggregated by account and region."""
        result = self._get_compliance_by_account(max_results)

        if not result.get("success"):
            return format_text_response(f"Failed to get compliance data: {result.get('error')}", raw=True)

        entries = result["compliance"]
        lines = [
            f"Compliance by Account: {result['count']} entries (of {result['total']} total)",
            "",
        ]

        if not entries:
            lines.append("No compliance data found.")
        else:
            for i, c in enumerate(entries, 1):
                lines.append(f"{i}. [{c['cloud_provider']}] Account: {c['account_id']} Region: {c['region']}")
                lines.append(f"   Service: {c['service']} ({c['service_category']}) | Resource: {c['resource_type']}")
                if c.get("resource_counts"):
                    lines.append(f"   Resource counts: {json.dumps(c['resource_counts'])}")
                if c.get("severities"):
                    lines.append(f"   Severities: {json.dumps(c['severities'])}")
                lines.append("")

        return format_text_response(
            "\n".join(lines),
            tool_name="cloud_compliance_by_account",
            raw=True,
            structured_data={"records": entries},
            metadata={"max_results": max_results},
        )

    async def cloud_get_risk_timeline(
        self,
        asset_id: Annotated[str, "GCRN (Global Cloud Resource Name) of the cloud asset"],
        risk_id: Annotated[Optional[str], "Filter to a single risk instance by its id"] = None,
        since: Annotated[Optional[str], "ISO-8601 timestamp; drop events/changes older than this"] = None,
        full: Annotated[bool, "Return the raw JSON payload instead of the projected summary"] = False,
        max_results: Annotated[int, "Cap on total merged timeline rows rendered (default: 50)"] = 50,
    ) -> str:
        """Retrieve the enriched cloud-risk timeline for a single asset (GCRN)."""
        result = self._get_risk_timeline(
            asset_id=asset_id,
            risk_id=risk_id,
            since=since,
            full=full,
            max_results=max_results,
        )

        if not result.get("success"):
            return format_text_response(result.get("error", "Unknown error"), raw=True)

        # Empty timeline (200 + empty resources) — surface the "no timeline" message.
        if not result["risks"] and not result["changes"] and result.get("message"):
            return format_text_response(result["message"], raw=True)

        if full:
            return format_text_response(
                json.dumps(result, default=str, indent=2),
                tool_name="cloud_get_risk_timeline",
                raw=True,
                structured_data={"risks": result.get("risks", []), "changes": result.get("changes", [])},
                metadata={"asset_id": asset_id, "risk_id": risk_id, "since": since, "full": True},
            )

        asset = result["asset"]
        lines: list[str] = [
            f"Cloud Risk Timeline for {asset.get('id', asset_id)}",
            f"Asset: {asset.get('type', '')} in "
            f"{asset.get('cloud_provider', '')}/{asset.get('account_id', '')}/{asset.get('region', '')}"
            f" (resource_id={asset.get('resource_id', '')})",
            "",
        ]

        risks = result["risks"]
        lines.append(f"Risks: {result['total_risks']} total")
        for i, r in enumerate(risks, 1):
            lines.append(
                f"  {i}. [{r['severity'].upper()}] {r['rule_name']}  "
                f"status={r['current_status']}  first_seen={r['first_seen']}  last_seen={r['last_seen']}"
            )
            if r.get("reason"):
                reason = r["reason"]
                suffix = "..." if len(reason) > 200 else ""
                lines.append(f"     reason: {reason[:200]}{suffix}")
            if r["events"]:
                ev_str = "; ".join(f"{e['event_type']} @ {e['occurred_at']}" for e in r["events"][:5])
                more = len(r["events"]) - 5
                if more > 0:
                    ev_str += f"; (+{more} more)"
                lines.append(f"     events: {ev_str}")
        lines.append("")

        changes = result["changes"]
        lines.append(f"Configuration changes: {result['total_changes']} total")
        for i, c in enumerate(changes, 1):
            lines.append(f"  {i}. {c['updated_at']}  rev {c['asset_revision']}  {c['external_asset_type']}")
            if c.get("changes"):
                chg_str = "; ".join(f"{ch['action']} {ch['attribute']}" for ch in c["changes"][:5])
                more = len(c["changes"]) - 5
                if more > 0:
                    chg_str += f"; (+{more} more)"
                lines.append(f"     changes: {chg_str}")
            rev = c.get("resource_events", [])
            for ev in rev[:3]:
                lines.append(f"     triggered by: {ev.get('event_name', '')} user={ev.get('user_name', ev.get('user_id', ''))}")
            more_rev = len(rev) - 3
            if more_rev > 0:
                lines.append(f"     (+{more_rev} more triggers)")
        lines.append("")

        tl = result["timeline"]
        lines.append(f"Merged timeline (most recent first, up to {max_results}):")
        for row in tl:
            if row["kind"] == "risk":
                synth_tag = " (current state)" if row.get("synthetic") else ""
                lines.append(f"  {row['timestamp']}  risk     {row['event_type']}{synth_tag}  {row.get('rule_name', '')}")
            else:
                lines.append(
                    f"  {row['timestamp']}  change   rev{row.get('asset_revision', '?')}  "
                    f"{row.get('event_name', '')} by {row.get('user_name', row.get('user_id', ''))}"
                )

        return format_text_response(
            "\n".join(lines),
            tool_name="cloud_get_risk_timeline",
            raw=True,
            structured_data={"records": tl, "risks": result.get("risks", [])},
            metadata={"asset_id": asset_id, "risk_id": risk_id, "since": since},
        )

    # ------------------------------------------------------------------
    # Internal methods (logic from handlers/cloud_security.py)
    # ------------------------------------------------------------------

    def _get_cloud_risks(self, severity=None, status=None, provider=None, account_id=None, max_results=50):
        if not CLOUD_SECURITY_AVAILABLE:
            return {"success": False, "error": "CloudSecurity client not available"}
        try:
            cloud_security = self._service(CloudSecurity)
            filter_parts = []
            if severity:
                filter_parts.append(f"severity:'{severity}'")
            if status:
                filter_parts.append(f"status:'{status}'")
            if provider:
                filter_parts.append(f"cloud_provider:'{provider}'")
            if account_id:
                filter_parts.append(f"account_id:'{account_id}'")

            kwargs = {"limit": min(max_results, 100), "sort": "severity|desc"}
            if filter_parts:
                kwargs["filter"] = "+".join(filter_parts)

            r = cloud_security.combined_cloud_risks(**kwargs)
            if r["status_code"] != 200:
                return {"success": False, "error": format_api_error(r, "Failed to get cloud risks", operation="combined_cloud_risks")}

            resources = r.get("body", {}).get("resources", [])
            total = r.get("body", {}).get("meta", {}).get("pagination", {}).get("total", len(resources))

            risks = []
            for risk in resources:
                risks.append(
                    {
                        "id": risk.get("id", ""),
                        "rule_name": risk.get("rule_name", ""),
                        "rule_description": risk.get("rule_description", "")[:300],
                        "severity": risk.get("severity", ""),
                        "score": risk.get("score", 0),
                        "status": risk.get("status", ""),
                        "provider": risk.get("provider", ""),
                        "account_id": risk.get("account_id", ""),
                        "account_name": risk.get("account_name", ""),
                        "asset_type": risk.get("asset_type", ""),
                        "asset_id": risk.get("asset_id", ""),
                        "asset_name": risk.get("asset_name", ""),
                        "asset_region": risk.get("asset_region", ""),
                        "service_category": risk.get("service_category", ""),
                        "insight_categories": risk.get("insight_categories", []),
                        "first_seen": risk.get("first_seen", ""),
                        "last_seen": risk.get("last_seen", ""),
                    }
                )

            return {"success": True, "risks": risks, "count": len(risks), "total": total}
        except Exception as e:
            return {"success": False, "error": f"Error getting cloud risks: {e}"}

    def _get_iom_detections(self, severity=None, provider=None, account_id=None, resource_type=None, max_results=20):
        if not DETECTIONS_AVAILABLE:
            return {"success": False, "error": "CloudSecurityDetections client not available"}
        try:
            detections = self._service(CloudSecurityDetections)
            filter_parts = []
            if severity:
                filter_parts.append(f"severity:'{severity}'")
            if provider:
                filter_parts.append(f"cloud_provider:'{provider}'")
            if account_id:
                filter_parts.append(f"account_id:'{account_id}'")
            if resource_type:
                filter_parts.append(f"resource_type:'{resource_type}'")

            kwargs = {"limit": min(max_results, 100)}
            if filter_parts:
                kwargs["filter"] = "+".join(filter_parts)

            r = detections.query_iom_entities(**kwargs)
            if r["status_code"] != 200:
                return {"success": False, "error": format_api_error(r, "Failed to query IOM entities", operation="query_iom_entities")}

            iom_ids = r.get("body", {}).get("resources", [])
            total = r.get("body", {}).get("meta", {}).get("pagination", {}).get("total", len(iom_ids))

            if not iom_ids:
                return {"success": True, "detections": [], "count": 0, "total": total}

            r2 = detections.get_iom_entities(ids=iom_ids)
            if r2["status_code"] != 200:
                return {"success": False, "error": format_api_error(r2, "Failed to get IOM entity details", operation="get_iom_entities")}

            entities = r2.get("body", {}).get("resources", [])

            detections = []
            for e in entities:
                cloud = e.get("cloud", {})
                resource = e.get("resource", {})
                evaluation = e.get("evaluation", {})
                rule = evaluation.get("rule", {})
                threat = rule.get("threat", {})

                detections.append(
                    {
                        "id": e.get("id", ""),
                        "cloud_provider": cloud.get("provider", ""),
                        "account_id": cloud.get("account_id", ""),
                        "region": cloud.get("region", ""),
                        "resource_type": resource.get("resource_type_name", resource.get("resource_type", "")),
                        "resource_id": resource.get("resource_id", ""),
                        "resource_tags": resource.get("tags", {}),
                        "severity": evaluation.get("severity", ""),
                        "status": evaluation.get("status", ""),
                        "rule_name": rule.get("name", ""),
                        "rule_description": rule.get("description", "")[:400],
                        "mitre_tactic": threat.get("tactic", {}).get("name", ""),
                        "mitre_technique": threat.get("technique", {}).get("name", ""),
                        "mitre_technique_id": threat.get("technique", {}).get("id", ""),
                        "remediation": rule.get("remediation", "")[:500],
                        "compliance_controls": [
                            f"{c.get('framework', '')}: {c.get('name', '')} ({c.get('requirement', '')})" for c in rule.get("controls", [])[:5]
                        ],
                        "console_url": evaluation.get("url", ""),
                    }
                )

            return {"success": True, "detections": detections, "count": len(detections), "total": total}
        except Exception as e:
            return {"success": False, "error": f"Error getting IOM detections: {e}"}

    def _query_assets(self, provider=None, account_id=None, resource_type=None, region=None, resource_id=None, max_results=20):
        if not ASSETS_AVAILABLE:
            return {"success": False, "error": "CloudSecurityAssets client not available"}
        try:
            assets = self._service(CloudSecurityAssets)
            filter_parts = []
            if provider:
                filter_parts.append(f"cloud_provider:'{provider}'")
            if account_id:
                filter_parts.append(f"account_id:'{account_id}'")
            if resource_type:
                filter_parts.append(f"resource_type:'{resource_type}'")
            if region:
                filter_parts.append(f"region:'{region}'")
            if resource_id:
                filter_parts.append(f"resource_id:'{resource_id}'")

            kwargs = {"limit": min(max_results, 100)}
            if filter_parts:
                kwargs["filter"] = "+".join(filter_parts)

            r = assets.query_assets(**kwargs)
            if r["status_code"] != 200:
                return {"success": False, "error": format_api_error(r, "Failed to query assets", operation="query_assets")}

            asset_ids = r.get("body", {}).get("resources", [])
            total = r.get("body", {}).get("meta", {}).get("pagination", {}).get("total", len(asset_ids))

            if not asset_ids:
                return {"success": True, "assets": [], "count": 0, "total": total}

            r2 = assets.get_assets(ids=asset_ids)
            if r2["status_code"] != 200:
                return {"success": False, "error": format_api_error(r2, "Failed to get asset details", operation="get_assets")}

            entities = r2.get("body", {}).get("resources", [])

            assets = []
            for a in entities:
                assets.append(
                    {
                        "id": a.get("id", ""),
                        "cloud_provider": a.get("cloud_provider", ""),
                        "account_id": a.get("account_id", ""),
                        "account_name": a.get("account_name", ""),
                        "region": a.get("region", ""),
                        "resource_type": a.get("resource_type_name", a.get("resource_type", "")),
                        "resource_id": a.get("resource_id", ""),
                        "resource_name": a.get("resource_name", ""),
                        "service": a.get("service", ""),
                        "service_category": a.get("service_category", ""),
                        "active": a.get("active", False),
                        "creation_time": a.get("creation_time", ""),
                        "first_seen": a.get("first_seen", ""),
                        "tags": a.get("tags", {}),
                        "configuration": a.get("configuration", {}),
                        "relationships": a.get("relationships", []),
                        "cloud_context": a.get("cloud_context", {}),
                    }
                )

            return {"success": True, "assets": assets, "count": len(assets), "total": total}
        except Exception as e:
            return {"success": False, "error": f"Error querying assets: {e}"}

    def _get_compliance_by_account(self, max_results=50):
        if not ASSETS_AVAILABLE:
            return {"success": False, "error": "CloudSecurityAssets client not available"}
        try:
            assets = self._service(CloudSecurityAssets)
            r = assets.get_combined_compliance_by_account(limit=min(max_results, 100))
            if r["status_code"] != 200:
                return {"success": False, "error": format_api_error(r, "Failed to get compliance data", operation="get_combined_compliance_by_account")}

            resources = r.get("body", {}).get("resources", [])
            total = r.get("body", {}).get("meta", {}).get("pagination", {}).get("total", len(resources))

            entries = []
            for c in resources:
                entries.append(
                    {
                        "account_id": c.get("account_id", ""),
                        "account_name": c.get("account_name", ""),
                        "cloud_provider": c.get("cloud_provider", ""),
                        "region": c.get("region", ""),
                        "service": c.get("service", ""),
                        "service_category": c.get("service_category", ""),
                        "resource_type": c.get("resource_type_name", c.get("resource_type", "")),
                        "control": c.get("control", ""),
                        "resource_counts": c.get("resource_counts", {}),
                        "severities": c.get("severities", {}),
                        "last_evaluated": c.get("last_evaluated", ""),
                    }
                )

            return {"success": True, "compliance": entries, "count": len(entries), "total": total}
        except Exception as e:
            return {"success": False, "error": f"Error getting compliance: {e}"}

    def _get_risk_timeline(self, asset_id, risk_id=None, since=None, full=False, max_results=50):
        if not HARNESS_AVAILABLE:
            return {"success": False, "error": "APIHarnessV2 client not available"}
        try:
            harness = self._service(APIHarnessV2)
            r = harness.command(
                override=TIMELINE_OVERRIDE,
                parameters={"id": asset_id},
            )

            if r["status_code"] != 200:
                err = format_api_error(
                    r,
                    "Failed to get cloud risk timeline",
                    operation=TIMELINE_OPERATION_ID,
                )
                if r["status_code"] == 429:
                    err += "\n\nRate limit: this endpoint allows 500 requests/min per CID."
                return {"success": False, "error": err}

            resources = r.get("body", {}).get("resources", [])
            if not resources:
                return {
                    "success": True,
                    "asset": {},
                    "risks": [],
                    "changes": [],
                    "timeline": [],
                    "total_risks": 0,
                    "total_changes": 0,
                    "message": (f"No timeline found for GCRN '{asset_id}' (feature may not be enabled on this tenant or GCRN is unknown)."),
                }

            entry = resources[0]
            a = entry.get("asset", {}) or {}
            tl = entry.get("timeline", {}) or {}

            asset = {
                "id": a.get("id", ""),
                "cloud_provider": a.get("cloud_provider", ""),
                "account_id": a.get("account_id", ""),
                "account_name": a.get("account_name", ""),
                "region": a.get("region", ""),
                "resource_id": a.get("resource_id", ""),
                "type": a.get("type", ""),
            }

            risks = []
            for ri in (tl.get("risks", {}) or {}).get("risk_instances", []) or []:
                risks.append(
                    {
                        "id": ri.get("id", ""),
                        "rule_name": ri.get("rule_name", ""),
                        "severity": ri.get("severity", ""),
                        "current_status": ri.get("current_status", ""),
                        "reason": ri.get("reason", ""),
                        "first_seen": ri.get("first_seen", ""),
                        "last_seen": ri.get("last_seen", ""),
                        "resolved_at": ri.get("resolved_at"),
                        "risk_factors_categories": ri.get("risk_factors_categories", []),
                        "events": [
                            {
                                "event_type": e.get("event_type", ""),
                                "occurred_at": e.get("occurred_at", ""),
                            }
                            for e in (ri.get("events") or [])
                        ],
                    }
                )

            changes = []
            for cc in tl.get("configuration_changes", []) or []:
                changes.append(
                    {
                        "id": cc.get("id", ""),
                        "asset_revision": cc.get("asset_revision", 0),
                        "external_asset_type": cc.get("external_asset_type", ""),
                        "updated_at": cc.get("updated_at", ""),
                        "changes": [
                            {
                                "action": ch.get("action", ""),
                                "attribute": ch.get("attribute", ""),
                            }
                            for ch in (cc.get("changes") or [])
                        ],
                        "resource_events": [
                            {
                                "event_name": ev.get("event_name", ""),
                                "timestamp": ev.get("timestamp", ""),
                                "user_id": ev.get("user_id", ""),
                                "user_name": ev.get("user_name", ""),
                            }
                            for ev in (cc.get("resource_events") or [])
                        ],
                    }
                )

            # --- Client-side filters ---
            if risk_id is not None:
                risks = [r for r in risks if r["id"] == risk_id]

            if since is not None:
                risks = _apply_since_to_risks(risks, since)
                changes = _apply_since_to_changes(changes, since)

            return {
                "success": True,
                "asset": asset,
                "risks": risks,
                "changes": changes,
                "timeline": _build_merged_timeline(risks, changes, max_results),
                "total_risks": len(risks),
                "total_changes": len(changes),
            }
        except Exception as e:
            return {"success": False, "error": f"Error getting cloud risk timeline: {e}"}
