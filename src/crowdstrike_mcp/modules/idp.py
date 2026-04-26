"""
Identity Protection Module — CrowdStrike Falcon Identity Protection (IDP) via GraphQL.

Tool:
  identity_investigate_entity — One-call entity investigation:
     resolve identifier(s) → run entity_details, risk_assessment, timeline_analysis,
     and/or relationship_analysis → synthesize single response.

Ported from CrowdStrike's falcon-mcp (https://github.com/CrowdStrike/falcon-mcp,
MIT-licensed). See THIRD_PARTY_NOTICES.md at the repo root.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Annotated, Any, Optional

try:
    from falconpy import IdentityProtection

    IDENTITY_PROTECTION_AVAILABLE = True
except ImportError:
    IDENTITY_PROTECTION_AVAILABLE = False

from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from fastmcp import FastMCP


# Allowed enum values (mirrored from upstream + CrowdStrike GraphQL schema)
VALID_INVESTIGATION_TYPES = {
    "entity_details",
    "risk_assessment",
    "timeline_analysis",
    "relationship_analysis",
}
VALID_TIMELINE_EVENT_TYPES = {
    "ACTIVITY",
    "NOTIFICATION",
    "THREAT",
    "ENTITY",
    "AUDIT",
    "POLICY",
    "SYSTEM",
}


class IDPModule(BaseModule):
    """Falcon Identity Protection tools (GraphQL-backed)."""

    def __init__(self, client):
        super().__init__(client)
        if not IDENTITY_PROTECTION_AVAILABLE:
            raise ImportError("IdentityProtection service class not available. Ensure crowdstrike-falconpy >= 1.6.1 is installed.")
        self._log("Initialized")

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.identity_investigate_entity,
            name="identity_investigate_entity",
            description=(
                "Falcon Identity Protection: investigate a user/device entity by name, "
                "email, IP, domain, or entity ID. Returns identity risk score + risk "
                "factors, AD/SSO/Azure account descriptors, open incidents, activity "
                "timeline, and/or nested relationship graph — any combination in one "
                "call. Primary triage tool for 'does Falcon consider this user "
                "identity-compromised?'."
            ),
            tier="read",
        )

    # --------------------------------------------------
    # Core GraphQL helper — single place that talks to falconpy
    # --------------------------------------------------
    def _graphql_call(self, query: str, context: str) -> dict[str, Any]:
        """Run a GraphQL query. Handles transport + GraphQL-level errors.

        Returns:
            On success: {"success": True, "data": <top-level data dict>}
            On failure: {"success": False, "error": "<message>"}
        """
        try:
            svc = self._service(IdentityProtection)
            response = svc.graphql(body={"query": query})
        except Exception as exc:
            return {"success": False, "error": f"{context}: {exc}"}

        status = response.get("status_code", 0)
        body = response.get("body", {}) or {}

        # Transport-level failure (non-2xx) — defer to format_api_error for scope msg
        if not (200 <= status < 300):
            return {
                "success": False,
                "error": format_api_error(response, context=context, operation="post_graphql"),
            }

        # GraphQL-level errors can arrive on HTTP 200. Treat non-empty errors[] as failure.
        gql_errors = body.get("errors")
        if isinstance(gql_errors, list) and gql_errors:
            msgs = [e.get("message", str(e)) if isinstance(e, dict) else str(e) for e in gql_errors]
            return {"success": False, "error": f"{context}: GraphQL error: {'; '.join(msgs)}"}

        return {"success": True, "data": body.get("data", {}) or {}}

    # NOTE: do NOT add a "sanitize" helper that strips backslashes/quotes.
    # `json.dumps()` already escapes GraphQL-unsafe characters correctly, and
    # stripping them silently corrupts legitimate AD values (e.g. `DOMAIN\\user`).

    # --------------------------------------------------
    # Entity resolution
    # --------------------------------------------------
    def _resolve_entities(self, identifiers: dict[str, Any]) -> list[str] | dict[str, Any]:
        """Resolve various identifier kinds to entity IDs via a single AND-combined
        GraphQL query. entity_ids pass through unchanged.

        Returns:
            list[str]: resolved entity ids (de-duplicated) on success
            dict: {"error": "..."} on GraphQL/transport failure
        """
        resolved_ids: list[str] = []

        # Direct entity IDs — no resolution needed
        direct_ids = identifiers.get("entity_ids")
        if direct_ids and isinstance(direct_ids, list):
            resolved_ids.extend(direct_ids)

        emails = identifiers.get("email_addresses")
        ips = identifiers.get("ip_addresses")
        has_user = bool(emails)
        has_endpoint = bool(ips)

        # USER and ENDPOINT types are mutually exclusive in a single `entities()` query;
        # prioritise USER because the triage workflow centres on user identity risk.
        if has_user and has_endpoint:
            self._log("WARN: email + IP supplied; dropping IP filter (USER wins)")
            ips = None
            has_endpoint = False

        query_filters: list[str] = []
        query_fields: set[str] = set()

        self._add_name_filter(identifiers.get("entity_names"), query_fields, query_filters)
        self._add_email_filter(emails, query_fields, query_filters)
        self._add_ip_filter(ips, has_user, query_fields, query_filters)
        domain_names = self._add_domain_filter(identifiers.get("domain_names"), query_fields, query_filters)

        if query_filters:
            limit = identifiers.get("limit") or 50
            fields_string = "\n                ".join(sorted(query_fields))
            if domain_names:
                fields_string += """
                accounts {
                    ... on ActiveDirectoryAccountDescriptor {
                        domain
                        samAccountName
                    }
                }"""
            query = f"""
            query {{
                entities({", ".join(query_filters)}, first: {limit}) {{
                    nodes {{
                        entityId
                        {fields_string}
                    }}
                }}
            }}
            """
            result = self._graphql_call(query, context="Failed to resolve entities")
            if not result.get("success"):
                return {"error": result["error"]}
            nodes = result["data"].get("entities", {}).get("nodes", [])
            if isinstance(nodes, list):
                resolved_ids.extend(n.get("entityId") for n in nodes if isinstance(n, dict) and n.get("entityId"))

        return sorted({i for i in resolved_ids if i})

    def _add_name_filter(self, names, fields, filters):
        if names and isinstance(names, list):
            vals = json.dumps(list(names))
            filters.append(f"primaryDisplayNames: {vals}")
            fields.add("primaryDisplayName")

    def _add_email_filter(self, emails, fields, filters):
        if emails and isinstance(emails, list):
            vals = json.dumps(list(emails))
            filters.append(f"secondaryDisplayNames: {vals}")
            filters.append("types: [USER]")
            fields.add("primaryDisplayName")
            fields.add("secondaryDisplayName")

    def _add_ip_filter(self, ips, has_user, fields, filters):
        if ips and isinstance(ips, list) and not has_user:
            vals = json.dumps(list(ips))
            filters.append(f"primaryDisplayNames: {vals}")
            filters.append("types: [ENDPOINT]")
            fields.add("primaryDisplayName")

    def _add_domain_filter(self, domains, fields, filters):
        if domains and isinstance(domains, list):
            vals = json.dumps(list(domains))
            filters.append(f"domains: {vals}")
            fields.add("primaryDisplayName")
            fields.add("secondaryDisplayName")
            return domains
        return None

    # --------------------------------------------------
    # entity_details
    # --------------------------------------------------
    def _build_entity_details_query(
        self,
        entity_ids: list[str],
        include_risk_factors: bool,
        include_associations: bool,
        include_incidents: bool,
        include_accounts: bool,
    ) -> str:
        ids_json = json.dumps(entity_ids)
        fields = [
            "entityId",
            "primaryDisplayName",
            "secondaryDisplayName",
            "type",
            "riskScore",
            "riskScoreSeverity",
        ]
        if include_risk_factors:
            fields.append("riskFactors { type severity }")
        if include_associations:
            fields.append("""
                associations {
                    bindingType
                    ... on EntityAssociation {
                        entity { entityId primaryDisplayName secondaryDisplayName type }
                    }
                    ... on LocalAdminLocalUserAssociation { accountName }
                    ... on LocalAdminDomainEntityAssociation {
                        entityType
                        entity { entityId primaryDisplayName secondaryDisplayName }
                    }
                    ... on GeoLocationAssociation {
                        geoLocation { country countryCode city cityCode latitude longitude }
                    }
                }""")
        if include_incidents:
            fields.append("""
                openIncidents(first: 10) {
                    nodes {
                        type startTime endTime
                        compromisedEntities { entityId primaryDisplayName }
                    }
                }""")
        if include_accounts:
            fields.append("""
                accounts {
                    ... on ActiveDirectoryAccountDescriptor {
                        domain samAccountName ou servicePrincipalNames
                        passwordAttributes { lastChange strength }
                        expirationTime
                    }
                    ... on SsoUserAccountDescriptor {
                        dataSource mostRecentActivity title creationTime
                        passwordAttributes { lastChange }
                    }
                    ... on AzureCloudServiceAdapterDescriptor {
                        registeredTenantType appOwnerOrganizationId
                        publisherDomain signInAudience
                    }
                    ... on CloudServiceAdapterDescriptor { dataSourceParticipantIdentifier }
                }""")
        fields_str = "\n                ".join(fields)
        return f"""
        query {{
            entities(entityIds: {ids_json}, first: 50) {{
                nodes {{
                    {fields_str}
                }}
            }}
        }}
        """

    def _get_entity_details_batch(self, entity_ids: list[str], options: dict[str, Any]) -> dict[str, Any]:
        query = self._build_entity_details_query(
            entity_ids=entity_ids,
            include_risk_factors=True,
            include_associations=options.get("include_associations", True),
            include_incidents=options.get("include_incidents", True),
            include_accounts=options.get("include_accounts", True),
        )
        result = self._graphql_call(query, context="Failed to get entity details")
        if not result.get("success"):
            return {"error": result["error"]}
        nodes = result["data"].get("entities", {}).get("nodes", []) or []
        nodes = [n for n in nodes if isinstance(n, dict)]
        return {"entities": nodes, "entity_count": len(nodes)}

    # --------------------------------------------------
    # risk_assessment
    # --------------------------------------------------
    def _build_risk_assessment_query(self, entity_ids: list[str], include_factors: bool) -> str:
        ids_json = json.dumps(entity_ids)
        risk = "riskScore\n                riskScoreSeverity"
        if include_factors:
            risk += "\n                riskFactors { type severity }"
        return f"""
        query {{
            entities(entityIds: {ids_json}, first: 50) {{
                nodes {{
                    entityId
                    primaryDisplayName
                    {risk}
                }}
            }}
        }}
        """

    def _assess_risks_batch(self, entity_ids: list[str], options: dict[str, Any]) -> dict[str, Any]:
        query = self._build_risk_assessment_query(entity_ids, options.get("include_risk_factors", True))
        result = self._graphql_call(query, context="Failed to assess risks")
        if not result.get("success"):
            return {"error": result["error"]}
        nodes = result["data"].get("entities", {}).get("nodes", []) or []
        assessments = [
            {
                "entityId": n.get("entityId"),
                "primaryDisplayName": n.get("primaryDisplayName"),
                "riskScore": n.get("riskScore", 0),
                "riskScoreSeverity": n.get("riskScoreSeverity", "LOW"),
                "riskFactors": n.get("riskFactors", []) if isinstance(n.get("riskFactors"), list) else [],
            }
            for n in nodes
            if isinstance(n, dict)
        ]
        return {"risk_assessments": assessments, "entity_count": len(assessments)}

    # --------------------------------------------------
    # timeline_analysis
    # --------------------------------------------------
    _TIMELINE_FRAGMENTS = """
        ... on TimelineUserOnEndpointActivityEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineAuthenticationEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineAlertEvent {
            sourceEntity { entityId primaryDisplayName }
        }
        ... on TimelineDceRpcEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineFailedAuthenticationEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineSuccessfulAuthenticationEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineServiceAccessEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineFileOperationEvent {
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineLdapSearchEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineRemoteCodeExecutionEvent {
            sourceEntity { entityId primaryDisplayName }
            targetEntity { entityId primaryDisplayName }
            geoLocation { country countryCode city cityCode latitude longitude }
            locationAssociatedWithUser userDisplayName endpointDisplayName ipAddress
        }
        ... on TimelineConnectorConfigurationEvent { category }
        ... on TimelineConnectorConfigurationAddedEvent { category }
        ... on TimelineConnectorConfigurationDeletedEvent { category }
        ... on TimelineConnectorConfigurationModifiedEvent { category }
    """

    def _build_timeline_query(
        self,
        entity_id: str,
        start_time: str | None,
        end_time: str | None,
        event_types: list[str] | None,
        limit: int,
    ) -> str:
        filters = [f'sourceEntityQuery: {{entityIds: ["{entity_id}"]}}']
        if isinstance(start_time, str) and start_time:
            filters.append(f'startTime: "{start_time}"')
        if isinstance(end_time, str) and end_time:
            filters.append(f'endTime: "{end_time}"')
        if isinstance(event_types, list) and event_types:
            filters.append(f"categories: [{', '.join(event_types)}]")
        return f"""
        query {{
            timeline({", ".join(filters)}, first: {limit}) {{
                nodes {{
                    eventId eventType eventSeverity timestamp
                    {self._TIMELINE_FRAGMENTS}
                }}
                pageInfo {{ hasNextPage endCursor }}
            }}
        }}
        """

    def _get_entity_timelines_batch(self, entity_ids: list[str], options: dict[str, Any]) -> dict[str, Any]:
        timelines = []
        for eid in entity_ids:
            query = self._build_timeline_query(
                entity_id=eid,
                start_time=options.get("start_time"),
                end_time=options.get("end_time"),
                event_types=options.get("event_types"),
                limit=options.get("limit", 50),
            )
            result = self._graphql_call(query, context=f"Failed to get timeline for '{eid}'")
            if not result.get("success"):
                return {"error": result["error"]}
            tl = result["data"].get("timeline", {}) or {}
            timelines.append(
                {
                    "entity_id": eid,
                    "timeline": tl.get("nodes", []) if isinstance(tl.get("nodes"), list) else [],
                    "page_info": tl.get("pageInfo", {}) if isinstance(tl.get("pageInfo"), dict) else {},
                }
            )
        return {"timelines": timelines, "entity_count": len(entity_ids)}

    # --------------------------------------------------
    # relationship_analysis
    # --------------------------------------------------
    def _build_relationship_query(self, entity_id: str, depth: int, include_risk_context: bool, limit: int) -> str:
        risk_fields = ""
        if include_risk_context:
            risk_fields = """
                riskScore
                riskScoreSeverity
                riskFactors { type severity }
            """

        def associations_block(remaining: int) -> str:
            if remaining <= 0:
                return ""
            nested = associations_block(remaining - 1) if remaining > 1 else ""
            return f"""
                associations {{
                    bindingType
                    ... on EntityAssociation {{
                        entity {{
                            entityId primaryDisplayName secondaryDisplayName type
                            {risk_fields}
                            {nested}
                        }}
                    }}
                    ... on LocalAdminLocalUserAssociation {{ accountName }}
                    ... on LocalAdminDomainEntityAssociation {{
                        entityType
                        entity {{
                            entityId primaryDisplayName secondaryDisplayName type
                            {risk_fields}
                            {nested}
                        }}
                    }}
                    ... on GeoLocationAssociation {{
                        geoLocation {{ country countryCode city cityCode latitude longitude }}
                    }}
                }}
            """

        return f"""
        query {{
            entities(entityIds: ["{entity_id}"], first: {limit}) {{
                nodes {{
                    entityId primaryDisplayName secondaryDisplayName type
                    {risk_fields}
                    {associations_block(depth)}
                }}
            }}
        }}
        """

    def _analyze_relationships_batch(self, entity_ids: list[str], options: dict[str, Any]) -> dict[str, Any]:
        relationships = []
        depth = options.get("relationship_depth", 2)
        for eid in entity_ids:
            query = self._build_relationship_query(
                entity_id=eid,
                depth=depth,
                include_risk_context=options.get("include_risk_context", True),
                limit=options.get("limit", 50),
            )
            result = self._graphql_call(query, context=f"Failed to analyze relationships for '{eid}'")
            if not result.get("success"):
                return {"error": result["error"]}
            nodes = result["data"].get("entities", {}).get("nodes", []) or []
            if nodes and isinstance(nodes[0], dict):
                associations = nodes[0].get("associations", [])
                if not isinstance(associations, list):
                    associations = []
            else:
                associations = []
            relationships.append(
                {
                    "entity_id": eid,
                    "associations": associations,
                    "relationship_count": len(associations),
                }
            )
        return {"relationships": relationships, "entity_count": len(entity_ids)}

    # --------------------------------------------------
    # Public tool + validation + synthesis
    # --------------------------------------------------
    def _validate_params(
        self,
        identifier_lists: list[list[str] | None],
        investigation_types: list[str],
        timeline_event_types: list[str] | None,
        relationship_depth: int,
        limit: int,
    ) -> str | None:
        if not any(identifier_lists):
            return "At least one entity identifier must be provided (username, entity_ids, entity_names, email_addresses, ip_addresses, or domain_names)."
        if not investigation_types:
            return f"investigation_types cannot be empty. Provide any subset of: {sorted(VALID_INVESTIGATION_TYPES)}."
        bad_inv = [t for t in investigation_types if t not in VALID_INVESTIGATION_TYPES]
        if bad_inv:
            return f"Invalid investigation_types: {bad_inv}. Valid values: {sorted(VALID_INVESTIGATION_TYPES)}."
        if timeline_event_types:
            bad_ev = [t for t in timeline_event_types if t not in VALID_TIMELINE_EVENT_TYPES]
            if bad_ev:
                return f"Invalid timeline_event_types: {bad_ev}. Valid values: {sorted(VALID_TIMELINE_EVENT_TYPES)}."
        if not 1 <= relationship_depth <= 3:
            return f"relationship_depth must be between 1 and 3 (got {relationship_depth})."
        if not 1 <= limit <= 200:
            return f"limit must be between 1 and 200 (got {limit})."
        return None

    def _execute_investigation(self, inv_type: str, entity_ids: list[str], params: dict[str, Any]) -> dict[str, Any]:
        if inv_type == "entity_details":
            return self._get_entity_details_batch(
                entity_ids,
                {
                    "include_associations": params["include_associations"],
                    "include_accounts": params["include_accounts"],
                    "include_incidents": params["include_incidents"],
                },
            )
        if inv_type == "risk_assessment":
            return self._assess_risks_batch(entity_ids, {"include_risk_factors": True})
        if inv_type == "timeline_analysis":
            return self._get_entity_timelines_batch(
                entity_ids,
                {
                    "start_time": params.get("timeline_start_time"),
                    "end_time": params.get("timeline_end_time"),
                    "event_types": params.get("timeline_event_types"),
                    "limit": params["limit"],
                },
            )
        if inv_type == "relationship_analysis":
            return self._analyze_relationships_batch(
                entity_ids,
                {
                    "relationship_depth": params["relationship_depth"],
                    "include_risk_context": True,
                    "limit": params["limit"],
                },
            )
        return {"error": f"Unknown investigation type: {inv_type}"}

    def _format_investigation_response(
        self,
        entity_ids: list[str],
        investigation_results: dict[str, dict[str, Any]],
        investigation_types: list[str],
        include_raw: bool,
    ) -> str:
        lines: list[str] = []
        lines.append(f"# Identity Investigation — {len(entity_ids)} entit{'y' if len(entity_ids) == 1 else 'ies'}")
        lines.append("")
        lines.append(f"Investigations run: {', '.join(investigation_types)}")
        lines.append(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
        lines.append(f"Resolved entity IDs: {', '.join(entity_ids)}")
        lines.append("")

        for inv_type in investigation_types:
            r = investigation_results.get(inv_type, {})
            lines.append(f"## {inv_type}")
            lines.append("")
            if inv_type == "entity_details":
                for e in r.get("entities", []):
                    if not isinstance(e, dict):
                        continue
                    lines.append(
                        f"- **{e.get('primaryDisplayName', '?')}** "
                        f"({e.get('type', '?')}) "
                        f"risk={e.get('riskScore', '?')} [{e.get('riskScoreSeverity', '?')}] "
                        f"id=`{e.get('entityId', '?')}`"
                    )
                    factors = e.get("riskFactors") or []
                    if isinstance(factors, list) and factors:
                        top = ", ".join(f"{f.get('type')}({f.get('severity')})" for f in factors[:5] if isinstance(f, dict))
                        lines.append(f"  - Top risk factors: {top}")
                    incidents = ((e.get("openIncidents") or {}).get("nodes") or []) if isinstance(e.get("openIncidents"), dict) else []
                    if incidents:
                        lines.append(f"  - Open incidents: {len(incidents)}")
            elif inv_type == "risk_assessment":
                for ra in r.get("risk_assessments", []):
                    lines.append(
                        f"- **{ra.get('primaryDisplayName', '?')}** "
                        f"risk={ra.get('riskScore', 0)} [{ra.get('riskScoreSeverity', 'LOW')}] "
                        f"id=`{ra.get('entityId', '?')}`"
                    )
                    factors = ra.get("riskFactors") or []
                    if isinstance(factors, list) and factors:
                        for f in factors[:10]:
                            if isinstance(f, dict):
                                lines.append(f"  - {f.get('type', '?')} ({f.get('severity', '?')})")
            elif inv_type == "timeline_analysis":
                for tl in r.get("timelines", []):
                    events = tl.get("timeline", []) or []
                    lines.append(f"- Entity `{tl.get('entity_id', '?')}`: {len(events)} events")
                    for ev in events[:10]:
                        if isinstance(ev, dict):
                            ts = ev.get("timestamp", "?")
                            et = ev.get("eventType", "?")
                            sev = ev.get("eventSeverity", "?")
                            eid = ev.get("eventId", "?")
                            lines.append(f"  - {ts} {et} [{sev}] id=`{eid}`")
            elif inv_type == "relationship_analysis":
                for rel in r.get("relationships", []):
                    assocs = rel.get("associations") or []
                    lines.append(f"- Entity `{rel.get('entity_id', '?')}`: {rel.get('relationship_count', 0)} associations")
                    for a in assocs[:10] if isinstance(assocs, list) else []:
                        if isinstance(a, dict):
                            ent = a.get("entity") or {}
                            if isinstance(ent, dict) and ent:
                                lines.append(f"  - [{a.get('bindingType', '?')}] → {ent.get('primaryDisplayName', '?')} ({ent.get('type', '?')})")
                            else:
                                lines.append(f"  - [{a.get('bindingType', '?')}]")
            lines.append("")

        if include_raw:
            lines.append("## Raw GraphQL results")
            lines.append("```json")
            lines.append(
                json.dumps(
                    {
                        "entity_ids": entity_ids,
                        "investigations": investigation_results,
                    },
                    indent=2,
                    default=str,
                )
            )
            lines.append("```")

        return "\n".join(lines)

    async def identity_investigate_entity(
        self,
        username: Annotated[Optional[str], "Ergonomic shortcut: single username/display name. Merged into entity_names."] = None,
        quick_triage: Annotated[
            bool,
            "One-shot triage mode: forces investigation_types=[entity_details, risk_assessment] "
            "with lean includes (no associations/accounts/incidents, limit=5). Good default for "
            "'does Falcon consider this user compromised?'.",
        ] = False,
        entity_ids: Annotated[Optional[list[str]], "Direct entity IDs to investigate (skip identifier resolution)."] = None,
        entity_names: Annotated[Optional[list[str]], "Entity display names (e.g. ['Administrator']). AND-combined with other identifier kinds."] = None,
        email_addresses: Annotated[Optional[list[str]], "Email addresses (restricts search to USER entities)."] = None,
        ip_addresses: Annotated[Optional[list[str]], "IP addresses (restricts search to ENDPOINT entities). Ignored if email_addresses given."] = None,
        domain_names: Annotated[Optional[list[str]], "Domain names (e.g. ['CORP.LOCAL'])."] = None,
        investigation_types: Annotated[list[str], "Any subset of: entity_details, risk_assessment, timeline_analysis, relationship_analysis."] = None,
        timeline_start_time: Annotated[Optional[str], "ISO-8601 timestamp (timeline_analysis only)."] = None,
        timeline_end_time: Annotated[Optional[str], "ISO-8601 timestamp (timeline_analysis only)."] = None,
        timeline_event_types: Annotated[
            Optional[list[str]], "Filter timeline categories: ACTIVITY, NOTIFICATION, THREAT, ENTITY, AUDIT, POLICY, SYSTEM."
        ] = None,
        relationship_depth: Annotated[int, "Relationship nesting depth 1-3 (relationship_analysis only)."] = 2,
        limit: Annotated[int, "Max results per query (1-200)."] = 10,
        include_associations: Annotated[bool, "Include entity associations in details."] = True,
        include_accounts: Annotated[bool, "Include AD/SSO/Azure account descriptors in details."] = True,
        include_incidents: Annotated[bool, "Include open security incidents in details."] = True,
        include_raw: Annotated[bool, "Append raw GraphQL JSON to the response (default False)."] = False,
    ) -> str:
        """Investigate an identity entity in Falcon IDP.

        Resolves identifier(s) to entity IDs, then runs any combination of
        entity_details / risk_assessment / timeline_analysis / relationship_analysis.
        """
        # Ergonomic shortcuts applied BEFORE validation so the usual
        # identifier/investigation_types rules still run on the merged values.
        if username:
            merged_names = list(entity_names or [])
            if username not in merged_names:
                merged_names.append(username)
            entity_names = merged_names

        if quick_triage:
            investigation_types = ["entity_details", "risk_assessment"]
            include_associations = False
            include_accounts = False
            include_incidents = False
            limit = 5
        elif investigation_types is None:
            investigation_types = ["entity_details"]

        validation_err = self._validate_params(
            [entity_ids, entity_names, email_addresses, ip_addresses, domain_names],
            investigation_types,
            timeline_event_types,
            relationship_depth,
            limit,
        )
        if validation_err:
            return format_text_response(f"Failed: {validation_err}", raw=True)

        resolved = self._resolve_entities(
            {
                "entity_ids": entity_ids,
                "entity_names": entity_names,
                "email_addresses": email_addresses,
                "ip_addresses": ip_addresses,
                "domain_names": domain_names,
                "limit": limit,
            }
        )
        if isinstance(resolved, dict) and "error" in resolved:
            return format_text_response(f"Failed to resolve entities: {resolved['error']}", raw=True)
        if not resolved:
            return format_text_response(
                "No entities found matching the provided criteria.",
                raw=True,
            )

        params = {
            "include_associations": include_associations,
            "include_accounts": include_accounts,
            "include_incidents": include_incidents,
            "timeline_start_time": timeline_start_time,
            "timeline_end_time": timeline_end_time,
            "timeline_event_types": timeline_event_types,
            "relationship_depth": relationship_depth,
            "limit": limit,
        }

        investigation_results: dict[str, dict[str, Any]] = {}
        for inv_type in investigation_types:
            res = self._execute_investigation(inv_type, resolved, params)
            if "error" in res:
                return format_text_response(
                    f"Failed during '{inv_type}' investigation: {res['error']}",
                    raw=True,
                )
            investigation_results[inv_type] = res

        return format_text_response(
            self._format_investigation_response(resolved, investigation_results, investigation_types, include_raw),
            raw=True,
        )
