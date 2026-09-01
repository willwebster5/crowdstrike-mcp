"""
Correlation Module — detection engineering via the CorrelationRules API.

Tools:
  correlation_list_rules   — List detection/correlation rules
  correlation_get_rule     — Get full rule details
  correlation_update_rule  — Enable/disable rules with audit comment
  correlation_export_rule  — Export rule in structured format
  correlation_list_templates — List available rule templates
  correlation_get_template   — Get full template details
"""

from __future__ import annotations

import json
import os
import re
from typing import TYPE_CHECKING, Annotated, Optional

import yaml

from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

try:
    from falconpy import CorrelationRules

    CORRELATION_AVAILABLE = True
except ImportError:
    CORRELATION_AVAILABLE = False

try:
    from falconpy import APIHarnessV2

    HARNESS_AVAILABLE = True
except ImportError:
    HARNESS_AVAILABLE = False

VALID_VENDORS = {"aws", "microsoft", "crowdstrike", "google", "github", "cato", "generic", "knowbe4"}


class CorrelationModule(BaseModule):
    """Correlation rule management for detection engineering."""

    def __init__(self, client):
        super().__init__(client)
        self._use_harness = not CORRELATION_AVAILABLE

        if not CORRELATION_AVAILABLE and not HARNESS_AVAILABLE:
            raise ImportError("Neither falconpy.CorrelationRules nor falconpy.APIHarnessV2 available. Ensure crowdstrike-falconpy >= 1.6.0 is installed.")

        # Path to crowdstrike-detections repo for IaC file writes
        self._detections_repo_path = os.environ.get(
            "DETECTIONS_REPO_PATH",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "crowdstrike-detections"),
        )
        if not os.path.isdir(self._detections_repo_path):
            self._detections_repo_path = None
            self._log("DETECTIONS_REPO_PATH not found — correlation_import_to_iac will use dry-run mode")

    def _get_correlation_service(self):
        cls = CorrelationRules if CORRELATION_AVAILABLE else APIHarnessV2
        return self._service(cls)

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.correlation_list_rules,
            name="correlation_list_rules",
            description=("List NGSIEM correlation/detection rules with optional filtering by enabled status and name search."),
        )
        self._add_tool(
            server,
            self.correlation_get_rule,
            name="correlation_get_rule",
            description=("Get full details for correlation rules: CQL filter, severity, MITRE mapping, notification settings."),
        )
        self._add_tool(
            server,
            self.correlation_update_rule,
            name="correlation_update_rule",
            description="Enable or disable a correlation rule with an audit comment.",
            tier="write",
        )
        self._add_tool(
            server,
            self.correlation_export_rule,
            name="correlation_export_rule",
            description="Export a correlation rule in structured format for review.",
        )
        self._add_tool(
            server,
            self.correlation_import_to_iac,
            name="correlation_import_to_iac",
            description=(
                "Export a console-created correlation rule to an IaC YAML template in the detections repo. Use dry_run=True to preview without writing."
            ),
            tier="write",
        )
        self._add_tool(
            server,
            self.correlation_list_templates,
            name="correlation_list_templates",
            description="List available CrowdStrike correlation rule templates with optional filtering. Templates are pre-built detection patterns.",
        )
        self._add_tool(
            server,
            self.correlation_get_template,
            name="correlation_get_template",
            description="Get full template details by ID, including CQL logic and configuration.",
        )

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    async def correlation_list_rules(
        self,
        enabled: Annotated[Optional[bool], "Filter by enabled status (omit for all rules)"] = None,
        search: Annotated[Optional[str], "Wildcard search on rule name/description"] = None,
        max_results: Annotated[int, "Maximum rules to return (default: 100)"] = 100,
    ) -> str:
        """List correlation/detection rules with optional filtering."""
        result = self._list_rules(enabled=enabled, search=search, max_results=max_results)

        if not result.get("success"):
            return format_text_response(f"Failed to list rules: {result.get('error')}", raw=True)

        rules = result.get("rules", [])
        lines = [
            f"Correlation Rules: {result['count']} returned (of {result['total']} total)",
            "",
        ]

        for i, rule in enumerate(rules, 1):
            status_str = (rule.get("status") or "unknown").upper()
            lines.append(f"{i}. [{status_str}] {rule['name']}")
            lines.append(f"   Rule ID: {rule['rule_id']}")
            if rule.get("severity"):
                lines.append(f"   Severity: {rule['severity']}")
            if rule.get("description"):
                lines.append(f"   Description: {rule['description']}")
            lines.append(f"   Updated: {rule.get('updated_on', 'N/A')}")
            lines.append("")

        if not rules:
            lines.append("No rules found matching the filters.")

        return format_text_response(
            "\n".join(lines),
            tool_name="correlation_list_rules",
            raw=True,
            structured_data={"records": rules},
            metadata={"enabled": enabled, "search": search, "max_results": max_results},
        )

    async def correlation_get_rule(
        self,
        rule_ids: Annotated[list[str], "Rule IDs to retrieve — the `rule_id` values from correlation_list_rules output"],
    ) -> str:
        """Get full details for specific correlation rules."""
        result = self._get_rules(rule_ids)

        if not result.get("success"):
            return format_text_response(f"Failed to get rules: {result.get('error')}", raw=True)

        lines = [f"Correlation Rule Details ({result['count']} rules)", ""]

        for rule in result.get("rules", []):
            lines.append(f"### {rule.get('name', 'Unknown')}")
            lines.append(f"- Rule ID: {rule.get('rule_id', 'N/A')}")
            lines.append(f"- Status: {rule.get('status', 'N/A')}")
            lines.append(f"- Severity: {rule.get('severity', 'N/A')}")
            lines.append(f"- Created: {rule.get('created_on', 'N/A')}")
            lines.append(f"- Updated: {rule.get('updated_on', 'N/A')}")
            if rule.get("description"):
                lines.append(f"- Description: {rule['description']}")

            search = rule.get("search", {})
            if search and search.get("filter"):
                lines.append("\n**CQL Filter:**")
                lines.append("```")
                lines.append(search["filter"])
                lines.append("```")

            lines.append("")
            lines.append("**Full Rule JSON:**")
            lines.append("```json")
            lines.append(json.dumps(rule, indent=2, default=str))
            lines.append("```")
            lines.append("")

        return format_text_response(
            "\n".join(lines),
            tool_name="correlation_get_rule",
            raw=True,
            structured_data={"records": result.get("rules", [])},
            metadata={"rule_ids": rule_ids},
        )

    async def correlation_update_rule(
        self,
        rule_id: Annotated[str, "Rule ID to update — the `rule_id` value from correlation_list_rules output"],
        enabled: Annotated[bool, "True to enable, False to disable"],
        comment: Annotated[Optional[str], "Audit comment explaining the change"] = None,
    ) -> str:
        """Enable or disable a correlation rule with an audit comment."""
        result = self._update_rule(rule_id, enabled, comment)

        if not result.get("success"):
            return format_text_response(f"Failed to update rule: {result.get('error')}", raw=True)

        action = "enabled" if result["enabled"] else "disabled"
        lines = [f"Successfully {action} rule: {result['rule_id']}"]
        if result.get("comment"):
            lines.append(f"Comment: {result['comment']}")

        return format_text_response("\n".join(lines), tool_name="correlation_update_rule", raw=True)

    async def correlation_export_rule(
        self,
        rule_id: Annotated[str, "Rule ID to export — the `rule_id` value from correlation_list_rules output"],
    ) -> str:
        """Export a correlation rule in structured format for review."""
        result = self._export_rule(rule_id)

        if not result.get("success"):
            return format_text_response(f"Failed to export rule: {result.get('error')}", raw=True)

        export = result["export"]
        lines = [
            f"## Correlation Rule Export: {export['metadata']['name']}",
            "",
            "### Metadata",
        ]
        for k, v in export["metadata"].items():
            lines.append(f"- **{k}**: {v}")
        lines.append("")

        if export.get("search", {}).get("filter"):
            lines.append("### CQL Filter")
            lines.append("```")
            lines.append(export["search"]["filter"])
            lines.append("```")
            lines.append("")

        lines.append("### Full Export")
        lines.append("```json")
        lines.append(json.dumps(export, indent=2, default=str))
        lines.append("```")

        # The full export is rendered inline; a rule with a long CQL body clears
        # the 20k threshold, and without structured_data the tail is dropped with
        # no way to recover it.
        return format_text_response(
            "\n".join(lines),
            tool_name="correlation_export_rule",
            raw=True,
            structured_data=result,
            metadata={"rule_id": rule_id},
        )

    # ------------------------------------------------------------------
    # Internal methods (logic from handlers/correlation_rules.py)
    # ------------------------------------------------------------------

    def _list_rules(self, enabled=None, search=None, max_results=100):
        try:
            falcon = self._get_correlation_service()
            all_rule_ids = []
            offset = 0
            batch_limit = 500
            while True:
                if self._use_harness:
                    response = falcon.command("queries_rules_get_v1", limit=batch_limit, offset=offset)
                else:
                    response = falcon.query_rules(limit=batch_limit, offset=offset)

                if response["status_code"] != 200:
                    return {"success": False, "error": format_api_error(response, "Failed to query rules", operation="query_rules")}

                batch_ids = response.get("body", {}).get("resources", [])
                all_rule_ids.extend(batch_ids)

                total_api = response.get("body", {}).get("meta", {}).get("pagination", {}).get("total", 0)
                if len(all_rule_ids) >= total_api or not batch_ids:
                    break
                offset += batch_limit

            if not all_rule_ids:
                return {"success": True, "rules": [], "count": 0, "total": 0}

            all_rules = []
            batch_size = 100
            for i in range(0, len(all_rule_ids), batch_size):
                batch = all_rule_ids[i : i + batch_size]
                if self._use_harness:
                    details = falcon.command("entities_rules_get_v1", ids=batch)
                else:
                    details = falcon.get_rules(ids=batch)

                if details["status_code"] != 200:
                    self._log(f"Failed to get details for batch {i // batch_size + 1}")
                    continue
                all_rules.extend(details.get("body", {}).get("resources", []))

            filtered = all_rules
            if enabled is not None:
                # The API's `enabled` field is always false regardless of a rule's
                # real state — `status` ("active"/"inactive") carries the real
                # signal, so the enabled filter is implemented against it.
                wanted_status = "active" if enabled else "inactive"
                filtered = [r for r in filtered if r.get("status") == wanted_status]
            if search:
                search_lower = search.lower()
                filtered = [r for r in filtered if search_lower in r.get("name", "").lower() or search_lower in r.get("description", "").lower()]

            total_matched = len(filtered)
            filtered = filtered[:max_results]

            summaries = []
            for rule in filtered:
                summaries.append(
                    {
                        "rule_id": rule.get("rule_id", ""),
                        "name": rule.get("name", ""),
                        "description": rule.get("description", "")[:200],
                        "status": rule.get("status", ""),
                        "severity": rule.get("severity", ""),
                        "created_on": rule.get("created_on", ""),
                        "updated_on": rule.get("updated_on", ""),
                        "created_by": rule.get("created_by", ""),
                    }
                )

            return {"success": True, "rules": summaries, "count": len(summaries), "total": total_matched}
        except Exception as e:
            return {"success": False, "error": f"Error listing rules: {str(e)}"}

    def _get_rules(self, rule_ids):
        try:
            falcon = self._get_correlation_service()
            if self._use_harness:
                response = falcon.command("entities_rules_get_v1", ids=rule_ids)
            else:
                response = falcon.get_rules(ids=rule_ids)

            if response["status_code"] != 200:
                return {"success": False, "error": format_api_error(response, "Failed to get rule details", operation="get_rules")}

            resources = response.get("body", {}).get("resources", [])
            if not resources:
                return {
                    "success": False,
                    "error": (
                        f"No rules found for IDs: {rule_ids}. This tool expects the `rule_id` value "
                        "from correlation_list_rules output, not the internal `id` field."
                    ),
                }

            return {"success": True, "rules": resources, "count": len(resources)}
        except Exception as e:
            return {"success": False, "error": f"Error getting rules: {str(e)}"}

    def _update_rule(self, rule_id, enabled, comment=None):
        try:
            falcon = self._get_correlation_service()
            update_payload = [{"id": rule_id, "enabled": enabled}]
            if comment:
                update_payload[0]["comment"] = comment

            if self._use_harness:
                response = falcon.command("entities_rules_patch_v1", body=update_payload)
            else:
                response = falcon.update_rule(body=update_payload)

            if response["status_code"] != 200:
                return {"success": False, "error": format_api_error(response, "Failed to update rule", operation="update_rules")}

            return {"success": True, "rule_id": rule_id, "enabled": enabled, "comment": comment}
        except Exception as e:
            return {"success": False, "error": f"Error updating rule: {str(e)}"}

    def _export_rule(self, rule_id):
        result = self._get_rules([rule_id])
        if not result.get("success"):
            return result

        rules = result.get("rules", [])
        if not rules:
            return {"success": False, "error": f"Rule not found: {rule_id}"}

        rule = rules[0]
        export = {
            "metadata": {
                "rule_id": rule.get("rule_id", ""),
                "name": rule.get("name", ""),
                "description": rule.get("description", ""),
                "status": rule.get("status", ""),
                "severity": rule.get("severity", ""),
                "created_on": rule.get("created_on", ""),
                "updated_on": rule.get("updated_on", ""),
                "created_by": rule.get("created_by", ""),
                "updated_by": rule.get("updated_by", ""),
            },
            "search": rule.get("search", {}),
            "notification": rule.get("notification", {}),
            "trigger": rule.get("trigger", {}),
            "full_rule": rule,
        }

        return {"success": True, "export": export}

    # ------------------------------------------------------------------
    # IaC import tool
    # ------------------------------------------------------------------

    async def correlation_import_to_iac(
        self,
        rule_id: Annotated[str, "Correlation rule ID to import — the `rule_id` value from correlation_list_rules output"],
        vendor: Annotated[str, "Vendor directory (aws, microsoft, crowdstrike, google, github, cato, generic, knowbe4)"],
        resource_id_override: Annotated[Optional[str], "Override the auto-generated resource_id"] = None,
        dry_run: Annotated[bool, "If True, return YAML without writing to disk"] = False,
    ) -> str:
        """Export a correlation rule to an IaC YAML template."""
        # Validate vendor
        if vendor.lower() not in VALID_VENDORS:
            return format_text_response(
                f"Invalid vendor '{vendor}'. Must be one of: {', '.join(sorted(VALID_VENDORS))}",
                raw=True,
            )
        vendor = vendor.lower()

        # Fetch rule
        result = self._get_rules([rule_id])
        if not result.get("success"):
            return format_text_response(f"Failed to fetch rule: {result.get('error')}", raw=True)

        rules = result.get("rules", [])
        if not rules:
            return format_text_response(f"Rule not found: {rule_id}", raw=True)

        rule = rules[0]

        # Convert to template
        template = self._rule_to_template(rule, vendor, resource_id_override)
        yaml_str = self._template_to_yaml(template)

        # Dry-run or path not available: return YAML as text
        if dry_run or not self._detections_repo_path:
            lines = []
            if not dry_run and not self._detections_repo_path:
                lines.append("NOTE: Detections repo path not configured — falling back to dry-run mode.")
                lines.append("Set DETECTIONS_REPO_PATH env var or place the repo at the expected location.")
                lines.append("")
            lines.append(f"## IaC Template for: {rule.get('name', 'Unknown')}")
            lines.append(f"Resource ID: `{template['resource_id']}`")
            lines.append(f"Target path: `resources/detections/{vendor}/{template['resource_id']}.yaml`")
            lines.append("")
            lines.append("```yaml")
            lines.append(yaml_str)
            lines.append("```")
            return format_text_response(
                "\n".join(lines),
                tool_name="correlation_import_to_iac",
                raw=True,
                structured_data={"records": [template]},
                metadata={"rule_id": rule_id, "vendor": vendor, "dry_run": dry_run},
            )

        # Write to file
        resource_id = template["resource_id"]
        target_dir = os.path.join(self._detections_repo_path, "resources", "detections", vendor)
        target_path = os.path.join(target_dir, f"{resource_id}.yaml")

        if os.path.exists(target_path):
            return format_text_response(
                f"File already exists: `{target_path}`\n\n"
                f"This rule may already be under IaC management. "
                f"Use a different resource_id_override or check the existing template.",
                raw=True,
            )

        if not os.path.isdir(target_dir):
            return format_text_response(
                f"Vendor directory does not exist: `{target_dir}`\nCreate it first or use a valid vendor.",
                raw=True,
            )

        with open(target_path, "w") as f:
            f.write(yaml_str)

        lines = [
            f"Template written to: `{target_path}`",
            "",
            f"Resource ID: `{resource_id}`",
            f"Name: {template['name']}",
            f"Severity: {template['severity']}",
            f"Status: {template['status']}",
            "",
            "Next steps:",
            f"1. Review and tune the CQL in `{target_path}`",
            "2. `python scripts/resource_deploy.py validate-query --template " + target_path + "`",
            "3. `python scripts/resource_deploy.py plan`",
            "4. `python scripts/resource_deploy.py apply`",
        ]
        return format_text_response("\n".join(lines), tool_name="correlation_import_to_iac", raw=True)

    async def correlation_list_templates(
        self,
        filter: Annotated[Optional[str], "FQL filter expression for templates"] = None,
        limit: Annotated[int, "Maximum templates to return (default: 100)"] = 100,
        offset: Annotated[int, "Pagination offset (default: 0)"] = 0,
    ) -> str:
        """List available correlation rule templates."""
        try:
            falcon = self._get_correlation_service()
            kwargs = {"limit": min(limit, 500), "offset": offset}
            if filter:
                kwargs["filter"] = filter

            if self._use_harness:
                response = falcon.command("queries_templates_get_v1Mixin0", **kwargs)
            else:
                response = falcon.query_templates(**kwargs)

            if response["status_code"] != 200:
                return format_text_response(
                    f"Failed to list templates: {format_api_error(response, 'Failed to query templates', operation='queries_templates_get_v1Mixin0')}",
                    raw=True,
                )

            template_ids = response.get("body", {}).get("resources", [])
            total = response.get("body", {}).get("meta", {}).get("pagination", {}).get("total", len(template_ids))

            lines = [f"Correlation Rule Templates: {len(template_ids)} returned (of {total} total)", ""]

            if not template_ids:
                lines.append("No templates found.")
            else:
                for i, tid in enumerate(template_ids, 1):
                    lines.append(f"{i}. {tid}")

            return format_text_response(
                "\n".join(lines),
                tool_name="correlation_list_templates",
                raw=True,
                structured_data={"records": template_ids},
                metadata={"filter": filter, "limit": limit, "offset": offset},
            )
        except Exception as e:
            return format_text_response(f"Failed to list templates: {e}", raw=True)

    async def correlation_get_template(
        self,
        template_ids: Annotated[list[str], "List of template IDs to retrieve"],
    ) -> str:
        """Get full details for correlation rule templates."""
        try:
            falcon = self._get_correlation_service()
            if self._use_harness:
                response = falcon.command("entities_templates_get_v1Mixin0", ids=template_ids)
            else:
                response = falcon.get_templates(ids=template_ids)

            if response["status_code"] != 200:
                err = format_api_error(response, "Failed to get template details", operation="entities_templates_get_v1Mixin0")
                return format_text_response(f"Failed to get templates: {err}", raw=True)

            resources = response.get("body", {}).get("resources", [])

            if not resources:
                return format_text_response(
                    f"No templates found for IDs: {template_ids}",
                    raw=True,
                )

            lines = [f"Correlation Rule Template Details ({len(resources)} templates)", ""]

            for template in resources:
                lines.append(f"### {template.get('name', 'Unknown')}")
                lines.append(f"- ID: {template.get('id', 'N/A')}")
                lines.append(f"- Severity: {template.get('severity', 'N/A')}")
                if template.get("description"):
                    lines.append(f"- Description: {template['description']}")
                lines.append(f"- Created: {template.get('created_on', 'N/A')}")
                lines.append(f"- Updated: {template.get('updated_on', 'N/A')}")

                search = template.get("search", {})
                if search and search.get("filter"):
                    lines.append("\n**CQL Filter:**")
                    lines.append("```")
                    lines.append(search["filter"])
                    lines.append("```")

                lines.append("")
                lines.append("**Full Template JSON:**")
                lines.append("```json")
                lines.append(json.dumps(template, indent=2, default=str))
                lines.append("```")
                lines.append("")

            return format_text_response(
                "\n".join(lines),
                tool_name="correlation_get_template",
                raw=True,
                structured_data={"records": resources},
                metadata={"template_ids": template_ids},
            )
        except Exception as e:
            return format_text_response(f"Failed to get templates: {e}", raw=True)

    # ------------------------------------------------------------------
    # IaC template conversion helpers
    # ------------------------------------------------------------------

    def _rule_to_template(self, rule: dict, vendor: str, resource_id_override: str = None) -> dict:
        """Convert a CrowdStrike API rule to IaC YAML template dict."""
        resource_id = self._generate_resource_id(rule.get("name", ""), vendor, resource_id_override)

        search = rule.get("search", {})
        trigger = rule.get("trigger", {})
        operation = rule.get("operation", {})

        # Map lookback from search.lookback_window or search.start
        lookback = search.get("lookback_window") or search.get("start") or "1h0m"

        # Map trigger mode / outcome
        trigger_mode = trigger.get("trigger_mode") or "summary"
        outcome = trigger.get("outcome") or "detection"

        template = {
            "resource_id": resource_id,
            "name": rule.get("name", ""),
            "description": rule.get("description", ""),
            "severity": rule.get("severity", 50),
            # `enabled` is always false on the Falcon API's rule objects regardless
            # of real state; `status` ("active"/"inactive") is the field that
            # reflects whether the rule is actually running.
            "status": "active" if rule.get("status") == "active" else "disabled",
            "search": {
                "filter": search.get("filter", ""),
                "lookback": lookback,
                "trigger_mode": trigger_mode,
                "outcome": outcome,
                "use_ingest_time": True,
            },
            "operation": {
                "schedule": {
                    "definition": operation.get("schedule", {}).get("definition", "@every 1h0m"),
                },
            },
        }

        mitre = rule.get("mitre_attack_ids", [])
        if mitre:
            template["mitre_attack"] = mitre

        return template

    @staticmethod
    def _generate_resource_id(name: str, vendor: str, override: str = None) -> str:
        """Generate a stable resource_id from a rule name.

        Convention: vendor_-_source_-_sanitized_name (matching existing templates).
        """
        if override:
            return override

        # Lowercase, remove special characters except underscores, hyphens, spaces
        sanitized = name.lower()
        sanitized = re.sub(r"[^a-z0-9\s_-]", "", sanitized)
        # Replace spaces with underscores (preserving hyphens as-is)
        sanitized = re.sub(r"\s+", "_", sanitized)
        # Collapse multiple underscores
        sanitized = re.sub(r"_+", "_", sanitized)
        sanitized = sanitized.strip("_")

        # The convention uses " - " in names which becomes "_-_" in resource_id
        # e.g. "AWS - CloudTrail - Suspicious IAM Activity" -> "aws_-_cloudtrail_-_suspicious_iam_activity"
        return sanitized

    @staticmethod
    def _template_to_yaml(template: dict) -> str:
        """Serialize a template dict to YAML string matching the project's style."""

        # Use block style for multi-line strings (filter)
        class BlockDumper(yaml.SafeDumper):
            pass

        def str_representer(dumper, data):
            if "\n" in data:
                return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
            return dumper.represent_scalar("tag:yaml.org,2002:str", data)

        BlockDumper.add_representer(str, str_representer)

        return yaml.dump(
            template,
            Dumper=BlockDumper,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )
