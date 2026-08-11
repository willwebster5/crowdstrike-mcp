"""
Cloud Registration Module — multi-cloud account inventory via registration APIs.

Tools:
  cloud_list_accounts   — List registered cloud accounts (AWS, Azure)
  cloud_policy_settings — Get CSPM policy settings and compliance benchmarks
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Optional

from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

try:
    from falconpy import CSPMRegistration

    CSPM_AVAILABLE = True
except ImportError:
    CSPM_AVAILABLE = False


class CloudRegistrationModule(BaseModule):
    """Cloud account registration and CSPM policy settings."""

    def __init__(self, client):
        super().__init__(client)
        if not CSPM_AVAILABLE:
            raise ImportError("falconpy.CSPMRegistration not available. Ensure crowdstrike-falconpy >= 1.6.0 is installed.")
        self._log("Initialized")

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.cloud_list_accounts,
            name="cloud_list_accounts",
            description=("List registered cloud accounts across AWS and Azure. Shows account status, CSPM/NGSIEM enablement, and features."),
        )
        self._add_tool(
            server,
            self.cloud_policy_settings,
            name="cloud_policy_settings",
            description=("Get CSPM policy settings for a cloud platform. Shows security policies, compliance benchmarks, and remediability."),
        )

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    async def cloud_list_accounts(
        self,
        provider: Annotated[Optional[str], "Filter by cloud provider ('aws' or 'azure')"] = None,
    ) -> str:
        """List registered cloud accounts across all providers."""
        result = self._list_accounts(provider)

        if not result.get("success"):
            return format_text_response(
                f"Failed to list cloud accounts: {result.get('error')}",
                raw=True,
            )

        accounts = result["accounts"]
        lines = [
            f"Cloud Accounts ({result['total_count']} total)",
            f"Providers queried: {', '.join(result['providers_queried'])}",
            "",
        ]

        for provider_key in ("aws", "azure"):
            provider_accounts = accounts.get(provider_key, [])
            if not provider_accounts:
                error = accounts.get(f"{provider_key}_error")
                if error:
                    lines.append(f"### {provider_key.upper()}: {error.get('error', 'error')}")
                continue

            lines.append(f"### {provider_key.upper()} ({len(provider_accounts)} accounts)")
            for a in provider_accounts:
                if provider_key == "aws":
                    features = []
                    if a.get("cspm_enabled"):
                        features.append("CSPM")
                    if a.get("ngsiem_enabled"):
                        features.append("NGSIEM")
                    if a.get("vulnerability_scanning_enabled"):
                        features.append("VulnScan")
                    feat_str = f" [{', '.join(features)}]" if features else ""
                    master = " (org master)" if a.get("is_master") else ""
                    lines.append(f"- {a['account_id']} ({a['account_name']}){master}{feat_str}")
                    lines.append(f"  Status: {a['status']}")
                else:
                    lines.append(f"- Tenant: {a['tenant_id']} Sub: {a['subscription_id']}")
                    lines.append(f"  Name: {a.get('subscription_name', 'N/A')}")
                    lines.append(f"  Status: {a['status']}")
            lines.append("")

        return format_text_response(
            "\n".join(lines),
            tool_name="cloud_list_accounts",
            raw=True,
            # `accounts` is keyed by provider; flatten so each account is its own
            # record. ResponseStore.select_records would otherwise treat the whole
            # dict as a single record, making record_index/search useless.
            structured_data={
                "records": [{**a, "provider": key} for key, value in accounts.items() if isinstance(value, list) for a in value],
            },
            metadata={"provider": provider},
        )

    async def cloud_policy_settings(
        self,
        cloud_platform: Annotated[str, "Cloud platform to get policies for ('aws' or 'azure')"] = "aws",
        service: Annotated[Optional[str], "Filter by cloud service (e.g. 'EC2', 'S3', 'IAM')"] = None,
    ) -> str:
        """Get CSPM policy settings for a cloud platform."""
        result = self._get_policy_settings(cloud_platform, service)

        if not result.get("success"):
            return format_text_response(
                f"Failed to get policy settings: {result.get('error')}",
                raw=True,
            )

        lines = [
            f"CSPM Policy Settings for {result['cloud_platform'].upper()} ({result['count']} policies)",
            "",
            "### Policies by Service:",
        ]
        for svc, count in result["by_service"].items():
            lines.append(f"  {svc}: {count}")

        lines.append("")
        lines.append("### Policy Details:")
        for p in result["policies"][:30]:
            remediate = " [remediable]" if p.get("is_remediable") else ""
            lines.append(f"- [{p['default_severity']}] {p['name']}{remediate}")
            lines.append(f"  Service: {p['cloud_service']} | Type: {p['cloud_asset_type']}")
        if result["count"] > 30:
            lines.append(f"\n... and {result['count'] - 30} more policies")

        return format_text_response(
            "\n".join(lines),
            tool_name="cloud_policy_settings",
            raw=True,
            # The render caps at 30 policies; the store keeps all of them, so the
            # "... and N more" line is actually followable.
            structured_data={"records": result["policies"], "by_service": result["by_service"]},
            metadata={"cloud_platform": cloud_platform, "service": service},
        )

    # ------------------------------------------------------------------
    # Internal methods (logic from handlers/cloud_registration.py)
    # ------------------------------------------------------------------

    def _list_accounts(self, provider=None):
        try:
            cspm = self._service(CSPMRegistration)
            results = {}

            if provider in (None, "aws"):
                r = cspm.get_aws_account()
                if r["status_code"] == 200:
                    accounts = r.get("body", {}).get("resources", [])
                    results["aws"] = [
                        {
                            "account_id": a.get("account_id", ""),
                            "account_name": a.get("account_name", a.get("account_id", "")),
                            "account_type": a.get("account_type", ""),
                            "organization_id": a.get("organization_id", ""),
                            "status": self._extract_status(a.get("status", [])),
                            "cspm_enabled": a.get("cspm_enabled", False),
                            "ngsiem_enabled": a.get("ngsiem_enabled", False),
                            "behavior_assessment_enabled": a.get("behavior_assessment_enabled", False),
                            "vulnerability_scanning_enabled": a.get("vulnerability_scanning_enabled", False),
                            "iam_role_arn": a.get("iam_role_arn", ""),
                            "is_master": a.get("is_master", False),
                        }
                        for a in accounts
                    ]
                else:
                    results["aws_error"] = {"success": False, "error": format_api_error(r, "AWS accounts")}

            if provider in (None, "azure"):
                r = cspm.get_azure_account()
                if r["status_code"] == 200:
                    accounts = r.get("body", {}).get("resources", [])
                    results["azure"] = [
                        {
                            "tenant_id": a.get("tenant_id", ""),
                            "subscription_id": a.get("subscription_id", ""),
                            "subscription_name": a.get("subscription_name", ""),
                            "account_type": a.get("account_type", ""),
                            "status": a.get("status", ""),
                            "client_id": a.get("client_id", ""),
                            "iom_status": a.get("iom_status", ""),
                            "ioa_status": a.get("ioa_status", ""),
                        }
                        for a in accounts
                    ]
                else:
                    results["azure_error"] = {"success": False, "error": format_api_error(r, "Azure accounts")}

            total = sum(len(v) for k, v in results.items() if isinstance(v, list))

            return {
                "success": True,
                "accounts": results,
                "total_count": total,
                "providers_queried": [p for p in ["aws", "azure"] if provider in (None, p)],
            }
        except Exception as e:
            return {"success": False, "error": f"Error listing accounts: {e}"}

    def _get_policy_settings(self, cloud_platform="aws", service=None):
        try:
            cspm = self._service(CSPMRegistration)
            kwargs = {"cloud_platform": cloud_platform}
            if service:
                kwargs["filter"] = f"cloud_service:'{service}'"

            r = cspm.get_policy_settings(**kwargs)
            if r["status_code"] != 200:
                return {"success": False, "error": format_api_error(r, "Failed to get policy settings", operation="get_policy_settings")}

            policies = r.get("body", {}).get("resources", [])

            summaries = []
            for p in policies:
                summaries.append(
                    {
                        "policy_id": p.get("policy_id", ""),
                        "name": p.get("name", ""),
                        "cloud_provider": p.get("cloud_provider", ""),
                        "cloud_service": p.get("cloud_service_friendly", p.get("cloud_service", "")),
                        "cloud_asset_type": p.get("cloud_asset_type", ""),
                        "default_severity": p.get("default_severity", ""),
                        "policy_type": p.get("policy_type", ""),
                        "is_remediable": p.get("is_remediable", False),
                        "nist_benchmark": p.get("nist_benchmark", ""),
                        "pci_benchmark": p.get("pci_benchmark", ""),
                        "cis_benchmark": p.get("cis_benchmark", ""),
                    }
                )

            services = {}
            for p in summaries:
                svc = p["cloud_service"] or "Unknown"
                services.setdefault(svc, 0)
                services[svc] += 1

            return {
                "success": True,
                "policies": summaries,
                "count": len(summaries),
                "cloud_platform": cloud_platform,
                "by_service": dict(sorted(services.items(), key=lambda x: -x[1])),
            }
        except Exception as e:
            return {"success": False, "error": f"Error getting policy settings: {e}"}

    @staticmethod
    def _extract_status(status_list):
        if not status_list:
            return "unknown"
        if isinstance(status_list, str):
            return status_list
        parts = []
        for entry in status_list:
            if isinstance(entry, dict):
                product = entry.get("product", "?")
                features = entry.get("features", [])
                for f in features:
                    feat_name = f.get("feature", "?")
                    feat_status = f.get("status", "?").replace("Event_DiscoverAccountStatus", "")
                    parts.append(f"{product}/{feat_name}:{feat_status}")
        return ", ".join(parts) if parts else str(status_list)
