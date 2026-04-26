"""
Hosts Module — device context lookups via the Hosts API.

Tools:
  host_lookup         — Look up device details by hostname or device_id
  host_login_history  — Get recent login events for a device
  host_network_history — Get network address history for a device
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated, Optional

from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from fastmcp import FastMCP

try:
    from falconpy import Hosts

    HOSTS_AVAILABLE = True
except ImportError:
    HOSTS_AVAILABLE = False


class HostsModule(BaseModule):
    """Host/device context lookups via CrowdStrike Hosts API."""

    def __init__(self, client):
        super().__init__(client)
        if not HOSTS_AVAILABLE:
            raise ImportError("falconpy.Hosts not available. Ensure crowdstrike-falconpy >= 1.6.0 is installed.")
        self._log("Initialized")

    def register_resources(self, server: FastMCP) -> None:
        from crowdstrike_mcp.resources.fql_guides import HOST_FQL

        def _host_fql():
            return HOST_FQL

        server.resource(
            "falcon://fql/hosts",
            name="Host FQL Syntax Guide",
            description="Documentation: Host FQL filter syntax",
        )(_host_fql)
        self.resources.append("falcon://fql/hosts")

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.host_lookup,
            name="host_lookup",
            description=("Look up device details: OS, last seen, containment status, policies, agent version. Search by hostname or device_id."),
        )
        self._add_tool(
            server,
            self.host_login_history,
            name="host_login_history",
            description="Get recent login events for a device by device_id.",
        )
        self._add_tool(
            server,
            self.host_network_history,
            name="host_network_history",
            description="Get network address history for a device by device_id.",
        )

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    async def host_lookup(
        self,
        hostname: Annotated[Optional[str], "Device hostname to look up"] = None,
        device_id: Annotated[Optional[str], "Device ID to look up"] = None,
    ) -> str:
        """Look up device details by hostname or device_id."""
        result = self._lookup(hostname=hostname, device_id=device_id)

        if not result.get("success"):
            return format_text_response(
                f"Failed to look up host: {result.get('error')}",
                raw=True,
            )

        devices = result.get("devices", [])
        lines = [f"Host Lookup Results ({result['count']} devices)", ""]

        for device in devices:
            lines.append(f"### {device.get('hostname', 'Unknown')}")
            lines.append(f"- Device ID: {device.get('device_id', 'N/A')}")
            lines.append(f"- Platform: {device.get('platform_name', 'N/A')}")
            lines.append(f"- OS: {device.get('os_version', 'N/A')}")
            lines.append(f"- Agent Version: {device.get('agent_version', 'N/A')}")
            lines.append(f"- Status: {device.get('status', 'N/A')}")
            lines.append(f"- Containment: {device.get('containment_status', 'N/A')}")
            lines.append(f"- Last Seen: {device.get('last_seen', 'N/A')}")
            lines.append(f"- First Seen: {device.get('first_seen', 'N/A')}")
            lines.append(f"- Local IP: {device.get('local_ip', 'N/A')}")
            lines.append(f"- External IP: {device.get('external_ip', 'N/A')}")
            if device.get("machine_domain"):
                lines.append(f"- Domain: {device['machine_domain']}")
            if device.get("tags"):
                lines.append(f"- Tags: {', '.join(device['tags'])}")
            policies = device.get("device_policies", {})
            if policies:
                lines.append("- Policies:")
                for ptype, pdata in policies.items():
                    if isinstance(pdata, dict):
                        lines.append(f"  - {ptype}: applied={pdata.get('applied', 'N/A')}")
            lines.append("")

        return format_text_response("\n".join(lines), raw=True)

    async def host_login_history(
        self,
        device_id: Annotated[str, "Device ID to query login history for"],
    ) -> str:
        """Get recent login events for a device."""
        result = self._get_login_history(device_id)

        if not result.get("success"):
            return format_text_response(
                f"Failed to get login history: {result.get('error')}",
                raw=True,
            )

        lines = [
            f"Login History for {result['device_id']} ({result['count']} entries)",
            "",
        ]
        for entry in result.get("login_history", []):
            lines.append("```json")
            lines.append(json.dumps(entry, indent=2, default=str))
            lines.append("```")
            lines.append("")

        if not result.get("login_history"):
            lines.append("No login history found.")

        return format_text_response("\n".join(lines), raw=True)

    async def host_network_history(
        self,
        device_id: Annotated[str, "Device ID to query network history for"],
    ) -> str:
        """Get network address history for a device."""
        result = self._get_network_history(device_id)

        if not result.get("success"):
            return format_text_response(
                f"Failed to get network history: {result.get('error')}",
                raw=True,
            )

        lines = [
            f"Network History for {result['device_id']} ({result['count']} entries)",
            "",
        ]
        for entry in result.get("network_history", []):
            lines.append("```json")
            lines.append(json.dumps(entry, indent=2, default=str))
            lines.append("```")
            lines.append("")

        if not result.get("network_history"):
            lines.append("No network history found.")

        return format_text_response("\n".join(lines), raw=True)

    # ------------------------------------------------------------------
    # Internal methods (logic from handlers/hosts.py)
    # ------------------------------------------------------------------

    def _lookup(self, hostname=None, device_id=None):
        try:
            if not hostname and not device_id:
                return {"success": False, "error": "At least one of hostname or device_id must be provided"}

            hosts = self._service(Hosts)
            device_ids = []
            if device_id:
                device_ids = [device_id]
            elif hostname:
                filter_query = f"hostname:'{hostname}'"
                response = hosts.query_devices_by_filter(filter=filter_query, limit=10)
                if response["status_code"] != 200:
                    return {"success": False, "error": format_api_error(response, "Failed to query devices", operation="query_devices_by_filter")}
                device_ids = response.get("body", {}).get("resources", [])
                if not device_ids:
                    return {"success": False, "error": f"No devices found with hostname: {hostname}"}

            details_response = hosts.get_device_details(ids=device_ids)
            if details_response["status_code"] != 200:
                return {"success": False, "error": format_api_error(details_response, "Failed to get device details", operation="get_device_details")}

            resources = details_response.get("body", {}).get("resources", [])
            if not resources:
                return {"success": False, "error": "No device details returned"}

            devices = []
            for device in resources:
                devices.append(
                    {
                        "device_id": device.get("device_id", ""),
                        "hostname": device.get("hostname", ""),
                        "platform_name": device.get("platform_name", ""),
                        "os_version": device.get("os_version", ""),
                        "os_build": device.get("os_build", ""),
                        "agent_version": device.get("agent_version", ""),
                        "last_seen": device.get("last_seen", ""),
                        "first_seen": device.get("first_seen", ""),
                        "status": device.get("status", ""),
                        "containment_status": device.get("containment_status", "normal"),
                        "local_ip": device.get("local_ip", ""),
                        "external_ip": device.get("external_ip", ""),
                        "mac_address": device.get("mac_address", ""),
                        "machine_domain": device.get("machine_domain", ""),
                        "ou": device.get("ou", []),
                        "site_name": device.get("site_name", ""),
                        "system_manufacturer": device.get("system_manufacturer", ""),
                        "system_product_name": device.get("system_product_name", ""),
                        "tags": device.get("tags", []),
                        "groups": device.get("groups", []),
                        "device_policies": self._extract_policies(device.get("device_policies", {})),
                        "meta": {"version": device.get("meta", {}).get("version", "")},
                    }
                )

            return {"success": True, "devices": devices, "count": len(devices)}
        except Exception as e:
            return {"success": False, "error": f"Error looking up host: {str(e)}"}

    def _get_login_history(self, device_id):
        try:
            hosts = self._service(Hosts)
            response = hosts.query_device_login_history(ids=[device_id])
            if response["status_code"] != 200:
                return {"success": False, "error": format_api_error(response, "Failed to get login history", operation="query_device_login_history")}
            resources = response.get("body", {}).get("resources", [])
            return {"success": True, "device_id": device_id, "login_history": resources, "count": len(resources)}
        except Exception as e:
            return {"success": False, "error": f"Error getting login history: {str(e)}"}

    def _get_network_history(self, device_id):
        try:
            hosts = self._service(Hosts)
            response = hosts.query_network_address_history(ids=[device_id])
            if response["status_code"] != 200:
                return {"success": False, "error": format_api_error(response, "Failed to get network history", operation="query_network_address_history")}
            resources = response.get("body", {}).get("resources", [])
            return {"success": True, "device_id": device_id, "network_history": resources, "count": len(resources)}
        except Exception as e:
            return {"success": False, "error": f"Error getting network history: {str(e)}"}

    @staticmethod
    def _extract_policies(policies):
        result = {}
        for policy_type, policy_data in policies.items():
            if isinstance(policy_data, dict):
                result[policy_type] = {
                    "policy_id": policy_data.get("policy_id", ""),
                    "policy_type": policy_data.get("policy_type", ""),
                    "applied": policy_data.get("applied", False),
                }
        return result
