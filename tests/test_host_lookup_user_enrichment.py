"""Tests for host_lookup recent-user enrichment (issue #44).

host_lookup now folds recent login users into its output so a single call
answers "what is this host?" and "who has been on it?". Users come from the
existing device-login-history endpoint, deduped so repeated system accounts
don't crowd out real users.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from crowdstrike_mcp.response_store import ResponseStore


@pytest.fixture
def hosts_module(mock_client):
    with patch("crowdstrike_mcp.modules.hosts.Hosts"):
        from crowdstrike_mcp.modules.hosts import HostsModule

        return HostsModule(mock_client)


def _module():
    with patch("crowdstrike_mcp.modules.hosts.Hosts"):
        from crowdstrike_mcp.modules.hosts import HostsModule

        return HostsModule(MagicMock())


class TestExtractRecentUsers:
    def test_wrapped_recent_logins_shape(self):
        from crowdstrike_mcp.modules.hosts import HostsModule

        resources = [
            {
                "device_id": "d",
                "recent_logins": [
                    {"user_name": "DOMAIN\\alice", "login_time": "2026-07-20T14:03:00Z"},
                    {"user_name": "DOMAIN\\bob", "login_time": "2026-07-20T09:00:00Z"},
                    {"user_name": "DOMAIN\\alice", "login_time": "2026-07-19T09:00:00Z"},
                ],
            }
        ]
        users = HostsModule._extract_recent_users(resources)
        assert [u["user_name"] for u in users] == ["DOMAIN\\alice", "DOMAIN\\bob"]
        assert users[0]["login_time"] == "2026-07-20T14:03:00Z"

    def test_flat_login_record_shape(self):
        from crowdstrike_mcp.modules.hosts import HostsModule

        resources = [
            {"user_name": "alice", "login_time": "t2"},
            {"user_name": "alice", "login_time": "t1"},
            {"user_name": "bob", "login_time": "t0"},
        ]
        users = HostsModule._extract_recent_users(resources)
        assert [u["user_name"] for u in users] == ["alice", "bob"]

    def test_case_insensitive_dedup_collapses_system_account(self):
        from crowdstrike_mcp.modules.hosts import HostsModule

        resources = [
            {
                "recent_logins": [
                    {"user_name": "NT AUTHORITY\\SYSTEM", "login_time": "t3"},
                    {"user_name": "nt authority\\system", "login_time": "t2"},
                    {"user_name": "DOMAIN\\alice", "login_time": "t1"},
                ]
            }
        ]
        users = HostsModule._extract_recent_users(resources)
        assert [u["user_name"] for u in users] == ["NT AUTHORITY\\SYSTEM", "DOMAIN\\alice"]

    def test_caps_at_three_unique_users(self):
        from crowdstrike_mcp.modules.hosts import HostsModule

        resources = [{"recent_logins": [{"user_name": f"user{i}"} for i in range(6)]}]
        users = HostsModule._extract_recent_users(resources)
        assert len(users) == 3
        assert [u["user_name"] for u in users] == ["user0", "user1", "user2"]

    def test_empty_and_none_return_empty_list(self):
        from crowdstrike_mcp.modules.hosts import HostsModule

        assert HostsModule._extract_recent_users([]) == []
        assert HostsModule._extract_recent_users(None) == []


class TestHostLookupRendersUsers:
    def _device(self):
        return {
            "device_id": "dev-1",
            "hostname": "WIN-1",
            "platform_name": "Windows",
            "os_version": "11",
            "containment_status": "normal",
        }

    def test_lookup_shows_most_recent_and_recent_users(self):
        module = _module()
        module._lookup = lambda hostname=None, device_id=None: {"success": True, "devices": [self._device()], "count": 1}
        module._get_login_history = lambda device_id: {
            "success": True,
            "device_id": device_id,
            "count": 1,
            "login_history": [
                {
                    "recent_logins": [
                        {"user_name": "DOMAIN\\alice", "login_time": "2026-07-20T14:03:00Z"},
                        {"user_name": "DOMAIN\\bob", "login_time": "2026-07-20T09:00:00Z"},
                    ]
                }
            ],
        }
        out = asyncio.run(module.host_lookup(hostname="WIN-1"))
        assert "Most Recent User" in out
        assert "DOMAIN\\alice" in out
        assert "2026-07-20T14:03:00Z" in out
        assert "Recent Users" in out
        assert "DOMAIN\\bob" in out

    def test_lookup_degrades_gracefully_when_history_fails(self):
        module = _module()
        module._lookup = lambda hostname=None, device_id=None: {"success": True, "devices": [self._device()], "count": 1}
        module._get_login_history = lambda device_id: {"success": False, "error": "boom"}
        out = asyncio.run(module.host_lookup(hostname="WIN-1"))
        # core lookup still succeeds and renders device fields
        assert "WIN-1" in out
        assert "Device ID: dev-1" in out
        assert "(none available)" in out

    def test_lookup_degrades_gracefully_when_history_empty(self):
        module = _module()
        module._lookup = lambda hostname=None, device_id=None: {"success": True, "devices": [self._device()], "count": 1}
        module._get_login_history = lambda device_id: {"success": True, "device_id": device_id, "count": 0, "login_history": []}
        out = asyncio.run(module.host_lookup(hostname="WIN-1"))
        assert "WIN-1" in out
        assert "(none available)" in out


class TestHostLookupRetrievable:
    def test_large_lookup_populates_response_store(self):
        module = _module()
        many = [
            {
                "device_id": f"dev-{i}",
                "hostname": f"WIN-{i}",
                "platform_name": "Windows",
                "os_version": "11",
                "containment_status": "normal",
                "os_build": "x" * 500,  # bulk so the structured payload exceeds the store threshold
            }
            for i in range(60)
        ]
        module._lookup = lambda hostname=None, device_id=None: {"success": True, "devices": many, "count": len(many)}
        module._get_login_history = lambda device_id: {
            "success": True,
            "device_id": device_id,
            "count": 1,
            "login_history": [{"recent_logins": [{"user_name": "u", "login_time": "t", "notes": "x" * 500}]}],
        }
        asyncio.run(module.host_lookup(hostname="WIN-*"))
        assert ResponseStore.list_refs()  # structured_data was wired and stored
