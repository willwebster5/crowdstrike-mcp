"""Tests for surfacing the triggering indicator on IOC/network-match alerts (#41).

For `ind:`-prefixed IOC/threat-intel match alerts (e.g.
CloudDetect-BlacklistedIPAddressHighUI), the process-behavior enrichment yields
only generic ProcessRollup2 events. The actual triggering indicator (a
blacklisted IP, matched domain, or IOC) lives in the alert record itself, which
the formatter previously dropped. These tests pin the extraction + rendering.
"""

from crowdstrike_mcp.modules.alerts import AlertsModule


class TestExtractAlertIndicators:
    def test_known_ioc_fields_surfaced(self):
        alert = {
            "composite_id": "cid:ind:x:1-2-3",
            "ioc_type": "domain",
            "ioc_value": "evil.example.com",
            "ioc_source": "Threat Intel",
        }
        ind = AlertsModule._extract_alert_indicators(alert)
        assert ind["ioc_type"] == "domain"
        assert ind["ioc_value"] == "evil.example.com"
        assert ind["ioc_source"] == "Threat Intel"

    def test_public_ip_in_arbitrary_field_surfaced(self):
        alert = {"composite_id": "cid:ind:x:1-2-3", "remote_address": "185.220.101.45"}
        ind = AlertsModule._extract_alert_indicators(alert)
        # keyed by its source field, value present
        assert any("185.220.101.45" in str(v) for v in ind.values())

    def test_private_ip_not_surfaced(self):
        alert = {"composite_id": "cid:ind:x:1-2-3", "local_ip": "10.1.2.3"}
        ind = AlertsModule._extract_alert_indicators(alert)
        assert not any("10.1.2.3" in str(v) for v in ind.values())

    def test_agent_id_hash_not_mistaken_for_indicator(self):
        alert = {
            "composite_id": "cid:ind:x:1-2-3",
            "aid": "a" * 32,  # 32-hex agent id must not be surfaced as an indicator
            "device_id": "b" * 32,
        }
        ind = AlertsModule._extract_alert_indicators(alert)
        assert ind == {}

    def test_normal_behavior_alert_has_no_indicators(self):
        alert = {"composite_id": "cid:ind:x:1-2-3", "name": "SuspiciousProcess", "severity": 50}
        assert AlertsModule._extract_alert_indicators(alert) == {}


class TestFormatterRendersIndicators:
    def test_formatter_includes_indicator_block(self):
        module = AlertsModule.__new__(AlertsModule)  # no client needed for pure formatter
        analysis = {
            "success": True,
            "product_name": "Endpoint (EDR)",
            "product_type": "endpoint",
            "alert": {
                "name": "CloudDetect-BlacklistedIPAddressHighUI",
                "composite_id": "cid:ind:x:1-2-3",
                "ioc_type": "remote_address",
                "ioc_value": "203.0.113.55",
            },
            "behaviors": [{"TargetProcessId": "1", "ImageFileName": "x.exe"}],
            "triggering_process": None,
            "triggering_indicators": AlertsModule._extract_alert_indicators({"ioc_type": "remote_address", "ioc_value": "203.0.113.55"}),
        }
        out = module._format_alert_analysis_response(analysis)
        assert "Indicator" in out
        assert "203.0.113.55" in out
