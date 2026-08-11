"""Every list-shaped tool must survive a large response with its tail reachable.

Companion to test_large_response_recoverability.py, which covers the three tools
named in issue #52. This sweeps the rest: any tool whose render is proportional
to a record collection or a JSON dump could drop its tail the same way, and
several measurably did — `correlation_list_rules(max_results=500)` rendered
176,541 chars and returned 6 of the 500 records it claimed in its own header,
with no ref to recover the rest.

Each case drives a tool with enough synthetic records to clear the 20,000-char
render threshold, then asserts three things:

  1. no "no structured_data" notice — the tail is not silently dropped
  2. a resp_XXX ref is minted
  3. get_stored_response can actually READ a record back from that ref

(3) is the one that matters. Passing structured_data is necessary but not
sufficient: ResponseStore.select_records finds nothing in a flat dict of
scalars, so a payload of the wrong shape mints a ref that reads back empty —
which looks fixed and isn't.
"""

import asyncio
import re
from unittest.mock import MagicMock, patch

import pytest

from crowdstrike_mcp.modules.response_store import ResponseStoreModule

# Wide enough that a few hundred of them clear the 20k threshold.
PAD = "x" * 400


def _records(n, **extra):
    return [{"id": f"rec{i}", "name": f"Record {i}", "description": PAD, **extra} for i in range(n)]


@pytest.fixture
def store():
    return ResponseStoreModule(MagicMock())


def _module(mock_client, module_path, class_name, patched=()):
    mod = __import__(f"crowdstrike_mcp.modules.{module_path}", fromlist=[class_name])
    if not patched:
        return getattr(mod, class_name)(mock_client)
    with patch.multiple(f"crowdstrike_mcp.modules.{module_path}", **{p: MagicMock() for p in patched}):
        return getattr(mod, class_name)(mock_client)


# (label, module, class, patched_names, seam, fake_result, call)
CASES = [
    (
        "cao_search_queries",
        "cao_hunting",
        "CAOHuntingModule",
        (),
        "_search_queries",
        lambda: {"success": True, "count": 300, "total": 300, "queries": _records(300, content=PAD)},
        lambda m: m.cao_search_queries(),
    ),
    (
        "cao_search_guides",
        "cao_hunting",
        "CAOHuntingModule",
        (),
        "_search_guides",
        lambda: {"success": True, "count": 300, "total": 300, "guides": _records(300, content=PAD)},
        lambda m: m.cao_search_guides(),
    ),
    (
        "cloud_get_risks",
        "cloud_security",
        "CloudSecurityModule",
        (),
        "_get_cloud_risks",
        lambda: {
            "success": True,
            "count": 300,
            "total": 300,
            "risks": [
                {
                    "severity": "Low",
                    "rule_name": f"Rule {i}",
                    "score": 30,
                    "provider": "AWS",
                    "account_id": "1",
                    "asset_type": "t",
                    "asset_id": "a",
                    "status": "Open",
                    "service_category": "Identity",
                    "rule_description": PAD,
                    "id": f"risk{i}",
                }
                for i in range(300)
            ],
        },
        lambda m: m.cloud_get_risks(max_results=500),
    ),
    (
        "correlation_list_rules",
        "correlation",
        "CorrelationModule",
        (),
        "_list_rules",
        lambda: {"success": True, "count": 300, "total": 675, "rules": _records(300)},
        lambda m: m.correlation_list_rules(max_results=500),
    ),
    (
        "correlation_get_rule",
        "correlation",
        "CorrelationModule",
        (),
        "_get_rules",
        lambda: {"success": True, "count": 40, "rules": _records(40)},
        lambda m: m.correlation_get_rule(rule_ids=["r1"]),
    ),
    (
        "spotlight_query_vulnerabilities",
        "spotlight",
        "SpotlightModule",
        (),
        "_query_vulnerabilities",
        lambda: {"success": True, "ids": [f"vuln-id-{i}-{PAD}" for i in range(300)], "total": 300},
        lambda m: m.spotlight_query_vulnerabilities(filter="status:'open'", limit=500),
    ),
    (
        "spotlight_get_vulnerabilities",
        "spotlight",
        "SpotlightModule",
        (),
        "_get_vulnerabilities",
        lambda: {
            "success": True,
            "resources": [
                {"cve": {"id": f"CVE-{i}", "severity": "HIGH", "base_score": 9.8}, "host_info": {"hostname": PAD}, "status": "open"} for i in range(300)
            ],
        },
        lambda m: m.spotlight_get_vulnerabilities(ids=["a"]),
    ),
    (
        "spotlight_get_remediations",
        "spotlight",
        "SpotlightModule",
        (),
        "_get_remediations",
        lambda: {"success": True, "resources": [{"title": f"Fix {i}", "id": f"r{i}", "action": PAD} for i in range(300)]},
        lambda m: m.spotlight_get_remediations(ids=["a"]),
    ),
    (
        "rtr_list_sessions",
        "rtr",
        "RTRModule",
        (),
        "_list_sessions",
        lambda: {"success": True, "sessions": [{"id": f"s{i}", "device_id": PAD, "pwd": PAD} for i in range(300)]},
        lambda m: m.rtr_list_sessions(ids=["s1"]),
    ),
    (
        "rtr_list_files",
        "rtr",
        "RTRModule",
        (),
        "_list_files",
        lambda: {"success": True, "files": [{"name": f"f{i}", "sha256": PAD, "size": 1} for i in range(300)]},
        lambda m: m.rtr_list_files(session_id="s1"),
    ),
    (
        "cloud_list_accounts",
        "cloud_registration",
        "CloudRegistrationModule",
        (),
        "_list_accounts",
        lambda: {
            "success": True,
            "total_count": 300,
            "providers_queried": ["aws"],
            "accounts": {"aws": [{"account_id": f"a{i}", "account_name": PAD, "status": PAD} for i in range(300)]},
        },
        lambda m: m.cloud_list_accounts(),
    ),
]


@pytest.mark.parametrize("label,mod,cls,patched,seam,fake,call", CASES, ids=[c[0] for c in CASES])
def test_large_response_keeps_a_readable_ref(mock_client, store, label, mod, cls, patched, seam, fake, call):
    module = _module(mock_client, mod, cls, patched)
    setattr(module, seam, lambda *a, **k: fake())

    out = asyncio.run(call(module))

    assert "no structured_data" not in out, f"{label} still drops its tail"
    assert "Tool 'unknown'" not in out, f"{label} does not name itself"

    match = re.search(r"resp_\d+", out)
    assert match, f"{label} minted no ref; the withheld records are unrecoverable:\n{out[:300]}"

    back = asyncio.run(store.get_stored_response(ref_id=match.group(0), record_index=0))
    assert "No records found" not in back, f"{label} minted a ref that reads back EMPTY — wrong payload shape"
    assert back.strip() not in ("[]", "{}"), f"{label} readback is empty"


def test_the_sweep_actually_exercises_truncation():
    """Guard the guard: if the synthetic payloads stopped clearing the render
    threshold, every case above would pass without testing anything."""
    from crowdstrike_mcp.utils import LARGE_RESPONSE_THRESHOLD

    assert len(PAD) * 300 > LARGE_RESPONSE_THRESHOLD
