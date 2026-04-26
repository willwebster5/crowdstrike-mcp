"""
Mock NGSIEM data for the Prefab pilot.

Generates deterministic-per-seed synthetic ProcessRollup2-style events so the
pilot can be run without Falcon credentials. When the follow-up agent wires
this up to real FalconPy calls, swap ``generate_process_events`` for the
live NGSIEM query and keep the same return shape.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

HOSTS = ["DESKTOP-AB1C2DE", "LAPTOP-X9Y8Z7", "SRV-DB01", "SRV-WEB02", "WKS-HR-04"]
USERS = ["jsmith", "awong", "rbell", "mperez", "SYSTEM"]
EVENT_NAMES = [
    "ProcessRollup2",
    "NetworkConnectIP4",
    "DnsRequest",
    "FileOpenInfo",
    "RegistryOperationDetectInfo",
]
IMAGES = [
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\System32\\powershell.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Windows\\System32\\svchost.exe",
    "/usr/bin/bash",
    "/usr/local/bin/node",
]


def generate_process_events(count: int, seed: int = 0) -> list[dict]:
    """Return ``count`` synthetic NGSIEM events, monotonically ascending in time."""
    rng = random.Random(seed)
    now = datetime(2026, 4, 22, 12, 0, 0, tzinfo=timezone.utc)
    step = timedelta(seconds=max(1, 86400 // max(1, count)))

    events: list[dict] = []
    for i in range(count):
        ts = now - (timedelta(days=1) - step * i)
        events.append(
            {
                "@timestamp": ts.isoformat(),
                "aid": f"{rng.randint(10**15, 10**16 - 1):016x}",
                "ComputerName": rng.choice(HOSTS),
                "event_simpleName": rng.choice(EVENT_NAMES),
                "UserName": rng.choice(USERS),
                "ImageFileName": rng.choice(IMAGES),
                "CommandLine": f"--flag={rng.randint(1, 999)}",
            }
        )
    return events
