"""
Browser dev preview for the NGSIEM render UI.

Exposes the NGSIEMRenderModule's internal FastMCPApp as ``app`` so the
fastmcp dev tooling can pick it up. Run with::

    fastmcp dev apps scripts/dev_render.py

This launches the user MCP server on :8000 and the Prefab dev UI on
:8080, opens a browser, and gives you a tool picker + interactive
preview backed by deterministic mock events (no NG-SIEM creds needed).

The script forces ``CROWDSTRIKE_RENDER_MOCK=1`` so the render tool
short-circuits the live query path and returns 20 generated events.
Set the env var to a falsy value externally to override and hit live
NG-SIEM.

Hot reload is on by default via ``--reload``; edits to the
``modules/ngsiem_render`` package re-spawn the server. Saving a layout
change refreshes in seconds vs a full Claude Desktop restart.
"""

from __future__ import annotations

import os

# Default to mock-mode unless the developer explicitly sets the flag elsewhere.
os.environ.setdefault("CROWDSTRIKE_RENDER_MOCK", "1")

from crowdstrike_mcp.client import FalconClient
from crowdstrike_mcp.modules.ngsiem_render import NGSIEMRenderModule

# FalconClient.deferred() builds a credential-less stub. NGSIEMRenderModule
# wires it through NGSIEMModule but never authenticates while the mock flag
# is on — execute_query is short-circuited before any FalconPy call.
_client = FalconClient.deferred()
_module = NGSIEMRenderModule(_client)

# fastmcp run / dev apps auto-detect a top-level `app` variable.
app = _module._app
