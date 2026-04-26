"""
NGSIEM render module — interactive Prefab UI for NGSIEM query results.

Registers two tools:
  ngsiem_query_render     — UI tool, returns a Prefab layout + ref_id summary
  ngsiem_query_drilldown  — backend tool the UI calls on row click

Imports prefab_ui lazily; if the optional dependency isn't installed, this
package still imports cleanly but ``RENDER_AVAILABLE`` is False and the
module class is not exposed. The auto-discovery walker in registry.py
checks for ``BaseModule`` subclasses on the imported module — when
RENDER_AVAILABLE is False we don't expose one, so nothing registers.
"""

from __future__ import annotations

try:
    import prefab_ui  # noqa: F401
    RENDER_AVAILABLE = True
except ImportError:
    RENDER_AVAILABLE = False

if RENDER_AVAILABLE:
    try:
        from crowdstrike_mcp.modules.ngsiem_render._module import NGSIEMRenderModule
        __all__ = ["NGSIEMRenderModule", "RENDER_AVAILABLE"]
    except ImportError:
        # _module not yet created (during incremental implementation) or has
        # its own broken dep. Allow the package to import so RENDER_AVAILABLE
        # is observable even before _module lands.
        __all__ = ["RENDER_AVAILABLE"]
else:
    __all__ = ["RENDER_AVAILABLE"]
