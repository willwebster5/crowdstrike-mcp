"""
Threat Graph Module — CrowdStrike Threat Graph read surface (process/file/network/identity edges).

Tools:
  threatgraph_get_vertices      — Fetch vertex metadata by composite ID
  threatgraph_get_edges         — Walk outgoing/incoming edges of one edge type
  threatgraph_get_ran_on        — Find hosts/processes where an indicator was observed
  threatgraph_get_summary       — Short triage-ready summary for vertex IDs
  threatgraph_get_edge_types    — Refresh (and return) the edge-type catalog

Resources:
  falcon://reference/threatgraph-edge-types
    Lazily populated from get_edge_types() on first read. Invalidated when
    the threatgraph_get_edge_types tool is called. First module in this repo
    with a *dynamic* MCP resource; static-content resources live in
    resources/fql_guides.py.

Vertex IDs are composite strings. The most common form is:
  pid:<aid>:<offset_ns>
where <aid> is the Falcon agent ID and <offset_ns> is a nanosecond-precision
offset from the alert / process payload. Every tool docstring includes the
recipe.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated, Literal, Optional

try:
    from falconpy import ThreatGraph

    THREATGRAPH_AVAILABLE = True
except ImportError:
    THREATGRAPH_AVAILABLE = False

from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.resources.threatgraph_reference import ThreatGraphEdgeTypeCache
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


EDGE_TYPES_RESOURCE_URI = "falcon://reference/threatgraph-edge-types"


class ThreatGraphModule(BaseModule):
    """Threat Graph read-only pivots (vertices, edges, ran-on, summary)."""

    _MAX_LIMIT = 1000

    def __init__(self, client):
        super().__init__(client)
        if not THREATGRAPH_AVAILABLE:
            raise ImportError("ThreatGraph not available. Ensure crowdstrike-falconpy >= 1.6.1 is installed.")
        self._edge_type_cache = ThreatGraphEdgeTypeCache(self._fetch_edge_types)
        self._log("Initialized")

    def register_resources(self, server: FastMCP) -> None:
        def _edge_types_body():
            return self._edge_type_cache.read()

        server.resource(
            EDGE_TYPES_RESOURCE_URI,
            name="Threat Graph Edge Types",
            description="Live list of Threat Graph edge types (cached in-process).",
        )(_edge_types_body)
        self.resources.append(EDGE_TYPES_RESOURCE_URI)

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.threatgraph_get_edge_types,
            name="threatgraph_get_edge_types",
            description=(
                "Refresh and return the live list of Threat Graph edge types. "
                "Also invalidates the falcon://reference/threatgraph-edge-types "
                "cache so the next resource read re-fetches. Use sparingly; "
                "prefer reading the resource."
            ),
        )
        self._add_tool(
            server,
            self.threatgraph_get_vertices,
            name="threatgraph_get_vertices",
            description=(
                "Fetch Threat Graph vertex metadata by composite ID. Vertex IDs "
                "take the form pid:<aid>:<offset_ns> for processes; other shapes "
                "exist for files, users, etc. Recipe: from an alert payload, "
                "assemble pid:<alert.device.device_id>:<alert.pattern_disposition_details.process_timestamp_ns>. "
                "Use vertex_type=process|file|domain|ip_address|user|module|... ; "
                "scope defaults to 'device' (per-host)."
            ),
        )
        self._add_tool(
            server,
            self.threatgraph_get_edges,
            name="threatgraph_get_edges",
            description=(
                "Walk edges of one type out of (or into) a set of vertex IDs. "
                "One edge_type per call; discover valid edge types via the "
                "falcon://reference/threatgraph-edge-types resource or "
                "threatgraph_get_edge_types tool. direction='primary' "
                "walks outgoing edges, 'secondary' walks incoming, "
                "None returns both. Defaults: limit=100, scope='device'; "
                "hard cap limit<=1000 (page via offset)."
            ),
        )
        self._add_tool(
            server,
            self.threatgraph_get_ran_on,
            name="threatgraph_get_ran_on",
            description=(
                "Look up where an indicator (hash, domain, IP) was observed in "
                "the environment. type=hash_md5|hash_sha256|domain|ip_address. "
                "Returns a list of hosts/processes where the indicator was seen — "
                "the starting point for IOC → affected-process-chain pivots. "
                "Defaults: limit=100, scope='device'; cap limit<=1000."
            ),
        )
        self._add_tool(
            server,
            self.threatgraph_get_summary,
            name="threatgraph_get_summary",
            description=(
                "Short triage-ready summary for one or more vertex IDs. Use "
                "after threatgraph_get_vertices to get a one-line-per-vertex "
                "overview rather than full properties."
            ),
        )

    async def threatgraph_get_edge_types(self) -> str:
        """Refresh the edge-type cache and return the current list."""
        try:
            response = self._fetch_edge_types()
            if response.get("status_code") != 200:
                err = format_api_error(
                    response,
                    "Failed to get edge types",
                    operation="queries_edgetypes_get",
                )
                return format_text_response(f"Failed to get edge types: {err}", raw=True)
            # Invalidate then re-read so the cache picks up the fresh response
            self._edge_type_cache.invalidate()
            body = self._edge_type_cache.read()
            return format_text_response(
                body,
                tool_name="threatgraph_get_edge_types",
                raw=True,
                structured_data={"records": [{"edge_types": body}]},
                metadata={},
            )
        except Exception as e:
            return format_text_response(f"Failed to get edge types: {e}", raw=True)

    async def threatgraph_get_vertices(
        self,
        ids: Annotated[list[str], "Composite vertex IDs (e.g. ['pid:<aid>:<offset_ns>'])"],
        vertex_type: Annotated[str, "Vertex type: process, file, domain, ip_address, user, module, etc."],
        scope: Annotated[Literal["device", "customer", "global", "cspm", "cwpp"], "Query scope"] = "device",
        nano: Annotated[bool, "Return nano-precision timestamps"] = False,
    ) -> str:
        """Fetch vertex metadata by composite ID (uses get_vertices_v2)."""
        if not ids:
            return format_text_response("Failed: ids is required", raw=True)
        try:
            falcon = self._service(ThreatGraph)
            response = falcon.get_vertices_v2(
                ids=ids,
                vertex_type=vertex_type,
                scope=scope,
                nano=nano,
            )
            return _handle_list_response(response, "get vertices", "entities_vertices_getv2", "Threat Graph Vertices")
        except Exception as e:
            return format_text_response(f"Failed to get vertices: {e}", raw=True)

    async def threatgraph_get_edges(
        self,
        ids: Annotated[list[str], "Source vertex IDs"],
        edge_type: Annotated[str, "Edge type (see falcon://reference/threatgraph-edge-types)"],
        direction: Annotated[Optional[Literal["primary", "secondary"]], "Edge direction: primary=outgoing, secondary=incoming, None=both"] = None,
        scope: Annotated[Literal["device", "customer", "global", "cspm", "cwpp"], "Query scope"] = "device",
        limit: Annotated[int, "Max edges per call (default 100, max 1000)"] = 100,
        offset: Annotated[Optional[str], "Pagination token from a prior call"] = None,
        nano: Annotated[bool, "Return nano-precision timestamps"] = False,
    ) -> str:
        """Walk edges of one edge_type out of/into the given vertex IDs."""
        if not ids:
            return format_text_response("Failed: ids is required", raw=True)
        if not edge_type:
            return format_text_response("Failed: edge_type is required", raw=True)
        if limit > self._MAX_LIMIT:
            return format_text_response(
                f"Failed: limit={limit} exceeds max {self._MAX_LIMIT}. Page through results using the offset argument.",
                raw=True,
            )
        kwargs = {
            "ids": ids,
            "edge_type": edge_type,
            "scope": scope,
            "limit": limit,
            "nano": nano,
        }
        if direction is not None:
            kwargs["direction"] = direction
        if offset:
            kwargs["offset"] = offset
        try:
            falcon = self._service(ThreatGraph)
            response = falcon.get_edges(**kwargs)
            return _handle_list_response(
                response,
                "get edges",
                "combined_edges_get",
                "Threat Graph Edges",
                status_hints={
                    400: (
                        "\n\nHint: call `threatgraph_get_edge_types` or read `falcon://reference/threatgraph-edge-types` for the valid edge_type values."
                    )
                },
            )
        except Exception as e:
            return format_text_response(f"Failed to get edges: {e}", raw=True)

    async def threatgraph_get_ran_on(
        self,
        value: Annotated[str, "Indicator value (e.g. a SHA256 hash, a domain, or an IP)"],
        type: Annotated[Literal["hash_md5", "hash_sha256", "domain", "ip_address"], "Indicator type"],
        scope: Annotated[Literal["device", "customer", "global", "cspm", "cwpp"], "Query scope"] = "device",
        limit: Annotated[int, "Max results (default 100, max 1000)"] = 100,
        offset: Annotated[Optional[str], "Pagination token from a prior call"] = None,
        nano: Annotated[bool, "Return nano-precision timestamps"] = False,
    ) -> str:
        """Find observations of an indicator across hosts/processes."""
        if not value:
            return format_text_response("Failed: value is required", raw=True)
        if not type:
            return format_text_response("Failed: type is required", raw=True)
        if limit > self._MAX_LIMIT:
            return format_text_response(
                f"Failed: limit={limit} exceeds max {self._MAX_LIMIT}. Page through results using the offset argument.",
                raw=True,
            )
        kwargs = {
            "value": value,
            "type": type,
            "scope": scope,
            "limit": limit,
            "nano": nano,
        }
        if offset:
            kwargs["offset"] = offset
        try:
            falcon = self._service(ThreatGraph)
            response = falcon.get_ran_on(**kwargs)
            return _handle_list_response(response, "get ran_on", "combined_ran_on_get", "Threat Graph Ran-On")
        except Exception as e:
            return format_text_response(f"Failed to get ran_on: {e}", raw=True)

    async def threatgraph_get_summary(
        self,
        ids: Annotated[list[str], "Composite vertex IDs"],
        vertex_type: Annotated[str, "Vertex type (process, file, etc.)"],
        scope: Annotated[Literal["device", "customer", "global", "cspm", "cwpp"], "Query scope"] = "device",
        nano: Annotated[bool, "Return nano-precision timestamps"] = False,
    ) -> str:
        """Fetch triage-ready vertex summaries."""
        if not ids:
            return format_text_response("Failed: ids is required", raw=True)
        try:
            falcon = self._service(ThreatGraph)
            response = falcon.get_summary(
                ids=ids,
                vertex_type=vertex_type,
                scope=scope,
                nano=nano,
            )
            return _handle_list_response(response, "get summary", "combined_summary_get", "Threat Graph Summary")
        except Exception as e:
            return format_text_response(f"Failed to get summary: {e}", raw=True)

    # -------- internal helpers --------

    def _fetch_edge_types(self) -> dict:
        """Invoke ThreatGraph.get_edge_types(); used as the cache fetcher."""
        falcon = self._service(ThreatGraph)
        return falcon.get_edge_types()


def _render_resources(header: str, response: dict) -> str:
    body = response.get("body") or {}
    resources = body.get("resources") or []
    meta = body.get("meta") or {}
    pagination = meta.get("pagination") or {}
    lines = [f"{header}: {len(resources)} returned"]
    if pagination.get("total") is not None:
        lines[-1] += f" (total={pagination['total']})"
    if pagination.get("offset"):
        lines.append(f"Next offset: `{pagination['offset']}`")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(resources, indent=2, default=str))
    lines.append("```")
    return "\n".join(lines)


def _handle_list_response(
    response: dict,
    operation_context: str,
    operation_code: str,
    result_header: str,
    status_hints: dict[int, str] | None = None,
) -> str:
    """Render a falconpy list response, or format the error with an optional status-specific hint."""
    status = response.get("status_code")
    if status != 200:
        err = format_api_error(response, f"Failed to {operation_context}", operation=operation_code)
        hint = (status_hints or {}).get(status, "") if status_hints else ""
        return format_text_response(f"Failed to {operation_context}: {err}{hint}", raw=True)
    body = response.get("body") or {}
    return format_text_response(
        _render_resources(result_header, response),
        tool_name=operation_code,
        raw=True,
        structured_data={"resources": body.get("resources") or []},
        metadata={"operation": operation_code, "meta": body.get("meta") or {}},
    )
