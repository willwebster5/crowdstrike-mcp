"""
CAO Hunting Module — intelligence queries and hunting guides.

Tools:
  cao_search_queries  — Search and retrieve intelligence queries
  cao_get_queries     — Get intelligence queries by IDs
  cao_search_guides   — Search and retrieve hunting guides
  cao_get_guides      — Get hunting guides by IDs
  cao_aggregate       — Aggregate intelligence queries or hunting guides
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Optional

from crowdstrike_mcp.common.errors import format_api_error
from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

try:
    from falconpy import CAOHunting

    CAO_HUNTING_AVAILABLE = True
except ImportError:
    CAO_HUNTING_AVAILABLE = False


class CAOHuntingModule(BaseModule):
    """Intelligence queries and hunting guides from CrowdStrike CAO."""

    def __init__(self, client):
        super().__init__(client)

        if not CAO_HUNTING_AVAILABLE:
            raise ImportError("CAOHunting FalconPy class not available. Ensure crowdstrike-falconpy >= 1.6.0 is installed.")

        self._log("Initialized")

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.cao_search_queries,
            name="cao_search_queries",
            description=(
                "Search CrowdStrike intelligence queries (CAO Hunting). "
                "Returns curated threat-hunting queries with metadata, "
                "filterable by FQL or free-text search."
            ),
        )
        self._add_tool(
            server,
            self.cao_get_queries,
            name="cao_get_queries",
            description=("Retrieve specific intelligence queries by their IDs. Use after cao_search_queries or when IDs are already known."),
        )
        self._add_tool(
            server,
            self.cao_search_guides,
            name="cao_search_guides",
            description=(
                "Search CrowdStrike hunting guides (CAO Hunting). "
                "Returns curated threat-hunting guides with metadata, "
                "filterable by FQL or free-text search."
            ),
        )
        self._add_tool(
            server,
            self.cao_get_guides,
            name="cao_get_guides",
            description=("Retrieve specific hunting guides by their IDs. Use after cao_search_guides or when IDs are already known."),
        )
        self._add_tool(
            server,
            self.cao_aggregate,
            name="cao_aggregate",
            description=("Aggregate intelligence queries or hunting guides by field. Supports terms, date_range, range, and cardinality aggregations."),
        )

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    async def cao_search_queries(
        self,
        filter: Annotated[Optional[str], "FQL filter expression for intelligence queries"] = None,
        q: Annotated[Optional[str], "Free-text search across query metadata"] = None,
        sort: Annotated[Optional[str], "Sort field and direction (e.g. 'created_on|desc')"] = None,
        include_translated_content: Annotated[bool, "Include AI-translated content (SPL, etc.)"] = False,
        max_results: Annotated[int, "Maximum queries to return (default: 20)"] = 20,
    ) -> str:
        """Search and retrieve intelligence queries."""
        result = self._search_queries(filter, q, sort, include_translated_content, max_results)

        if not result.get("success"):
            return format_text_response(f"Failed to search intelligence queries: {result.get('error')}", raw=True)

        queries = result["queries"]
        lines = [
            f"Intelligence Queries: {result['count']} returned (of {result['total']} total)",
            "",
        ]

        if not queries:
            lines.append("No intelligence queries found matching the criteria.")
        else:
            for i, q_item in enumerate(queries, 1):
                lines.append(f"{i}. {q_item['name']}")
                if q_item.get("description"):
                    lines.append(f"   {q_item['description'][:200]}")
                lines.append(f"   ID: {q_item['id']}")
                if q_item.get("tags"):
                    lines.append(f"   Tags: {', '.join(q_item['tags'][:10])}")
                if q_item.get("created_on"):
                    lines.append(f"   Created: {q_item['created_on']}")
                if q_item.get("modified_on"):
                    lines.append(f"   Modified: {q_item['modified_on']}")
                if q_item.get("content"):
                    lines.append(f"   Content: {q_item['content'][:300]}")
                if q_item.get("translated_content"):
                    for lang, text in q_item["translated_content"].items():
                        lines.append(f"   [{lang}]: {text[:200]}")
                lines.append("")

        return format_text_response(
            "\n".join(lines),
            tool_name="cao_search_queries",
            raw=True,
            structured_data={"records": queries},
            metadata={"filter": filter, "q": q, "max_results": max_results},
        )

    async def cao_get_queries(
        self,
        ids: Annotated[str, "Comma-separated intelligence query IDs"],
        include_translated_content: Annotated[bool, "Include AI-translated content"] = False,
    ) -> str:
        """Retrieve intelligence queries by IDs."""
        id_list = [i.strip() for i in ids.split(",") if i.strip()]
        if not id_list:
            return format_text_response("No valid IDs provided.", raw=True)

        result = self._get_queries_by_ids(id_list, include_translated_content)

        if not result.get("success"):
            return format_text_response(f"Failed to get intelligence queries: {result.get('error')}", raw=True)

        queries = result["queries"]
        lines = [f"Intelligence Queries: {len(queries)} returned", ""]

        if not queries:
            lines.append("No intelligence queries found for the given IDs.")
        else:
            for i, q_item in enumerate(queries, 1):
                lines.append(f"{i}. {q_item['name']}")
                if q_item.get("description"):
                    lines.append(f"   {q_item['description'][:200]}")
                lines.append(f"   ID: {q_item['id']}")
                if q_item.get("tags"):
                    lines.append(f"   Tags: {', '.join(q_item['tags'][:10])}")
                if q_item.get("created_on"):
                    lines.append(f"   Created: {q_item['created_on']}")
                if q_item.get("modified_on"):
                    lines.append(f"   Modified: {q_item['modified_on']}")
                if q_item.get("content"):
                    lines.append(f"   Content: {q_item['content'][:300]}")
                if q_item.get("translated_content"):
                    for lang, text in q_item["translated_content"].items():
                        lines.append(f"   [{lang}]: {text[:200]}")
                lines.append("")

        return format_text_response(
            "\n".join(lines),
            tool_name="cao_get_queries",
            raw=True,
            structured_data={"records": queries},
            metadata={"ids": id_list},
        )

    async def cao_search_guides(
        self,
        filter: Annotated[Optional[str], "FQL filter expression for hunting guides"] = None,
        q: Annotated[Optional[str], "Free-text search across guide metadata"] = None,
        sort: Annotated[Optional[str], "Sort field and direction"] = None,
        max_results: Annotated[int, "Maximum guides to return (default: 20)"] = 20,
    ) -> str:
        """Search and retrieve hunting guides."""
        result = self._search_guides(filter, q, sort, max_results)

        if not result.get("success"):
            return format_text_response(f"Failed to search hunting guides: {result.get('error')}", raw=True)

        guides = result["guides"]
        lines = [
            f"Hunting Guides: {result['count']} returned (of {result['total']} total)",
            "",
        ]

        if not guides:
            lines.append("No hunting guides found matching the criteria.")
        else:
            for i, g in enumerate(guides, 1):
                lines.append(f"{i}. {g['name']}")
                if g.get("description"):
                    lines.append(f"   {g['description'][:200]}")
                lines.append(f"   ID: {g['id']}")
                if g.get("tags"):
                    lines.append(f"   Tags: {', '.join(g['tags'][:10])}")
                if g.get("created_on"):
                    lines.append(f"   Created: {g['created_on']}")
                if g.get("modified_on"):
                    lines.append(f"   Modified: {g['modified_on']}")
                if g.get("content"):
                    lines.append(f"   Content: {g['content'][:300]}")
                lines.append("")

        return format_text_response(
            "\n".join(lines),
            tool_name="cao_search_guides",
            raw=True,
            structured_data={"records": guides},
            metadata={"filter": filter, "q": q, "max_results": max_results},
        )

    async def cao_get_guides(
        self,
        ids: Annotated[str, "Comma-separated hunting guide IDs"],
    ) -> str:
        """Retrieve hunting guides by IDs."""
        id_list = [i.strip() for i in ids.split(",") if i.strip()]
        if not id_list:
            return format_text_response("No valid IDs provided.", raw=True)

        result = self._get_guides_by_ids(id_list)

        if not result.get("success"):
            return format_text_response(f"Failed to get hunting guides: {result.get('error')}", raw=True)

        guides = result["guides"]
        lines = [f"Hunting Guides: {len(guides)} returned", ""]

        if not guides:
            lines.append("No hunting guides found for the given IDs.")
        else:
            for i, g in enumerate(guides, 1):
                lines.append(f"{i}. {g['name']}")
                if g.get("description"):
                    lines.append(f"   {g['description'][:200]}")
                lines.append(f"   ID: {g['id']}")
                if g.get("tags"):
                    lines.append(f"   Tags: {', '.join(g['tags'][:10])}")
                if g.get("created_on"):
                    lines.append(f"   Created: {g['created_on']}")
                if g.get("modified_on"):
                    lines.append(f"   Modified: {g['modified_on']}")
                if g.get("content"):
                    lines.append(f"   Content: {g['content'][:300]}")
                lines.append("")

        return format_text_response(
            "\n".join(lines),
            tool_name="cao_get_guides",
            raw=True,
            structured_data={"records": guides},
            metadata={"ids": id_list},
        )

    async def cao_aggregate(
        self,
        field: Annotated[str, "Field to aggregate on (e.g. 'severity', 'tags', 'created_on')"],
        type: Annotated[str, "Aggregation type: 'terms', 'date_range', 'range', 'cardinality'"] = "terms",
        resource_type: Annotated[str, "What to aggregate: 'queries' or 'guides'"] = "queries",
        filter: Annotated[Optional[str], "FQL filter to scope the aggregation"] = None,
        size: Annotated[int, "Number of buckets to return (default: 10)"] = 10,
    ) -> str:
        """Aggregate intelligence queries or hunting guides by field."""
        if resource_type not in ("queries", "guides"):
            return format_text_response("Invalid resource_type: must be 'queries' or 'guides'.", raw=True)

        result = self._aggregate(resource_type, field, type, filter, size)

        if not result.get("success"):
            return format_text_response(f"Failed to aggregate {resource_type}: {result.get('error')}", raw=True)

        buckets = result["buckets"]
        lines = [
            f"Aggregation: {field} ({type}) on {resource_type}",
            "",
        ]

        if not buckets:
            lines.append("No aggregation results.")
        else:
            for b in buckets:
                label = b.get("label", b.get("key", "unknown"))
                count = b.get("count", 0)
                lines.append(f"  {label}: {count}")

        return format_text_response(
            "\n".join(lines),
            tool_name="cao_aggregate",
            raw=True,
            structured_data={"records": buckets},
            metadata={"field": field, "type": type, "resource_type": resource_type, "filter": filter},
        )

    # ------------------------------------------------------------------
    # Internal methods
    # ------------------------------------------------------------------

    def _search_queries(self, filter=None, q=None, sort=None, include_translated_content=False, max_results=20):
        try:
            cao = self._service(CAOHunting)
            kwargs = {"limit": min(max_results, 100)}
            if filter:
                kwargs["filter"] = filter
            if q:
                kwargs["q"] = q
            if sort:
                kwargs["sort"] = sort

            r = cao.search_queries(**kwargs)
            if r["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(r, "Failed to search queries", operation="search_queries"),
                }

            query_ids = r.get("body", {}).get("resources", [])
            total = r.get("body", {}).get("meta", {}).get("pagination", {}).get("total", len(query_ids))

            if not query_ids:
                return {"success": True, "queries": [], "count": 0, "total": total}

            return self._get_queries_by_ids(query_ids, include_translated_content, total=total)
        except Exception as e:
            return {"success": False, "error": f"Error searching intelligence queries: {e}"}

    def _get_queries_by_ids(self, ids, include_translated_content=False, total=None):
        try:
            cao = self._service(CAOHunting)
            kwargs = {"ids": ids}
            if include_translated_content:
                kwargs["include_translated_content"] = "__all__"

            r = cao.get_queries(**kwargs)
            if r["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(r, "Failed to get queries", operation="get_queries"),
                }

            resources = r.get("body", {}).get("resources", [])

            queries = []
            for q in resources:
                entry = {
                    "id": q.get("id", ""),
                    "name": q.get("name", ""),
                    "description": q.get("description", ""),
                    "content": q.get("content", ""),
                    "tags": q.get("tags", []),
                    "created_on": q.get("created_on", ""),
                    "modified_on": q.get("modified_on", ""),
                }
                if include_translated_content and q.get("translated_content"):
                    entry["translated_content"] = q["translated_content"]
                queries.append(entry)

            return {
                "success": True,
                "queries": queries,
                "count": len(queries),
                "total": total if total is not None else len(queries),
            }
        except Exception as e:
            return {"success": False, "error": f"Error getting intelligence queries: {e}"}

    def _search_guides(self, filter=None, q=None, sort=None, max_results=20):
        try:
            cao = self._service(CAOHunting)
            kwargs = {"limit": min(max_results, 100)}
            if filter:
                kwargs["filter"] = filter
            if q:
                kwargs["q"] = q
            if sort:
                kwargs["sort"] = sort

            r = cao.search_guides(**kwargs)
            if r["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(r, "Failed to search guides", operation="search_guides"),
                }

            guide_ids = r.get("body", {}).get("resources", [])
            total = r.get("body", {}).get("meta", {}).get("pagination", {}).get("total", len(guide_ids))

            if not guide_ids:
                return {"success": True, "guides": [], "count": 0, "total": total}

            return self._get_guides_by_ids(guide_ids, total=total)
        except Exception as e:
            return {"success": False, "error": f"Error searching hunting guides: {e}"}

    def _get_guides_by_ids(self, ids, total=None):
        try:
            cao = self._service(CAOHunting)
            r = cao.get_guides(ids=ids)
            if r["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(r, "Failed to get guides", operation="get_guides"),
                }

            resources = r.get("body", {}).get("resources", [])

            guides = []
            for g in resources:
                guides.append(
                    {
                        "id": g.get("id", ""),
                        "name": g.get("name", ""),
                        "description": g.get("description", ""),
                        "content": g.get("content", ""),
                        "tags": g.get("tags", []),
                        "created_on": g.get("created_on", ""),
                        "modified_on": g.get("modified_on", ""),
                    }
                )

            return {
                "success": True,
                "guides": guides,
                "count": len(guides),
                "total": total if total is not None else len(guides),
            }
        except Exception as e:
            return {"success": False, "error": f"Error getting hunting guides: {e}"}

    def _aggregate(self, resource_type, field, agg_type, filter=None, size=10):
        try:
            cao = self._service(CAOHunting)
            body = [{"field": field, "type": agg_type, "size": size}]
            if filter:
                body[0]["filter"] = filter

            if resource_type == "queries":
                r = cao.aggregate_queries(body=body)
                op = "aggregate_queries"
            else:
                r = cao.aggregate_guides(body=body)
                op = "aggregate_guides"

            if r["status_code"] != 200:
                return {
                    "success": False,
                    "error": format_api_error(r, f"Failed to aggregate {resource_type}", operation=op),
                }

            resources = r.get("body", {}).get("resources", [])

            buckets = []
            for agg in resources:
                for bucket in agg.get("buckets", []):
                    buckets.append(
                        {
                            "key": bucket.get("key", ""),
                            "label": bucket.get("label", bucket.get("key", "")),
                            "count": bucket.get("count", 0),
                        }
                    )

            return {"success": True, "buckets": buckets}
        except Exception as e:
            return {"success": False, "error": f"Error aggregating {resource_type}: {e}"}
