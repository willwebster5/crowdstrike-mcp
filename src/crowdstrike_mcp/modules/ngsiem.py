"""
NGSIEM Module — CQL query execution + read-only introspection.

Tools:
  ngsiem_query                      — Execute CQL query across all CrowdStrike logs
  ngsiem_list_saved_queries         — Enumerate saved searches
  ngsiem_get_saved_query_template   — Fetch one saved search's body + metadata
  ngsiem_list_lookup_files          — Enumerate lookup files
  ngsiem_get_lookup_file            — Fetch a lookup file (metadata; content opt-in)
  ngsiem_list_dashboards            — Enumerate dashboards
  ngsiem_list_parsers               — Enumerate parsers
  ngsiem_get_parser                 — Fetch a parser's live config + script
  ngsiem_list_data_connections      — Enumerate ingestion pipelines
  ngsiem_get_data_connection        — Fetch one data connection's state
  ngsiem_get_provisioning_status    — Fetch ingestion health status
  ngsiem_list_data_connectors       — Enumerate connector types
  ngsiem_list_connector_configs     — Enumerate connector configuration instances

All tools are read-only. Writes remain with talonctl. get_ingest_token
is intentionally excluded (credential).
"""

from __future__ import annotations

import re
import time
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Optional

from falconpy import NGSIEM

from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from fastmcp import FastMCP


class NGSIEMModule(BaseModule):
    """NGSIEM query module for global search-all repository."""

    def __init__(self, client):
        super().__init__(client)
        self.repository = "search-all"
        self._log(f"Initialized with global repository: {self.repository}")

    def register_resources(self, server: FastMCP) -> None:
        from crowdstrike_mcp.resources.fql_guides import CQL_SYNTAX

        def _cql_syntax():
            return CQL_SYNTAX

        server.resource(
            "falcon://cql/syntax",
            name="CQL Query Syntax Reference",
            description="Documentation: CQL query language syntax for NGSIEM",
        )(_cql_syntax)
        self.resources.append("falcon://cql/syntax")

    def register_tools(self, server: FastMCP) -> None:
        self._add_tool(
            server,
            self.ngsiem_query,
            name="ngsiem_query",
            description=("Execute NGSIEM/CQL query across all CrowdStrike logs using search-all repository"),
        )
        self._add_tool(
            server,
            self.ngsiem_list_saved_queries,
            name="ngsiem_list_saved_queries",
            description="Enumerate saved NGSIEM queries (compact projection by default).",
        )
        self._add_tool(
            server,
            self.ngsiem_get_saved_query_template,
            name="ngsiem_get_saved_query_template",
            description="Fetch the live body + metadata of one saved NGSIEM query.",
        )
        self._add_tool(
            server,
            self.ngsiem_list_lookup_files,
            name="ngsiem_list_lookup_files",
            description="Enumerate NGSIEM lookup files (compact projection by default).",
        )
        self._add_tool(
            server,
            self.ngsiem_get_lookup_file,
            name="ngsiem_get_lookup_file",
            description="Fetch a lookup file; metadata only unless include_content=True.",
        )
        self._add_tool(
            server,
            self.ngsiem_list_dashboards,
            name="ngsiem_list_dashboards",
            description="Enumerate NGSIEM dashboards (compact projection by default).",
        )
        self._add_tool(
            server,
            self.ngsiem_list_parsers,
            name="ngsiem_list_parsers",
            description="Enumerate NGSIEM parsers (compact projection by default).",
        )
        self._add_tool(
            server,
            self.ngsiem_get_parser,
            name="ngsiem_get_parser",
            description="Fetch a parser's live configuration + script.",
        )
        self._add_tool(
            server,
            self.ngsiem_list_data_connections,
            name="ngsiem_list_data_connections",
            description="Enumerate NGSIEM data connections (compact projection by default).",
        )
        self._add_tool(
            server,
            self.ngsiem_get_data_connection,
            name="ngsiem_get_data_connection",
            description="Fetch a single data connection's state + configuration.",
        )
        self._add_tool(
            server,
            self.ngsiem_get_provisioning_status,
            name="ngsiem_get_provisioning_status",
            description="Fetch overall NGSIEM ingestion provisioning / health status.",
        )
        self._add_tool(
            server,
            self.ngsiem_list_data_connectors,
            name="ngsiem_list_data_connectors",
            description="Enumerate available NGSIEM data connector types.",
        )
        self._add_tool(
            server,
            self.ngsiem_list_connector_configs,
            name="ngsiem_list_connector_configs",
            description="Enumerate connector configuration instances (compact projection by default).",
        )

    async def ngsiem_query(
        self,
        query: Annotated[str, "The NGSIEM/CQL query to execute"],
        start_time: Annotated[str, "Time range (e.g. '1h', '1d', '7d', '30d')"] = "1d",
        max_results: Annotated[int, "Maximum results to return (default: 100, max: 1000)"] = 100,
        fields: Annotated[Optional[str], "Comma-separated field names for server-side projection via select()"] = None,
    ) -> str:
        """Execute a CQL query on the search-all repository."""
        max_results = min(max(max_results, 1), 1000)

        result = self.execute_query(query, start_time, max_results, fields=fields)

        if result.get("success"):
            events = result.get("events", [])
            lines = [
                "NGSIEM Query Results (All Logs):",
                f"Query: {result['query']}",
                f"Time Range: {result['time_range']}",
                "Repository: search-all (global)",
                f"Events Processed: {result['events_processed']:,}",
                f"Events Matched: {result['events_matched']:,}",
                f"Events Returned: {result['events_returned']}",
            ]
            if result.get("field_projection"):
                lines.append(f"Field Projection: {', '.join(result['field_projection'])}")
            if result.get("field_projection_skipped"):
                lines.append(f"Note: {result['field_projection_skipped']}")
            if result.get("results_truncated"):
                lines.append(f"Results limited to {max_results} events out of {result['events_matched']} total matches")
            lines.append("")

            if events:
                lines.append("Results:")
                for i, event in enumerate(events[:10]):
                    lines.append(f"\n#{i + 1}:")
                    for key, value in event.items():
                        str_value = str(value)
                        if len(str_value) > 200:
                            str_value = str_value[:200] + "..."
                        lines.append(f"  {key}: {str_value}")
                if len(events) > 10:
                    lines.append(f"\n... and {len(events) - 10} more results")
            else:
                lines.append("No events found matching the query.")
                lines.append("\nTips:")
                lines.append("- Try longer time ranges like '7d' or '30d'")
                lines.append("- Use broader queries like '*' to see available data")

            return format_text_response(
                "\n".join(lines),
                tool_name="ngsiem_query",
                raw=True,
                structured_data=result,
                metadata={"query": result.get("query"), "time_range": start_time},
            )
        else:
            error_text = (
                f"NGSIEM Query Failed:\nError: {result.get('error', 'Unknown error')}\n"
                f"\nPlease ensure:\n1. Query syntax is valid CQL\n"
                f"2. Time range is reasonable\n3. Try simpler queries first"
            )
            return format_text_response(error_text, raw=True)

    # ------------------------------------------------------------------
    # Public query execution (called by ngsiem_query and the render module)
    # ------------------------------------------------------------------

    def execute_query(
        self,
        query: str,
        start_time: str = "1d",
        max_results: int = 100,
        fields: str | None = None,
    ) -> dict:
        """Execute a complete NGSIEM query. Returns result dict."""
        # Field projection: append | select([...]) to query if fields specified
        field_projection = None
        field_projection_skipped = None
        if fields:
            field_list = [f.strip() for f in fields.split(",") if f.strip()]
            if field_list:
                # Check if query already has select() or table()
                if re.search(r"\|\s*(?:select|table)\s*\(", query):
                    field_projection_skipped = "query already contains select() or table()"
                else:
                    field_projection = field_list
                    select_clause = ", ".join(field_list)
                    query = f"{query} | select([{select_clause}])"

        # Add MCP identifier comment for audit/tracking
        timestamped_query = f"// MCP Query - {datetime.now().isoformat()}\n{query}"

        # Start search
        try:
            falcon = self._service(NGSIEM)
            response = falcon.start_search(
                repository=self.repository,
                query_string=timestamped_query,
                start=start_time,
                is_live=False,
            )

            if response["status_code"] != 200:
                error_details = []

                resources = response.get("resources", {})
                if "errors" in resources:
                    for error in resources["errors"]:
                        if isinstance(error, dict) and "message" in error:
                            error_details.append(error["message"])
                        else:
                            error_details.append(str(error))

                body = response.get("body", {})
                if "errors" in body:
                    for error in body["errors"]:
                        if isinstance(error, dict) and "message" in error:
                            error_details.append(error["message"])
                        else:
                            error_details.append(str(error))

                if not error_details:
                    error_details = [f"HTTP {response['status_code']} error"]

                error_msg = "; ".join(error_details)
                return {
                    "success": False,
                    "error": f"Failed to start search (HTTP {response['status_code']}): {error_msg}",
                }

            search_id = response.get("resources", {}).get("id")

        except Exception as e:
            return {"success": False, "error": f"Search start error: {str(e)}"}

        # Wait for completion
        try:
            start = time.time()
            timeout = 120  # 2 minute timeout

            while time.time() - start < timeout:
                status_response = falcon.get_search_status(
                    repository=self.repository,
                    search_id=search_id,
                )

                if status_response["status_code"] != 200:
                    error_msg = f"HTTP {status_response['status_code']}"
                    body = status_response.get("body", {})
                    if "errors" in body:
                        error_msg += f": {body['errors']}"
                    return {"success": False, "error": f"Status check failed: {error_msg}"}

                body = status_response.get("body", {})
                done = body.get("done", False)
                cancelled = body.get("cancelled", False)
                state = body.get("state", "unknown")

                if done or cancelled:
                    events = body.get("events", [])
                    events_matched = len(events)
                    events_processed = events_matched

                    if len(events) > max_results:
                        events = events[:max_results]
                        truncated = True
                    else:
                        truncated = False

                    return {
                        "success": True,
                        "events_processed": events_processed,
                        "events_matched": events_matched,
                        "events_returned": len(events),
                        "results_truncated": truncated,
                        "query": query,  # Original query without MCP comment
                        "time_range": start_time,
                        "events": events,
                        "field_projection": field_projection,
                        "field_projection_skipped": field_projection_skipped,
                    }

                if state == "error":
                    messages = body.get("messages", [])
                    return {"success": False, "error": f"Search error: {messages}"}

                time.sleep(2)

            # Timeout
            falcon.stop_search(repository=self.repository, id=search_id)
            return {"success": False, "error": f"Query timed out after {timeout} seconds"}

        except Exception as e:
            try:
                falcon.stop_search(repository=self.repository, id=search_id)
            except Exception:
                pass
            return {"success": False, "error": f"Query execution error: {str(e)}"}

    # ------------------------------------------------------------------
    # Shared unwrap helper (FR 07 read-expansion tools)
    # ------------------------------------------------------------------

    _COMPACT_LIST_FIELDS = ("id", "name", "last_modified", "state", "status")

    @classmethod
    def _project_compact(cls, records: list) -> list:
        """Return records filtered to the compact projection field set."""
        projected = []
        for rec in records:
            if not isinstance(rec, dict):
                projected.append(rec)
                continue
            projected.append({k: rec[k] for k in cls._COMPACT_LIST_FIELDS if k in rec})
        return projected

    def _format_list(
        self,
        result: dict,
        *,
        tool_name: str,
        label: str,
        filter_: str | None,
        limit: int,
        detail: bool,
        meta_extra: dict | None = None,
    ) -> str:
        """Shared formatter for the compact/detail list tools."""
        if not result.get("success"):
            return format_text_response(
                f"{tool_name} failed:\n{result.get('error', 'Unknown error')}",
                tool_name=tool_name,
                raw=True,
            )
        records = result["resources"] or []
        if not detail:
            records = self._project_compact(records)
        header = [
            f"{label} ({len(records)} result{'s' if len(records) != 1 else ''}):",
        ]
        if filter_:
            header.append(f"Filter: {filter_}")
        header.append(f"Limit: {limit}")
        header.append(f"Detail: {detail}")
        header.append("")
        if not records:
            header.append(f"No {label.lower()} found.")
            return format_text_response(
                "\n".join(header),
                tool_name=tool_name,
                raw=True,
                structured_data={"records": records, **(meta_extra or {})},
                metadata={"filter": filter_, "limit": limit},
            )
        for i, rec in enumerate(records[:50]):
            header.append(f"#{i + 1}:")
            if isinstance(rec, dict):
                for k, v in rec.items():
                    sv = str(v)
                    if len(sv) > 300:
                        sv = sv[:300] + "..."
                    header.append(f"  {k}: {sv}")
            else:
                header.append(f"  {rec}")
            header.append("")
        if len(records) > 50:
            header.append(f"... and {len(records) - 50} more records")
        return format_text_response(
            "\n".join(header),
            tool_name=tool_name,
            raw=True,
            structured_data={"records": records, **(meta_extra or {})},
            metadata={"filter": filter_, "limit": limit},
        )

    def _format_single(
        self,
        result: dict,
        *,
        tool_name: str,
        label: str,
        identifier: str,
    ) -> str:
        """Shared formatter for the get_* single-record tools."""
        if not result.get("success"):
            return format_text_response(
                f"{tool_name} failed:\n{result.get('error', 'Unknown error')}",
                tool_name=tool_name,
                raw=True,
            )
        resources = result["resources"]
        record = resources[0] if isinstance(resources, list) and resources else resources
        lines = [f"{label} ({identifier}):", ""]
        if isinstance(record, dict):
            for k, v in record.items():
                sv = str(v)
                if len(sv) > 2000:
                    sv = sv[:2000] + "..."
                lines.append(f"{k}: {sv}")
        else:
            lines.append(str(record))
        return format_text_response(
            "\n".join(lines),
            tool_name=tool_name,
            raw=True,
            structured_data={"record": record},
            metadata={"id": identifier},
        )

    def _call_and_unwrap(self, method, operation: str, **kwargs) -> dict:
        """Call a falconpy method and normalize the response shape.

        Returns ``{"success": True, "resources": <list|dict>, "body": <dict>}``
        on HTTP 200, or ``{"success": False, "error": <str>}`` on any
        non-2xx or thrown exception. Errors are extracted from both the
        top-level ``resources.errors`` and ``body.errors`` shapes that
        falconpy may use, matching the pattern in ``execute_query``.
        """
        try:
            response = method(**kwargs)
        except Exception as exc:
            return {"success": False, "error": f"{operation} call error: {exc}"}

        status = response.get("status_code", 0)
        body = response.get("body", {}) or {}

        if 200 <= status < 300:
            return {
                "success": True,
                "resources": body.get("resources", []),
                "body": body,
            }

        error_details: list[str] = []
        resources = response.get("resources", {}) or {}
        if isinstance(resources, dict) and "errors" in resources:
            for err in resources["errors"]:
                if isinstance(err, dict) and "message" in err:
                    error_details.append(err["message"])
                else:
                    error_details.append(str(err))
        if "errors" in body:
            for err in body["errors"]:
                if isinstance(err, dict) and "message" in err:
                    error_details.append(err["message"])
                else:
                    error_details.append(str(err))
        if not error_details:
            error_details = [f"HTTP {status} error"]

        return {
            "success": False,
            "error": f"{operation} failed (HTTP {status}): {'; '.join(error_details)}",
        }

    # ------------------------------------------------------------------
    # FR 07 saved-query tools
    # ------------------------------------------------------------------

    async def ngsiem_list_saved_queries(
        self,
        filter: Annotated[Optional[str], "FQL filter (optional)"] = None,
        limit: Annotated[int, "Max records (default 100, cap 1000)"] = 100,
        detail: Annotated[bool, "Return full records instead of compact projection"] = False,
    ) -> str:
        """Enumerate saved NGSIEM searches (enrichment functions, etc.)."""
        limit = min(max(limit, 1), 1000)
        falcon = self._service(NGSIEM)
        kwargs: dict = {"limit": limit}
        if filter:
            kwargs["filter"] = filter
        result = self._call_and_unwrap(falcon.list_saved_queries, "list_saved_queries", **kwargs)
        return self._format_list(
            result,
            tool_name="ngsiem_list_saved_queries",
            label="Saved Queries",
            filter_=filter,
            limit=limit,
            detail=detail,
        )

    async def ngsiem_get_saved_query_template(
        self,
        id: Annotated[str, "Saved query ID"],
    ) -> str:
        """Fetch the live body + metadata of one saved NGSIEM search."""
        falcon = self._service(NGSIEM)
        result = self._call_and_unwrap(falcon.get_saved_query_template, "get_saved_query_template", ids=id)
        return self._format_single(
            result,
            tool_name="ngsiem_get_saved_query_template",
            label="Saved Query Template",
            identifier=id,
        )

    async def ngsiem_list_lookup_files(
        self,
        filter: Annotated[Optional[str], "FQL filter (optional)"] = None,
        limit: Annotated[int, "Max records (default 100, cap 1000)"] = 100,
        detail: Annotated[bool, "Return full records instead of compact projection"] = False,
    ) -> str:
        """Enumerate NGSIEM lookup files."""
        limit = min(max(limit, 1), 1000)
        falcon = self._service(NGSIEM)
        kwargs: dict = {"limit": limit}
        if filter:
            kwargs["filter"] = filter
        result = self._call_and_unwrap(falcon.list_lookup_files, "list_lookup_files", **kwargs)
        return self._format_list(
            result,
            tool_name="ngsiem_list_lookup_files",
            label="Lookup Files",
            filter_=filter,
            limit=limit,
            detail=detail,
        )

    async def ngsiem_get_lookup_file(
        self,
        id: Annotated[str, "Lookup file ID"],
        include_content: Annotated[bool, "Return file content, not just metadata"] = False,
    ) -> str:
        """Fetch a lookup file — metadata only unless include_content=True."""
        falcon = self._service(NGSIEM)
        result = self._call_and_unwrap(falcon.get_lookup_file, "get_lookup_file", ids=id)
        if result.get("success") and not include_content:
            # Strip content from each record client-side; metadata fields retained.
            stripped: list = []
            for rec in result["resources"] or []:
                if isinstance(rec, dict):
                    stripped.append({k: v for k, v in rec.items() if k != "content"})
                else:
                    stripped.append(rec)
            result["resources"] = stripped
        return self._format_single(
            result,
            tool_name="ngsiem_get_lookup_file",
            label="Lookup File",
            identifier=id,
        )

    async def ngsiem_list_dashboards(
        self,
        filter: Annotated[Optional[str], "FQL filter (optional)"] = None,
        limit: Annotated[int, "Max records (default 100, cap 1000)"] = 100,
        detail: Annotated[bool, "Return full records instead of compact projection"] = False,
    ) -> str:
        """Enumerate NGSIEM dashboards."""
        limit = min(max(limit, 1), 1000)
        falcon = self._service(NGSIEM)
        kwargs: dict = {"limit": limit}
        if filter:
            kwargs["filter"] = filter
        result = self._call_and_unwrap(falcon.list_dashboards, "list_dashboards", **kwargs)
        return self._format_list(
            result,
            tool_name="ngsiem_list_dashboards",
            label="Dashboards",
            filter_=filter,
            limit=limit,
            detail=detail,
        )

    async def ngsiem_list_parsers(
        self,
        filter: Annotated[Optional[str], "FQL filter (optional)"] = None,
        limit: Annotated[int, "Max records (default 100, cap 1000)"] = 100,
        detail: Annotated[bool, "Return full records instead of compact projection"] = False,
    ) -> str:
        """Enumerate NGSIEM parsers."""
        limit = min(max(limit, 1), 1000)
        falcon = self._service(NGSIEM)
        kwargs: dict = {"limit": limit}
        if filter:
            kwargs["filter"] = filter
        result = self._call_and_unwrap(falcon.list_parsers, "list_parsers", **kwargs)
        return self._format_list(
            result,
            tool_name="ngsiem_list_parsers",
            label="Parsers",
            filter_=filter,
            limit=limit,
            detail=detail,
        )

    async def ngsiem_get_parser(
        self,
        id: Annotated[str, "Parser ID"],
    ) -> str:
        """Fetch a parser's live configuration + script."""
        falcon = self._service(NGSIEM)
        result = self._call_and_unwrap(falcon.get_parser, "get_parser", ids=id)
        return self._format_single(
            result,
            tool_name="ngsiem_get_parser",
            label="Parser",
            identifier=id,
        )

    async def ngsiem_list_data_connections(
        self,
        filter: Annotated[Optional[str], "FQL filter (optional)"] = None,
        limit: Annotated[int, "Max records (default 100, cap 1000)"] = 100,
        detail: Annotated[bool, "Return full records instead of compact projection"] = False,
    ) -> str:
        """Enumerate NGSIEM data connections (ingestion pipelines)."""
        limit = min(max(limit, 1), 1000)
        falcon = self._service(NGSIEM)
        kwargs: dict = {"limit": limit}
        if filter:
            kwargs["filter"] = filter
        result = self._call_and_unwrap(falcon.list_data_connections, "list_data_connections", **kwargs)
        return self._format_list(
            result,
            tool_name="ngsiem_list_data_connections",
            label="Data Connections",
            filter_=filter,
            limit=limit,
            detail=detail,
        )

    async def ngsiem_get_data_connection(
        self,
        id: Annotated[str, "Data connection ID"],
    ) -> str:
        """Fetch a single data connection's state + configuration."""
        falcon = self._service(NGSIEM)
        result = self._call_and_unwrap(falcon.get_connection_by_id, "get_connection_by_id", ids=id)
        return self._format_single(
            result,
            tool_name="ngsiem_get_data_connection",
            label="Data Connection",
            identifier=id,
        )

    async def ngsiem_get_provisioning_status(self) -> str:
        """Fetch overall NGSIEM ingestion provisioning / health status."""
        falcon = self._service(NGSIEM)
        result = self._call_and_unwrap(falcon.get_provisioning_status, "get_provisioning_status")
        return self._format_single(
            result,
            tool_name="ngsiem_get_provisioning_status",
            label="Provisioning Status",
            identifier="(tenant)",
        )

    async def ngsiem_list_data_connectors(self) -> str:
        """Enumerate available NGSIEM data connector types."""
        falcon = self._service(NGSIEM)
        result = self._call_and_unwrap(falcon.list_data_connectors, "list_data_connectors")
        return self._format_list(
            result,
            tool_name="ngsiem_list_data_connectors",
            label="Data Connectors",
            filter_=None,
            limit=1000,
            detail=True,  # connector-type records are small; return full
        )

    async def ngsiem_list_connector_configs(
        self,
        filter: Annotated[Optional[str], "FQL filter (optional)"] = None,
        limit: Annotated[int, "Max records (default 100, cap 1000)"] = 100,
        detail: Annotated[bool, "Return full records instead of compact projection"] = False,
    ) -> str:
        """Enumerate connector configuration instances."""
        limit = min(max(limit, 1), 1000)
        falcon = self._service(NGSIEM)
        kwargs: dict = {"limit": limit}
        if filter:
            kwargs["filter"] = filter
        result = self._call_and_unwrap(falcon.list_connector_configs, "list_connector_configs", **kwargs)
        return self._format_list(
            result,
            tool_name="ngsiem_list_connector_configs",
            label="Connector Configs",
            filter_=filter,
            limit=limit,
            detail=detail,
        )
