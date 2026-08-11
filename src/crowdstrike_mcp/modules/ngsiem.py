"""
NGSIEM Module — CQL query execution + read-only introspection.

Tools:
  ngsiem_query                      — Execute CQL query against a selectable repository (default: search-all)
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

import os
import re
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Annotated, Optional

import requests
from falconpy import NGSIEM

from crowdstrike_mcp.modules.base import BaseModule
from crowdstrike_mcp.utils import format_text_response

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

# Search-job polling defaults. Overridable via env so a long hunt isn't cut short by the default ceiling.
DEFAULT_POLL_INTERVAL_SECONDS = 2
DEFAULT_TIMEOUT_SECONDS = 300

# Inline result rows rendered by ngsiem_query. Raised from the old hard cap of 10;
# overridable per call (display_rows) or via env. The full result set is always
# retrievable via get_stored_response, and oversized inline text is still stored
# and paged, so a higher default is safe.
DEFAULT_INLINE_ROWS = 50
MAX_INLINE_ROWS = 1000

# The NGSIEM content-management endpoints are scoped by a query param the API
# requires and falconpy does not default. Omitting it is an unconditional HTTP
# 400 ("missing search_domain query param" / "missing repository query param"),
# so every tool below failed on every call — including the no-argument form.
# The param is not optional in any meaningful sense; it just had no default.
DEFAULT_SEARCH_DOMAIN = "all"
SEARCH_DOMAINS = ("all", "falcon", "third-party", "dashboards", "parsers-repository")

# Parsers are scoped by `repository` rather than `search_domain`, and the API
# accepts exactly one value for it.
PARSERS_REPOSITORY = "parsers-repository"

_SEARCH_DOMAIN_HELP = f"Search domain to scope the request. One of: {', '.join(SEARCH_DOMAINS)}. Default '{DEFAULT_SEARCH_DOMAIN}' (everything)."

# A caller-supplied filter is already FQL if it looks like `field:...`.
_FQL_SHAPED = re.compile(r"^\s*[A-Za-z_][\w.]*\s*:")

# Lookup files are downloads, not records: the GET returns the file bytes. Cap
# what we render inline by default so a 80k-row CSV doesn't flood the context.
LOOKUP_PREVIEW_LINES = 10


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
            description=(
                "Execute an NGSIEM/CQL query against a selectable repository (default: search-all, "
                "spanning all CrowdStrike logs). Long field values (e.g. @rawstring) are truncated "
                "to ~200 chars inline; pass full=True to render them untruncated, or fetch the full "
                "value via get_stored_response — every non-empty result is stored under a resp_XXX "
                "ref, including single-event result sets."
            ),
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
            description=(
                "Enumerate NGSIEM lookup files (compact projection by default). Pass a bare "
                "name substring as filter — it is wrapped into the FQL the API requires."
            ),
        )
        self._add_tool(
            server,
            self.ngsiem_get_lookup_file,
            name="ngsiem_get_lookup_file",
            description=(
                "Download a lookup file by filename (e.g. 'cato-users.csv'). Returns size, line "
                "count and a short preview; pass include_content=True for the whole file. The full "
                "content is always retrievable via get_stored_response."
            ),
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
        time_range: Annotated[str, "Relative lookback window (e.g. '1h', '1d', '7d', '30d'). Ignored if start_time is given."] = "1d",
        start_time: Annotated[
            Optional[str],
            "Absolute window start: ISO-8601 (e.g. '2026-05-15T13:00:00Z') or epoch seconds/millis. Overrides time_range.",
        ] = None,
        end_time: Annotated[
            Optional[str],
            "Absolute window end: ISO-8601 or epoch seconds/millis. Defaults to now when start_time is set.",
        ] = None,
        max_results: Annotated[int, "Maximum results to return (default: 100, max: 1000)"] = 100,
        fields: Annotated[Optional[str], "Comma-separated field names for server-side projection via select()"] = None,
        full: Annotated[
            bool,
            "Render long field values (e.g. @rawstring) in full inline instead of truncating to ~200 chars. "
            "Results are always retrievable in full via get_stored_response regardless of this flag.",
        ] = False,
        display_rows: Annotated[
            Optional[int],
            "How many result rows to render inline (default 50, env FALCON_MCP_NGSIEM_DISPLAY_ROWS). "
            "The full result set is always retrievable via get_stored_response.",
        ] = None,
        repository: Annotated[
            str,
            "Repository to search. Options: search-all (default, all event data), investigate_view "
            "(endpoint events), third-party (third-party source events), falcon_for_it_view (Falcon for IT "
            "data), forensics_view (Falcon Forensics triage data).",
        ] = "search-all",
    ) -> str:
        """Execute a CQL query against an NGSIEM repository (default: search-all)."""
        max_results = min(max(max_results, 1), 1000)

        result = self._execute_query(
            query,
            time_range=time_range,
            start_time=start_time,
            end_time=end_time,
            max_results=max_results,
            fields=fields,
            repository=repository,
        )

        if result.get("success"):
            events = result.get("events", [])
            lines = [
                "NGSIEM Query Results (All Logs):",
                f"Query: {result['query']}",
                f"Time Range: {result['time_range']}",
                f"Repository: {repository}",
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
                n_show = self._resolve_display_rows(display_rows)
                lines.append("Results:")
                for i, event in enumerate(events[:n_show]):
                    lines.append(f"\n#{i + 1}:")
                    for key, value in event.items():
                        str_value = str(value)
                        if not full and len(str_value) > 200:
                            str_value = str_value[:200] + "..."
                        lines.append(f"  {key}: {str_value}")
                if len(events) > n_show:
                    lines.append(f"\n... and {len(events) - n_show} more results (retrieve all via get_stored_response)")
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
                metadata={"query": result.get("query"), "time_range": result.get("time_range")},
                # Always keep a retrievable ref when there are events, so a small
                # result set with a long @rawstring is recoverable in full (#40).
                force_store=bool(events),
            )
        else:
            error = result.get("error", "Unknown error")
            if result.get("syntax_diagnostic"):
                # LogScale told us the exact token and the exact reason. The
                # generic checklist below competes with that answer and points
                # at the wrong causes (connectivity, time range), so drop it.
                # Emit raw — the caret markers are aligned to the source columns
                # and are destroyed by any reflowing.
                error_text = f"NGSIEM Query Failed:\n{error}"
            else:
                error_text = (
                    f"NGSIEM Query Failed:\nError: {error}\n"
                    f"\nPlease ensure:\n1. Query syntax is valid CQL\n"
                    f"2. Time range is reasonable\n3. Try simpler queries first"
                )
            return format_text_response(error_text, tool_name="ngsiem_query", raw=True)

    # ------------------------------------------------------------------
    # Internal query execution (also called by AlertsModule)
    # ------------------------------------------------------------------

    @staticmethod
    def _to_epoch_ms(value: str) -> str:
        """Convert an absolute time to an epoch-millisecond string.

        The NGSIEM/LogScale start_search API rejects ISO-8601 timestamps
        with HTTP 400 "No content was received for this request"; it accepts
        only relative durations ('1d') or epoch milliseconds. Absolute inputs
        (ISO-8601, epoch seconds, or epoch millis) must be normalized to ms.
        """
        s = str(value).strip()
        if s.isdigit():
            n = int(s)
            # Epoch-seconds (~1.7e9 today) vs epoch-millis (~1.7e12).
            return str(n * 1000 if n < 10**12 else n)
        # ISO-8601; tolerate a trailing 'Z' which fromisoformat rejects < 3.11.
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return str(int(dt.timestamp() * 1000))

    @staticmethod
    def _resolve_display_rows(display_rows: int | None) -> int:
        """Resolve the inline row cap: explicit arg > env default > module default.

        Clamped to [1, MAX_INLINE_ROWS]. Invalid env values fall back to the default.
        """
        if display_rows is None:
            try:
                display_rows = int(os.environ.get("FALCON_MCP_NGSIEM_DISPLAY_ROWS", str(DEFAULT_INLINE_ROWS)))
            except (ValueError, TypeError):
                display_rows = DEFAULT_INLINE_ROWS
        return min(max(display_rows, 1), MAX_INLINE_ROWS)

    def _raw_start_search_error(self, repo: str, query: str, search_kwargs: dict) -> str | None:
        """Recover LogScale's text/plain syntax diagnostic that falconpy discards.

        falconpy parses every response body as JSON. A CQL syntax error is
        returned as ``text/plain``, so ``json.loads`` raises and falconpy's
        handler — reading the exception as "no content" rather than "not JSON" —
        substitutes its own "No content was received for this request." string
        without ever touching ``response.text``. The real diagnostic (named
        error codes, per-token carets) is lost before any caller sees it.

        This re-issues the same POST with ``requests`` so the raw body survives.
        Best-effort by design: any failure here returns None and the caller falls
        back to the parsed-envelope path. It must never raise, because it runs
        while we are already reporting an error.

        ``query`` is deliberately the caller's own query, NOT the timestamped
        copy sent on the primary path: LogScale reports the offending line
        number, and the injected ``// MCP Query`` audit comment shifts every
        line by one. Sending the plain query makes the reported line numbers
        match what the caller actually wrote.

        Returns the diagnostic text, or None if nothing was recoverable.
        """
        try:
            auth = self._get_auth()
            base_url = (auth.base_url or "").rstrip("/")
            token = auth.token_value
            if not base_url or not token:
                return None

            payload = {
                "queryString": query,
                "start": search_kwargs.get("start"),
                "isLive": False,
            }
            if search_kwargs.get("end") is not None:
                payload["end"] = search_kwargs["end"]

            resp = requests.post(
                f"{base_url}/humio/api/v1/repositories/{repo}/queryjobs",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json=payload,
                timeout=30,
            )
        except Exception:  # noqa: BLE001 — diagnostics must never mask the verdict
            return None

        if resp.status_code == 200:
            # Raced a transient failure: the query parses after all. We have just
            # created a real query job, so stop it rather than orphaning it —
            # the primary path cleans up after itself and this must too.
            try:
                job_id = (resp.json() or {}).get("id")
            except ValueError:
                job_id = None
            if job_id:
                try:
                    self._service(NGSIEM).stop_search(repository=repo, id=job_id)
                except Exception:  # noqa: BLE001
                    self._log(f"Failed to stop raced query job {job_id} in {repo}")
            return None

        detail = (resp.text or "").strip()
        return detail or None

    def _execute_query(
        self,
        query: str,
        time_range: str = "1d",
        start_time: str | None = None,
        end_time: str | None = None,
        max_results: int = 100,
        fields: str | None = None,
        repository: str | None = None,
    ) -> dict:
        """Execute a complete NGSIEM query. Returns result dict.

        When ``start_time`` is supplied an absolute window is used (converted
        to epoch-ms); otherwise the relative ``time_range`` string is sent
        through unchanged (the API accepts '1d', '7d', ...).

        ``repository`` selects the NGSIEM repository; when omitted the module
        default (``self.repository``) is used so existing internal callers are
        unaffected.
        """
        repo = repository or self.repository
        # Resolve the time window into API params + a human-readable label.
        try:
            if start_time:
                api_start: str = self._to_epoch_ms(start_time)
                api_end: str | None = self._to_epoch_ms(end_time) if end_time else None
                display_range = f"{start_time} → {end_time or 'now'}"
            else:
                api_start = time_range
                api_end = None
                display_range = time_range
        except (ValueError, TypeError) as e:
            return {
                "success": False,
                "error": f"Invalid time value (use ISO-8601, epoch, or a relative range like '1d'): {e}",
            }
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
            search_kwargs = {
                "repository": repo,
                "query_string": timestamped_query,
                "start": api_start,
                "is_live": False,
            }
            if api_end is not None:
                search_kwargs["end"] = api_end
            response = falcon.start_search(**search_kwargs)

            if response["status_code"] != 200:
                status = response["status_code"]

                # A CQL syntax error comes back as HTTP 400 with a text/plain
                # body carrying LogScale's full diagnostic — named error codes
                # and caret markers under the offending column, the same linting
                # the Falcon console shows. falconpy never surfaces it: its
                # JSONDecodeError handler assumes a non-JSON body means an EMPTY
                # body and raises NoContentWarning without reading response.text
                # (_util/_functions.py). The caller then receives a fabricated
                # {"errors": [{"message": "No content was received for this
                # request."}]}, which is both wrong and actively misleading.
                # Re-issue the request raw to recover what was thrown away.
                # Scoped to 400 so auth/scope/transport failures (which DO return
                # parseable JSON) don't pay for a duplicate round trip.
                if status == 400:
                    diagnostic = self._raw_start_search_error(repo, query, search_kwargs)
                    if diagnostic:
                        # Self-describing: _execute_query is also called by
                        # AlertsModule, which only ever reads ["error"].
                        return {
                            "success": False,
                            "error": f"CQL syntax error (HTTP {status}):\n{diagnostic}",
                            "syntax_diagnostic": True,
                        }

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
                    error_details = [f"HTTP {status} error"]

                error_msg = "; ".join(error_details)
                return {
                    "success": False,
                    "error": f"Failed to start search (HTTP {status}): {error_msg}",
                }

            search_id = response.get("resources", {}).get("id")

        except Exception as e:
            return {"success": False, "error": f"Search start error: {str(e)}"}

        # Wait for completion. Poll/timeout are env-tunable so long hunts
        # aren't cut short by the default ceiling.
        try:
            start = time.time()
            timeout = int(os.environ.get("FALCON_MCP_NGSIEM_TIMEOUT", str(DEFAULT_TIMEOUT_SECONDS)))
            poll_interval = int(os.environ.get("FALCON_MCP_NGSIEM_POLL_INTERVAL", str(DEFAULT_POLL_INTERVAL_SECONDS)))

            while time.time() - start < timeout:
                status_response = falcon.get_search_status(
                    repository=repo,
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
                        "time_range": display_range,
                        "events": events,
                        "field_projection": field_projection,
                        "field_projection_skipped": field_projection_skipped,
                    }

                if state == "error":
                    messages = body.get("messages", [])
                    return {"success": False, "error": f"Search error: {messages}"}

                time.sleep(poll_interval)

            # Timeout
            falcon.stop_search(repository=repo, id=search_id)
            return {"success": False, "error": f"Query timed out after {timeout} seconds"}

        except Exception as e:
            try:
                falcon.stop_search(repository=repo, id=search_id)
            except Exception:
                pass
            return {"success": False, "error": f"Query execution error: {str(e)}"}

    # ------------------------------------------------------------------
    # Shared unwrap helper (FR 07 read-expansion tools)
    # ------------------------------------------------------------------

    @staticmethod
    def _as_name_fql(filter_: str | None) -> str | None:
        """Normalize a caller's filter into the FQL these endpoints demand.

        The NGSIEM content endpoints only accept ``name:~'value'`` and reject
        anything else with "invalid fql syntax". A bare substring is the natural
        thing to pass — and passing it used to produce a confusing dual error
        alongside the missing-scope one — so wrap it here instead of making every
        caller know the shape. An already-FQL-shaped filter is passed through
        untouched.
        """
        if not filter_:
            return None
        cleaned = filter_.strip()
        if not cleaned:
            return None
        if _FQL_SHAPED.match(cleaned):
            return cleaned
        # Single quotes terminate the FQL literal; drop them rather than
        # emitting a filter the API will reject.
        return f"name:~'{cleaned.replace(chr(39), '')}'"

    _COMPACT_LIST_FIELDS = ("id", "name", "last_modified", "state", "status")

    @classmethod
    def _project_compact(cls, records: list) -> list:
        """Return records filtered to the compact projection field set.

        Key matching is case-INSENSITIVE. The parsers endpoint returns ``Name``
        and ``ID`` where every other NGSIEM endpoint returns ``name`` and ``id``,
        so a case-sensitive match projected every parser to ``{}`` — the tool
        rendered "2 results" followed by two blank entries. That was invisible
        until v5.9.0 unbroke the call itself, and invisible in testing because
        detail=True skips this projection entirely.

        A record that matches nothing falls through whole rather than rendering
        blank: showing an unexpected shape beats silently showing nothing. The
        caller-facing render caps at 50 records and truncates values at 300
        chars, so the fallback stays bounded.
        """
        projected = []
        for rec in records:
            if not isinstance(rec, dict):
                projected.append(rec)
                continue
            # Canonical field order, original key spelling.
            by_lower = {k.lower(): k for k in rec}
            compact = {by_lower[f]: rec[by_lower[f]] for f in cls._COMPACT_LIST_FIELDS if f in by_lower}
            projected.append(compact or rec)
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
        falconpy may use, matching the pattern in ``_execute_query``.
        """
        try:
            response = method(**kwargs)
        except Exception as exc:
            return {"success": False, "error": f"{operation} call error: {exc}"}

        # Download endpoints (get_lookup_file) return the file itself, not an
        # envelope — falconpy hands back raw bytes with no status_code to read.
        # Calling .get() on that is an AttributeError outside the try above, so
        # it would surface as a server crash rather than a result.
        if isinstance(response, (bytes, bytearray)):
            return {"success": True, "content": bytes(response), "resources": [], "body": {}}

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
        filter: Annotated[Optional[str], "Name substring, or FQL (name:~'value'). A bare substring is wrapped for you."] = None,
        limit: Annotated[int, "Max records (default 100, cap 1000)"] = 100,
        detail: Annotated[bool, "Return full records instead of compact projection"] = False,
        search_domain: Annotated[str, _SEARCH_DOMAIN_HELP] = DEFAULT_SEARCH_DOMAIN,
    ) -> str:
        """Enumerate saved NGSIEM searches (enrichment functions, etc.)."""
        limit = min(max(limit, 1), 1000)
        falcon = self._service(NGSIEM)
        fql = self._as_name_fql(filter)
        kwargs: dict = {"limit": limit, "search_domain": search_domain}
        if fql:
            kwargs["filter"] = fql
        result = self._call_and_unwrap(falcon.list_saved_queries, "list_saved_queries", **kwargs)
        return self._format_list(
            result,
            tool_name="ngsiem_list_saved_queries",
            label="Saved Queries",
            filter_=fql,
            limit=limit,
            detail=detail,
            meta_extra={"search_domain": search_domain},
        )

    async def ngsiem_get_saved_query_template(
        self,
        id: Annotated[str, "Saved query ID (from ngsiem_list_saved_queries)"],
        search_domain: Annotated[str, _SEARCH_DOMAIN_HELP] = DEFAULT_SEARCH_DOMAIN,
    ) -> str:
        """Fetch the live body + metadata of one saved NGSIEM search."""
        falcon = self._service(NGSIEM)
        result = self._call_and_unwrap(
            falcon.get_saved_query_template,
            "get_saved_query_template",
            ids=id,
            search_domain=search_domain,
        )
        return self._format_single(
            result,
            tool_name="ngsiem_get_saved_query_template",
            label="Saved Query Template",
            identifier=id,
        )

    async def ngsiem_list_lookup_files(
        self,
        filter: Annotated[Optional[str], "Name substring, or FQL (name:~'value'). A bare substring is wrapped for you."] = None,
        limit: Annotated[int, "Max records (default 100, cap 1000)"] = 100,
        detail: Annotated[bool, "Return full records instead of compact projection"] = False,
        search_domain: Annotated[str, _SEARCH_DOMAIN_HELP] = DEFAULT_SEARCH_DOMAIN,
    ) -> str:
        """Enumerate NGSIEM lookup files."""
        limit = min(max(limit, 1), 1000)
        falcon = self._service(NGSIEM)
        fql = self._as_name_fql(filter)
        kwargs: dict = {"limit": limit, "search_domain": search_domain}
        if fql:
            kwargs["filter"] = fql
        result = self._call_and_unwrap(falcon.list_lookup_files, "list_lookup_files", **kwargs)
        return self._format_list(
            result,
            tool_name="ngsiem_list_lookup_files",
            label="Lookup Files",
            filter_=fql,
            limit=limit,
            detail=detail,
            meta_extra={"search_domain": search_domain},
        )

    async def ngsiem_get_lookup_file(
        self,
        filename: Annotated[str, "Lookup file name including extension, e.g. 'cato-users.csv' (from ngsiem_list_lookup_files)"],
        include_content: Annotated[bool, "Render the whole file inline. Default False returns size + header + a short preview."] = False,
        search_domain: Annotated[str, _SEARCH_DOMAIN_HELP] = DEFAULT_SEARCH_DOMAIN,
    ) -> str:
        """Fetch a lookup file — preview by default, whole file with include_content=True.

        This endpoint is a *download*: it returns the file bytes, not a record
        with a strippable "content" field. The previous implementation both
        addressed it by the wrong parameter (``ids`` where the API wants
        ``filename``) and assumed a metadata shape the API never returns.
        """
        falcon = self._service(NGSIEM)
        result = self._call_and_unwrap(
            falcon.get_lookup_file,
            "get_lookup_file",
            filename=filename,
            search_domain=search_domain,
        )
        if not result.get("success"):
            return format_text_response(
                f"ngsiem_get_lookup_file failed:\n{result.get('error', 'Unknown error')}",
                tool_name="ngsiem_get_lookup_file",
                raw=True,
            )

        raw = result.get("content")
        if raw is None:
            # Defensive: an envelope rather than a download. Render it as-is
            # rather than claiming a zero-byte file.
            return self._format_single(
                result,
                tool_name="ngsiem_get_lookup_file",
                label="Lookup File",
                identifier=filename,
            )

        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()
        header = [
            f"Lookup File ({filename}):",
            f"Search domain: {search_domain}",
            f"Size: {len(raw):,} bytes",
            f"Lines: {len(lines):,}",
            "",
        ]
        truncated = False
        if include_content:
            body = lines
        else:
            body = lines[:LOOKUP_PREVIEW_LINES]
            truncated = len(lines) > LOOKUP_PREVIEW_LINES
            if truncated:
                body = [*body, f"... and {len(lines) - LOOKUP_PREVIEW_LINES:,} more lines (pass include_content=True for the whole file)"]
        return format_text_response(
            "\n".join([*header, *body]),
            tool_name="ngsiem_get_lookup_file",
            raw=True,
            # Nested under "records" deliberately: ResponseStore.select_records
            # finds nothing in a flat dict of scalars, so a bare
            # {"filename": ..., "content": ...} payload would mint a ref_id that
            # get_stored_response cannot read back — worse than no ref at all.
            structured_data={"records": [{"filename": filename, "search_domain": search_domain, "size_bytes": len(raw), "content": text}]},
            metadata={"filename": filename, "search_domain": search_domain},
            # Whenever we withhold lines, guarantee a ref: a small file that
            # still exceeds the preview would otherwise have no recovery path
            # short of re-calling with include_content=True.
            force_store=truncated,
        )

    async def ngsiem_list_dashboards(
        self,
        filter: Annotated[Optional[str], "Name substring, or FQL (name:~'value'). A bare substring is wrapped for you."] = None,
        limit: Annotated[int, "Max records (default 100, cap 1000)"] = 100,
        detail: Annotated[bool, "Return full records instead of compact projection"] = False,
        search_domain: Annotated[str, _SEARCH_DOMAIN_HELP] = DEFAULT_SEARCH_DOMAIN,
    ) -> str:
        """Enumerate NGSIEM dashboards."""
        limit = min(max(limit, 1), 1000)
        falcon = self._service(NGSIEM)
        fql = self._as_name_fql(filter)
        kwargs: dict = {"limit": limit, "search_domain": search_domain}
        if fql:
            kwargs["filter"] = fql
        result = self._call_and_unwrap(falcon.list_dashboards, "list_dashboards", **kwargs)
        return self._format_list(
            result,
            tool_name="ngsiem_list_dashboards",
            label="Dashboards",
            filter_=fql,
            limit=limit,
            detail=detail,
            meta_extra={"search_domain": search_domain},
        )

    async def ngsiem_list_parsers(
        self,
        filter: Annotated[Optional[str], "Name substring, or FQL (name:~'value'). A bare substring is wrapped for you."] = None,
        limit: Annotated[int, "Max records (default 100, cap 1000)"] = 100,
        detail: Annotated[bool, "Return full records instead of compact projection"] = False,
    ) -> str:
        """Enumerate NGSIEM parsers."""
        limit = min(max(limit, 1), 1000)
        falcon = self._service(NGSIEM)
        fql = self._as_name_fql(filter)
        # Parsers are scoped by `repository`, not `search_domain`, and the API
        # accepts exactly one value — so this is supplied rather than exposed.
        kwargs: dict = {"limit": limit, "repository": PARSERS_REPOSITORY}
        if fql:
            kwargs["filter"] = fql
        result = self._call_and_unwrap(falcon.list_parsers, "list_parsers", **kwargs)
        return self._format_list(
            result,
            tool_name="ngsiem_list_parsers",
            label="Parsers",
            filter_=fql,
            limit=limit,
            detail=detail,
            meta_extra={"repository": PARSERS_REPOSITORY},
        )

    async def ngsiem_get_parser(
        self,
        id: Annotated[str, "Parser ID, e.g. '018bfba2b38a3734bf35cbc1fe4fffef:2.0.1' (from ngsiem_list_parsers)"],
    ) -> str:
        """Fetch a parser's live configuration + script."""
        falcon = self._service(NGSIEM)
        result = self._call_and_unwrap(falcon.get_parser, "get_parser", ids=id, repository=PARSERS_REPOSITORY)
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
