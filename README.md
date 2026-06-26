# CrowdStrike Falcon MCP Server

A modular, multi-transport [Model Context Protocol](https://modelcontextprotocol.io/) server that connects AI assistants to the CrowdStrike Falcon platform. Query NG-SIEM logs, triage alerts, inspect endpoints, manage detection rules, and audit cloud security posture — all through natural language.

**v4.3** — Modular auto-discovery architecture with 77 tools across 14 modules.

---

## Architecture

```
              ┌────────────────────────────────────────────┐
              │                 MCP Client                 │
              │  (Claude Code · Claude Desktop · IDEs)     │
              └───────────────────────┬────────────────────┘
                                      │  stdio · sse · streamable-http
              ┌───────────────────────▼────────────────────┐
              │  server.py  —  FalconMCPServer (FastMCP)   │
              │  registry.py auto-discovers modules/       │
              └───────────────────────┬────────────────────┘
                                      │
   ┌──────────────────────────────────▼────────────────────────────────────┐
   │                      modules/  (14 modules · 77 tools)                │
   │                                                                       │
   │   Detection & triage:  ngsiem (14) · alerts (4) · correlation (7)     │
   │   Hosts & response:    hosts (3) · response (2) · rtr (7)             │
   │   Cloud security:      cloud_security (5) · cloud_registration (2)    │
   │   Identity & graph:    idp (1) · threat_graph (5)                     │
   │   Vulnerabilities:     spotlight (6)                                  │
   │   Case & hunting:      case_management (15) · cao_hunting (5)         │
   │   Infrastructure:      response_store (2)                             │
   └──────────────────────────────────┬────────────────────────────────────┘
                                      │
              ┌───────────────────────▼────────────────────┐
              │  client.py — FalconClient                  │
              │  Shared OAuth2 session · credential chain  │
              └───────────────────────┬────────────────────┘
                                      │
              ┌───────────────────────▼────────────────────┐
              │          CrowdStrike Falcon APIs           │
              └────────────────────────────────────────────┘
```

### File Layout

```
crowdstrike-mcp/
├── pyproject.toml                     # Package metadata, deps, entry point
├── src/crowdstrike_mcp/
│   ├── __init__.py                    # Package root, __version__
│   ├── server.py                      # FastMCP server, CLI, multi-transport
│   ├── client.py                      # FalconClient — shared OAuth2 + credential chain
│   ├── registry.py                    # Module auto-discovery via pkgutil
│   ├── utils.py                       # Response formatting, credential helpers
│   ├── response_store.py             # In-memory structured data store
│   │
│   ├── modules/                       # Each module = independent tool group
│   │   ├── base.py                    # BaseModule ABC
│   │   ├── ngsiem.py                  # CQL query + read-only introspection
│   │   ├── alerts.py                  # Alert retrieval, analysis, triage
│   │   ├── hosts.py                   # Device lookups + login/network history
│   │   ├── correlation.py             # Detection rule management
│   │   ├── cloud_registration.py      # Cloud account + CSPM policies
│   │   ├── cloud_security.py          # Risks, IOMs, assets, compliance, timeline
│   │   ├── case_management.py         # Case lifecycle management
│   │   ├── cao_hunting.py             # Intelligence queries + hunting guides
│   │   ├── spotlight.py               # Vulnerability evaluation + triage
│   │   ├── idp.py                     # Identity Protection (GraphQL triage)
│   │   ├── rtr.py                     # Real-Time Response (read-only subset)
│   │   ├── threat_graph.py            # Threat Graph pivots (vertices, edges)
│   │   ├── response.py                # Host containment actions
│   │   └── response_store.py          # Stored response retrieval
│   │
│   ├── resources/                     # MCP TextResources (syntax + reference docs)
│   │   ├── fql_guides.py              # FQL + CQL syntax references
│   │   └── threatgraph_reference.py   # Threat Graph edge-type reference
│   │
│   └── common/                        # Shared infrastructure
│       ├── errors.py                  # Scope-aware API error handling
│       ├── api_scopes.py              # Operation → required scope mapping
│       ├── session_auth.py            # Per-session Falcon auth middleware
│       ├── health.py                  # Health check endpoint
│       └── auth_middleware.py         # ASGI API key auth for HTTP transports
│
├── tests/                             # Unit tests
└── Dockerfile                         # Container build
```

---

## Quick Start

### 1. Installation

```bash
pip install crowdstrike-mcp
```

Or for development:

```bash
git clone https://github.com/willwebster5/crowdstrike-mcp.git
cd crowdstrike-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

### 2. Configure credentials

The server resolves credentials in priority order:

| Priority | Method | Details |
|----------|--------|---------|
| 1 | Environment variables | `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, `FALCON_BASE_URL` |
| 2 | Credential file | `~/.config/falcon/credentials.json` |

**Credential file format:**
```json
{
    "falcon_client_id": "your_client_id",
    "falcon_client_secret": "your_client_secret",
    "base_url": "US1"
}
```

Supported `base_url` values: `US1`, `US2`, `EU1`, `USGOV1`, `USGOV2`

### 3. Connect to an MCP client

**Claude Code** (`.mcp.json` at project root):
```json
{
  "mcpServers": {
    "crowdstrike": {
      "command": "crowdstrike-mcp",
      "args": ["--allow-writes"]
    }
  }
}
```

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "crowdstrike": {
      "command": "crowdstrike-mcp",
      "args": []
    }
  }
}
```

### Docker

```bash
docker build -t crowdstrike-mcp .
docker run -p 8000:8000 \
  -e FALCON_CLIENT_ID=... \
  -e FALCON_CLIENT_SECRET=... \
  crowdstrike-mcp
```

---

## Tools Reference

### NG-SIEM — `modules/ngsiem.py`

| Tool | Description |
|------|-------------|
| `ngsiem_query` | Execute CQL queries across all CrowdStrike logs (search-all repository) |
| `ngsiem_list_saved_queries` | Enumerate saved searches (enrichment functions, detections) |
| `ngsiem_get_saved_query_template` | Retrieve a saved search's live body and metadata |
| `ngsiem_list_lookup_files` | Enumerate lookup files |
| `ngsiem_get_lookup_file` | Get a lookup file's metadata (content opt-in) |
| `ngsiem_list_dashboards` | Enumerate dashboards |
| `ngsiem_list_parsers` | Enumerate parsers |
| `ngsiem_get_parser` | Get a parser's live config |
| `ngsiem_list_data_connections` | Enumerate data connections (ingestion) |
| `ngsiem_get_data_connection` | Get connection state for one ID |
| `ngsiem_get_provisioning_status` | Get provisioning / ingestion health status |
| `ngsiem_list_data_connectors` | Enumerate available data connectors |
| `ngsiem_list_connector_configs` | Enumerate connector configuration instances |

**`ngsiem_query` parameters:** `query` (CQL string), `start_time` (e.g. `1h`, `1d`, `7d`, `30d`), `max_results` (1-1000)

```
"Show me failed console logins in the last 24 hours"
→ ngsiem_query(query='#repo="cloudtrail" event.action="ConsoleLogin" #event.outcome!="success"', start_time="1d")
```

The `list_*` tools default to compact projections (id, name, last_modified); pass `detail=true` to get full records. `ngsiem_get_lookup_file` is metadata-only unless `include_content=true`. Every read tool is scoped to `ngsiem:read`; write operations remain with `talonctl`.

### Alerts — `modules/alerts.py`

| Tool | Description |
|------|-------------|
| `get_alerts` | Retrieve alerts across all detection types with filtering |
| `alert_analysis` | Deep-dive analysis with MITRE ATT&CK context and related events |
| `ngsiem_alert_analysis` | Alias for `alert_analysis` |
| `update_alert_status` | Change alert status, add comments and tags, assign/unassign a user (by user ID / email) |

**Detection types supported:** Endpoint (`ind`), NG-SIEM (`ngsiem`), Cloud Security (`fcs`), Identity (`ldt`), Third-party (`thirdparty`)

Each alert analysis routes to type-specific enrichment:
- **NG-SIEM alerts** — retrieves related events via indicator/detection two-step lookup
- **Endpoint alerts** — fetches EDR behaviors with process trees and MITRE techniques
- **Cloud/Identity/Third-party** — extracts metadata from alert payload

### Hosts — `modules/hosts.py`

| Tool | Description |
|------|-------------|
| `host_lookup` | Device details: OS, agent version, containment status, policies |
| `host_login_history` | Recent login events for a device |
| `host_network_history` | Network address history for a device |

### Correlation Rules — `modules/correlation.py`

| Tool | Description |
|------|-------------|
| `correlation_list_rules` | List detection/correlation rules with optional name search |
| `correlation_get_rule` | Full rule details: CQL filter, severity, MITRE mapping |
| `correlation_update_rule` | Enable/disable rules with audit comment (write) |
| `correlation_export_rule` | Export rule in structured format |
| `correlation_import_to_iac` | Export rules to IaC YAML for the detections repo (write) |
| `correlation_list_templates` | List correlation rule templates |
| `correlation_get_template` | Full template details |

### CAO Hunting — `modules/cao_hunting.py`

| Tool | Description |
|------|-------------|
| `cao_search_queries` | Search hunting queries by keyword or tag |
| `cao_get_queries` | Retrieve hunting query details by ID |
| `cao_search_guides` | Search hunting guides/playbooks |
| `cao_get_guides` | Retrieve hunting guide details by ID |
| `cao_aggregate` | Aggregate hunting query metrics |

### Case Management — `modules/case_management.py`

| Tool | Description |
|------|-------------|
| `case_query` | List/search cases with optional filters |
| `case_get` | Get full case details by ID |
| `case_create` | Create a new case (write) |
| `case_update` | Update case fields — status, assignee, description (write) |
| `case_add_alert_evidence` | Attach alerts as evidence to a case (write) |
| `case_add_event_evidence` | Attach NG-SIEM events as evidence to a case (write) |
| `case_add_tags` | Add tags to a case (write) |
| `case_delete_tags` | Remove tags from a case (write) |
| `case_upload_file` | Upload a file attachment to a case (write) |
| `case_get_fields` | List available case field definitions |
| `case_query_access_tags` | Query access control tags |
| `case_get_access_tags` | Get access tags for a case |
| `case_aggregate_access_tags` | Aggregate access tag statistics |
| `case_get_rtr_file_metadata` | Get RTR file metadata attached to a case |
| `case_get_rtr_recent_files` | List recent RTR files attached to a case |

### Containment — `modules/response.py`

| Tool | Description |
|------|-------------|
| `host_contain` | Network-isolate a host (write) |
| `host_lift_containment` | Lift network isolation from a host (write) |

### Real-Time Response (read-only subset) — `modules/rtr.py`

| Tool | Description |
|------|-------------|
| `rtr_init_session` | Open an RTR session on a host |
| `rtr_list_sessions` | List metadata for owned session IDs |
| `rtr_pulse_session` | Keep-alive ping (resets 10-min idle timeout) |
| `rtr_execute_command` | Run an allowlisted read-only active-responder command |
| `rtr_check_command_status` | Poll submitted command for stdout/stderr |
| `rtr_list_files` | List files pulled via `getfile` |
| `rtr_get_extracted_file_contents` | Download a pulled file (7z, password `infected`) |

All RTR tools register as read-tier. Safety is enforced by a hardcoded MCP-layer
command allowlist (`ls, ps, reg query, getfile, cat, env, ipconfig, netstat, cd,
pwd, filehash, eventlog view, zip, mount, users, history, memdump`) plus a
never-allowed deny list (`cp, mv, rm, put, runscript, kill, mkdir`). Extend via
env var `CROWDSTRIKE_MCP_RTR_EXTRA_ALLOWED` (comma-separated) — deny list always
wins. Every `rtr_execute_command` invocation is audited to
`~/.config/falcon/rtr_audit.log`.

### Response Store — `modules/response_store.py`

| Tool | Description |
|------|-------------|
| `get_stored_response` | Retrieve a stored large response by ID |
| `list_stored_responses` | List all responses currently in the store |

### Spotlight — `modules/spotlight.py`

| Tool | Description |
|------|-------------|
| `spotlight_supported_evaluations` | Assessment methods, OS/platform coverage, evaluation criteria |
| `spotlight_query_vulnerabilities` | Find vulnerability IDs by FQL filter (host, CVE, severity, status) |
| `spotlight_get_vulnerabilities` | Fetch full records: CVE metadata, severity, host, exploit status, apps |
| `spotlight_vulnerabilities_combined` | One-shot query+get — recommended default for vuln lookups |
| `spotlight_get_remediations` | Remediation instructions (patches, config changes) by remediation ID |
| `spotlight_host_vulns` | Triage shortcut: all open vulns for a specific host by device_id |

### Identity Protection — `modules/idp.py`

| Tool | Description |
|------|-------------|
| `identity_investigate_entity` | One-call identity triage — resolve user/device by name/email/IP/domain, return risk + timeline + relationships. |

### Threat Graph — `modules/threat_graph.py`

Read-only pivots against the CrowdStrike Threat Graph: process trees, file/network/identity edges, and indicator-to-host lookups. Includes 1 dynamic MCP resource (`falcon://reference/threatgraph-edge-types`) populated on first read.

| Tool | Description |
|------|-------------|
| `threatgraph_get_vertices` | Fetch vertex metadata by composite ID (process, file, domain, user, etc.) |
| `threatgraph_get_edges` | Walk outgoing/incoming edges of one edge type from a set of vertex IDs |
| `threatgraph_get_ran_on` | Find hosts/processes where an indicator (hash, domain, IP) was observed |
| `threatgraph_get_summary` | Triage-ready one-line-per-vertex summary for a set of vertex IDs |
| `threatgraph_get_edge_types` | Refresh and return the live list of valid Threat Graph edge types |

### Cloud Registration — `modules/cloud_registration.py`

| Tool | Description |
|------|-------------|
| `cloud_list_accounts` | List registered AWS/Azure accounts and their status |
| `cloud_policy_settings` | CSPM policy settings and compliance benchmarks |

### Cloud Security — `modules/cloud_security.py`

| Tool | Description |
|------|-------------|
| `cloud_get_risks` | Cloud risks ranked by score (misconfigs, unused identities, exposure) |
| `cloud_get_iom_detections` | Indicator of Misconfiguration detections with remediation steps |
| `cloud_query_assets` | Cloud asset inventory across AWS/Azure/GCP |
| `cloud_compliance_by_account` | Compliance posture aggregated by account and region |
| `cloud_get_risk_timeline` | Enriched per-asset timeline (GCRN): risk open/close/reopen events + config changes + actors |

---

## MCP Resources

The server exposes filter-syntax and reference documentation as MCP TextResources. AI assistants can read these to self-correct query/filter syntax or look up valid enum values without external lookups.

| URI | Content |
|-----|---------|
| `falcon://fql/alerts` | Alert FQL filter syntax (severity, status, product, timestamp) |
| `falcon://fql/hosts` | Host FQL filter syntax (hostname, platform, containment) |
| `falcon://fql/cases` | Case FQL filter syntax |
| `falcon://fql/cloud-risks` | Cloud risk filter syntax |
| `falcon://fql/cloud-iom` | IOM detection filter syntax |
| `falcon://fql/cloud-assets` | Cloud asset filter syntax |
| `falcon://fql/spotlight-vulnerabilities` | Spotlight vulnerability FQL syntax (aid, cve.id, severity, status) |
| `falcon://cql/syntax` | CQL query language reference for NG-SIEM |
| `falcon://rtr/commands` | RTR command allowlist + usage reference |
| `falcon://reference/threatgraph-edge-types` | Live Threat Graph edge-type vocabulary (populated on first read) |

---

## Multi-Transport Support

### stdio (default)

Standard MCP transport for CLI tools like Claude Code. No additional configuration needed.

```bash
crowdstrike-mcp
# or
crowdstrike-mcp --transport stdio
```

### SSE (Server-Sent Events)

HTTP-based transport for web clients and remote connections.

```bash
crowdstrike-mcp --transport sse --port 8000
```

### Streamable HTTP

Newer HTTP transport with bidirectional streaming.

```bash
crowdstrike-mcp --transport streamable-http --port 8000
```

### HTTP Authentication

For SSE and streamable-http transports, enable API key authentication:

```bash
crowdstrike-mcp --transport sse --api-key "your-secret-key"
```

Clients must include the `x-api-key` header in requests. Authentication uses constant-time comparison to prevent timing attacks.

---

## CLI Reference

```
crowdstrike-mcp [OPTIONS]
```

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--transport` | `FALCON_MCP_TRANSPORT` | `stdio` | Transport: `stdio`, `sse`, `streamable-http` |
| `--modules` | `FALCON_MCP_MODULES` | all | Comma-separated module list |
| `--debug` | `FALCON_MCP_DEBUG` | false | Enable debug logging |
| `--host` | `FALCON_MCP_HOST` | `127.0.0.1` | HTTP bind address |
| `--port` | `FALCON_MCP_PORT` | `8000` | HTTP port |
| `--api-key` | `FALCON_MCP_API_KEY` | — | API key for HTTP auth |
| — | `FALCON_MCP_NGSIEM_TIMEOUT` | `300` | Max seconds to poll for an `ngsiem_query` search job before timing out |
| — | `FALCON_MCP_NGSIEM_POLL_INTERVAL` | `2` | Seconds between `ngsiem_query` search-status polls |

### Selective Module Loading

Load only the modules you need to reduce attack surface and startup time:

```bash
# SOC triage workflow — just alerts, NGSIEM, and hosts
crowdstrike-mcp --modules ngsiem,alerts,hosts

# Cloud security audit
crowdstrike-mcp --modules cloudsecurity,cloudregistration

# Detection engineering
crowdstrike-mcp --modules ngsiem,correlation
```

**Available module names:** `alerts`, `caohunting`, `casemanagement`, `cloudsecurity`, `cloudregistration`, `correlation`, `hosts`, `idp`, `ngsiem`, `response`, `responsestore`, `rtr`, `spotlight`, `threatgraph`

---

## Permissions

The server uses a two-layer permission model: **server-side visibility** controls which tools exist, and **client-side presets** control which tools require user approval.

### Server-Side: `--allow-writes`

By default, the server runs in **read-only mode**. Write tools (alert updates, containment, rule changes) are not registered and don't appear in the tool list.

To enable write tools:

```bash
crowdstrike-mcp --allow-writes
```

Or via environment variable:

```bash
FALCON_MCP_ALLOW_WRITES=true crowdstrike-mcp
```

#### .mcp.json examples

**Read-only (default, recommended):**
```json
{
  "mcpServers": {
    "crowdstrike": {
      "command": "crowdstrike-mcp",
      "args": []
    }
  }
}
```

**With write tools enabled:**
```json
{
  "mcpServers": {
    "crowdstrike": {
      "command": "crowdstrike-mcp",
      "args": ["--allow-writes"]
    }
  }
}
```

**Minimal — only NGSIEM and host lookups:**
```json
{
  "mcpServers": {
    "crowdstrike": {
      "command": "crowdstrike-mcp",
      "args": ["--modules", "ngsiem,hosts"]
    }
  }
}
```

### Client-Side: Permission Presets

Four Claude Code permission presets are included in `.claude/`:

| Preset | Use Case | Auto-allowed | Prompts For |
|--------|----------|-------------|-------------|
| `permissions-minimal.json` | Query-only analyst | ngsiem_query, host_lookup | Everything else |
| `permissions-readonly.json` | Read-only (default) | All read tools | All write tools |
| `permissions-standard.json` | SOC triage analyst | All read + alert/case updates | Containment, rule changes |
| `permissions-full.json` | Admin / full trust | All tools | Nothing |

To switch presets:

```bash
cp .claude/permissions-standard.json .claude/settings.json
```

### How the Layers Compose

| Control | What it does |
|---------|-------------|
| `--modules` | Which modules load at all |
| `--allow-writes` | Whether write tools register within loaded modules |
| `.claude/settings.json` | Whether Claude Code prompts before calling a tool |

All three are independent. A tool must pass all applicable gates to execute without prompting.

### Write Tools

These tools require `--allow-writes` to be visible:

| Tool | Module | What it does |
|------|--------|-------------|
| `update_alert_status` | alerts | Change alert status, add comments/tags, assign/unassign a user (by user ID / email) |
| `correlation_update_rule` | correlation | Enable/disable detection rules |
| `correlation_import_to_iac` | correlation | Export rules to IaC YAML |
| `host_contain` | response | Network-isolate a host |
| `host_lift_containment` | response | Lift network isolation |
| `case_create` | case_management | Create a new case |
| `case_update` | case_management | Update case fields |
| `case_add_alert_evidence` | case_management | Attach alerts to a case |
| `case_add_event_evidence` | case_management | Attach events to a case |
| `case_add_tags` | case_management | Add tags to a case |
| `case_delete_tags` | case_management | Remove tags from a case |
| `case_upload_file` | case_management | Upload file to a case |

---

## Key Features

### Query Audit Trail

All NG-SIEM queries are automatically tagged with a timestamp comment for compliance and attribution:

```cql
// MCP Query - 2025-09-04T15:30:45.123456
#repo="cloudtrail" event.action = "ConsoleLogin"
```

### Scope-Aware Error Handling

When the API returns a 403 Forbidden, the error message includes the specific API scopes needed to resolve it:

```
HTTP 403: Insufficient permissions for query_alerts_v2.
Required scopes: alerts:read
Resolution: Add the required scopes to your API client in the CrowdStrike console.
```

### Graceful Module Degradation

Each module is imported independently with try/except. If a module fails to load (missing FalconPy service class, insufficient permissions, etc.), the remaining modules continue to function normally.

### Large Response Handling

Responses exceeding 20KB are automatically written to temporary files with a truncated summary returned to the AI assistant, preventing context window overflow.

### Shared OAuth2 Session

All modules share a single `OAuth2` token through `FalconClient.auth_object`. This means one authentication handshake for all 77 tools, regardless of how many FalconPy service classes are instantiated.

---

## Required API Scopes

### By Tool

| Tool | Module | Required Scopes | Notes |
|------|--------|----------------|-------|
| `ngsiem_query` | NG-SIEM | `ngsiem:read` | `ngsiem:write` only needed for timeout cleanup |
| `ngsiem_list_saved_queries` | NG-SIEM | `ngsiem:read` | |
| `ngsiem_get_saved_query_template` | NG-SIEM | `ngsiem:read` | |
| `ngsiem_list_lookup_files` | NG-SIEM | `ngsiem:read` | |
| `ngsiem_get_lookup_file` | NG-SIEM | `ngsiem:read` | Metadata only unless `include_content=true` |
| `ngsiem_list_dashboards` | NG-SIEM | `ngsiem:read` | |
| `ngsiem_list_parsers` | NG-SIEM | `ngsiem:read` | |
| `ngsiem_get_parser` | NG-SIEM | `ngsiem:read` | |
| `ngsiem_list_data_connections` | NG-SIEM | `ngsiem:read` | |
| `ngsiem_get_data_connection` | NG-SIEM | `ngsiem:read` | |
| `ngsiem_get_provisioning_status` | NG-SIEM | `ngsiem:read` | |
| `ngsiem_list_data_connectors` | NG-SIEM | `ngsiem:read` | |
| `ngsiem_list_connector_configs` | NG-SIEM | `ngsiem:read` | |
| `get_alerts` | Alerts | `alerts:read` | |
| `alert_analysis` | Alerts | `alerts:read` | |
| `ngsiem_alert_analysis` | Alerts | `alerts:read` | Alias for `alert_analysis` |
| `update_alert_status` | Alerts | `alerts:write` | Only write tool for alerts |
| `host_lookup` | Hosts | `hosts:read` | |
| `host_login_history` | Hosts | `hosts:read` | |
| `host_network_history` | Hosts | `hosts:read` | |
| `correlation_list_rules` | Correlation | `correlation-rules:read` | |
| `correlation_get_rule` | Correlation | `correlation-rules:read` | |
| `correlation_update_rule` | Correlation | `correlation-rules:write` | Enable/disable only, no create/delete |
| `correlation_export_rule` | Correlation | `correlation-rules:read` | |
| `cloud_list_accounts` | Cloud Registration | `cspm-registration:read` | |
| `cloud_policy_settings` | Cloud Registration | `cspm-registration:read` | |
| `cloud_get_risks` | Cloud Security | `cloud-security:read` | |
| `cloud_get_iom_detections` | Cloud Security | `cloud-security-detections:read` | |
| `cloud_query_assets` | Cloud Security | `cloud-security-assets:read` | |
| `cloud_compliance_by_account` | Cloud Security | `cloud-security-assets:read` | |
| `cloud_get_risk_timeline` | Cloud Security | `cloud-security:read` | |
| `case_query` | Case Management | `cases:read` | |
| `case_get` | Case Management | `cases:read` | |
| `case_get_fields` | Case Management | `cases:read` | |
| `case_create` | Case Management | `cases:read` | Uses POST but reads/creates |
| `case_update` | Case Management | `cases:write` | |
| `case_add_alert_evidence` | Case Management | `cases:write` | |
| `case_add_event_evidence` | Case Management | `cases:write` | |
| `case_add_tags` | Case Management | `cases:write` | |
| `case_delete_tags` | Case Management | `cases:write` | |
| `case_upload_file` | Case Management | `cases:write` | |
| `cao_search_queries`, `cao_get_queries`, `cao_aggregate`, `cao_search_guides`, `cao_get_guides` | CAO Hunting | `cao-hunting:read` | |
| `spotlight_*` (all 6 tools) | Spotlight | `spotlight-vulnerabilities:read` | Includes `supported_evaluations`, `query/get_vulnerabilities`, `vulnerabilities_combined`, `get_remediations`, `host_vulns` |
| `identity_investigate_entity` | Identity Protection | `identity-protection-assessment:read`, `identity-protection-detections:read`, `identity-protection-entities:read`, `identity-protection-timeline:read`, `identity-protection-graphql:write` | Read-only GraphQL query; `graphql:write` required by API surface for all GraphQL calls |
| `rtr_init_session`, `rtr_pulse_session`, `rtr_execute_command` | Real-Time Response | `real-time-response:write` | Session + command submission use the `:write` scope even though the MCP layer restricts commands to a read-only allowlist |
| `rtr_list_sessions`, `rtr_check_command_status`, `rtr_list_files`, `rtr_get_extracted_file_contents` | Real-Time Response | `real-time-response:read` | |
| `threatgraph_*` (all 5 tools) | Threat Graph | `threatgraph:read` | Vertices, edges, ran-on, summary, edge-type discovery |

### Minimum Scopes by Workflow

| Workflow | Scopes |
|----------|--------|
| **SOC triage** (read-only) | `alerts:read`, `ngsiem:read`, `hosts:read`, `detects:read` |
| **SOC triage** (with status updates) | Above + `alerts:write`, `cases:read`, `cases:write` |
| **Detection engineering** | `ngsiem:read`, `correlation-rules:read`, `correlation-rules:write` |
| **Cloud security audit** | `cspm-registration:read`, `cloud-security:read`, `cloud-security-detections:read`, `cloud-security-assets:read` |
| **Vulnerability management** | `spotlight-vulnerabilities:read` |
| **Identity investigation** | `identity-protection-assessment:read`, `identity-protection-detections:read`, `identity-protection-entities:read`, `identity-protection-timeline:read`, `identity-protection-graphql:write` |
| **Threat Graph pivots** | `threatgraph:read` |
| **Remote triage (RTR)** | `real-time-response:read`, `real-time-response:write` |
| **Full access** | All scopes above |

---

## Adding a New Module

1. Create `src/crowdstrike_mcp/modules/your_module.py` with a class extending `BaseModule`:

```python
from crowdstrike_mcp.modules.base import BaseModule

class YourModule(BaseModule):
    def __init__(self, client):
        super().__init__(client)
        # Create FalconPy service using shared auth
        self.service = SomeService(auth_object=self.client.auth_object)

    def register_tools(self, server):
        self._add_tool(server, self.your_tool, name="your_tool",
                       description="What this tool does")

    async def your_tool(self, param: Annotated[str, "Description"]) -> str:
        # Implementation
        return format_text_response(result, raw=True)
```

2. That's it. The registry auto-discovers any class ending in `Module` that extends `BaseModule`.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| **Credentials not found** | Check `~/.config/falcon/credentials.json` exists, or set `FALCON_CLIENT_ID` / `FALCON_CLIENT_SECRET` env vars |
| **403 Forbidden** | Add the required API scopes listed in the error message to your CrowdStrike API client |
| **Module failed to load** | Check stderr for `[registry] Failed to instantiate ...` — usually a missing FalconPy service class or dependency |
| **Query timeout** | NG-SIEM queries timeout after 120s. Simplify the query or narrow the time range |
| **Import error** | Run `pip install crowdstrike-mcp` or `pip install -e .[dev]` — requires `crowdstrike-falconpy>=1.6.1` and `mcp>=1.12.1` |
| **SSE connection refused** | Ensure `--host 0.0.0.0` if connecting from a different machine (default binds to localhost only) |

---

## Security

- Credentials are resolved at runtime from env vars or local files — never hardcoded
- HTTP transports support API key authentication with constant-time comparison
- All NG-SIEM queries carry audit trail timestamps for compliance attribution
- Input sanitization strips control characters and truncates oversized values
- The `update_alert_status` tool is the only write operation against live alert state
- `correlation_update_rule` can enable/disable rules but cannot create or delete them
- Defensive security focus only — no offensive capabilities

---

## Acknowledgements

Contains a port of the IdentityProtection module from CrowdStrike's falcon-mcp (MIT). See THIRD_PARTY_NOTICES.md.
