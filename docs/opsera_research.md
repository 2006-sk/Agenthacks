# Opsera Integration Research

> Research conducted for MergeGuard AI P3 — programmatic Security Scan and Architecture Analysis against a local codebase.

## Executive Summary

Opsera DevSecOps Agents are **not a traditional REST API or local CLI package**. They are exposed primarily as an **HTTP MCP (Model Context Protocol) server** intended for IDE integrations (Cursor, Claude Code, VS Code). There is **no published standalone REST endpoint** for `POST /security-scan` or similar. Backend integration requires an **MCP client** with **OAuth/Bearer authentication**, or a **Mock Mode** fallback for demo continuity.

---

## 1. How Opsera Is Installed

Opsera is **not installed as a pip/npm package** for scanning. Installation is IDE/plugin-based:

| Method | Command / Action |
|--------|----------------|
| Cursor Marketplace | Install from https://cursor.com/marketplace/opsera |
| Claude Code Marketplace | `/install opsera-devsecops` |
| GitHub plugin | `/plugin marketplace add opsera-agents/opsera-devsecops` |
| MCP one-liner (Claude Code) | `claude mcp add --scope user --transport http opsera https://agent.opsera.ai/mcp` |
| Manual MCP config | Add server block to `~/.cursor/mcp.json`, `~/.config/claude/mcp_settings.json`, or `.vscode/mcp.json` |

**Prerequisites:** Node.js 18+ (for MCP host), internet connection, Opsera account (free trial at https://agent.opsera.ai).

**Source:** [Quickstart](https://docs.agents.opsera.ai/getting-started/quickstart), [Claude Desktop Setup](https://docs.agents.opsera.ai/terminal-setup/claude-desktop), [GitHub opsera-devsecops](https://github.com/opsera-agents/opsera-devsecops)

---

## 2. Does It Run as an MCP Server?

**Yes.** This is the primary integration surface.

| Endpoint | Purpose |
|----------|---------|
| `https://agent.opsera.ai/mcp` | Primary MCP server (HTTP/streamable-http) |
| `https://mcp.opsera.io/mcp` | Alternate URL referenced in marketing docs |

**Verified behavior (live probe):**

```bash
curl -X POST https://agent.opsera.ai/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{...}}'
```

Response without auth:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32001,
    "message": "Authentication required",
    "data": {"discoveryEndpoint": "/.well-known/oauth-protected-resource"}
  }
}
```

OAuth discovery:

```json
{
  "resource": "https://agent.opsera.ai",
  "authorization_servers": ["https://agent.opsera.ai"],
  "bearer_methods_supported": ["header"]
}
```

---

## 3. Does It Run Through CLI Commands?

**Partially.** There is no standalone `opsera scan` binary. CLI access is through **IDE/agent slash commands**:

| Command | Description |
|---------|-------------|
| `/security-scan` | Comprehensive security scan |
| `/architecture-analyze` | Risk-focused architecture analysis |
| `/compliance-audit` | SOC2, HIPAA, PCI-DSS, ISO 27001 |
| `/sql-security` | SQL vulnerability scan |

Natural language prompts also work: *"Run a security scan on this repository"*.

Marketing pages show examples like `opsera-devops-agent:security-scan` — these are **agent command invocations inside the IDE**, not a system CLI.

**Source:** [Cursor Plugin](https://docs.agents.opsera.ai/marketplace/marketplace/cursor-plugin), [opsera-devsecops README](https://github.com/opsera-agents/opsera-devsecops)

---

## 4. Does It Expose REST APIs?

**No public REST API for DevSecOps scan agents.**

- Opsera Agents communicate via **MCP JSON-RPC** over HTTP.
- A separate legacy Opsera platform MCP server (`https://agent.opsera.io/mcp`) exists for **pipeline/insights** operations (third-party `CodeGlide/opsera-mcp-server`), not the DevSecOps scan agents.
- Docs mention results stored in the **Opsera portal** but do not publish a REST API to retrieve scan results programmatically.

**Implication for MergeGuard P3:** Use MCP client calls, not REST fetch.

---

## 5. Authentication Requirements

| Method | Details |
|--------|---------|
| **OAuth 2.0 (primary)** | Browser-based login via `/mcp` in Claude Code; tokens stored in OS keychain; auto-refresh |
| **Bearer token (programmatic)** | `Authorization: Bearer <token>` header on MCP HTTP requests |
| **Token source** | Opsera dashboard → API Keys → Generate Token (marketing page); OAuth flow for IDE plugins |

OAuth authorization server metadata (`https://agent.opsera.ai/.well-known/oauth-authorization-server`):

- `authorization_endpoint`: `https://agent.opsera.ai/authorize`
- `token_endpoint`: `https://agent.opsera.ai/token`
- `mcp_endpoint`: `https://agent.opsera.ai/mcp`
- Grant types: `authorization_code`, `refresh_token`
- PKCE supported: `S256`

**Docs state:** "No API keys required" for IDE setup (OAuth handles it). For **headless backend** use, a Bearer token env var is the practical approach.

**Recommended env vars for P3:**

```bash
OPSERA_MCP_URL=https://agent.opsera.ai/mcp
OPSERA_API_TOKEN=<bearer-token>   # optional; triggers live MCP mode
OPSERA_MOCK_MODE=true             # force mock when no token
```

---

## 6. Input Format

### MCP Tool Names (from official plugin source)

| Tool | MCP Name |
|------|----------|
| Security Scan | `mcp__opsera__security-scan` |
| Architecture Analyze | `mcp__opsera__architecture-analyze` |
| Compliance Audit | `mcp__opsera__compliance-audit` |
| SQL Security | `mcp__opsera__sql-security` |
| Telemetry | `mcp__opsera__report-telemetry` |

### Security Scan Parameters

| Parameter | Values | Required |
|-----------|--------|----------|
| `path` | Directory/repo path | Yes |
| `scan_type` | `full`, `secrets`, `vulnerabilities`, `sast`, `containers`, `iac`, `pre-commit` | Yes |
| `severity_threshold` | `critical`, `high`, `medium`, `all` | Yes |
| `phase` | 1–6 (phased execution) | Per phase |
| `tools_ready` | boolean (phase 2) | Per phase |
| `scan_results` | object (phase 4) | Per phase |

**Phases:** Pre-flight → Tool verification → Execute scans → Generate reports → Telemetry → Complete

**Underlying scanners:** Gitleaks (secrets), npm/pip audits (dependencies), Semgrep (SAST), Trivy (containers/IaC)

### Architecture Analyze Parameters

| Parameter | Description |
|-----------|-------------|
| Repository path / context | Target codebase |
| `_execution_id` | Continuation ID from prior pass |
| `_phase_result` | Result from prior pass |

**Execution:** Multi-pass (Pass 1: Fast Scan → Pass 2: Risk Deep Dive → Pass 3: Risk Report). Request HTML format for rich output.

---

## 7. Output Format

Opsera does **not publish a fixed JSON schema** for findings. Output is primarily:

### Security Scan Output

- **Console:** Phase progress, severity counts, file:line references
- **Reports:** `security-scan-report.html`, markdown summaries
- **Finding fields (documented):**
  - Severity: CRITICAL, HIGH, MEDIUM, LOW
  - File path + line number
  - Description of issue
  - Remediation recommendations
  - Severity summary breakdown

### Architecture Analyze Output

- **Reports (5 files):**
  - `architecture-documentation.md`
  - `cicd-pipeline-architecture.md`
  - `cost-optimization-analysis.md`
  - `disaster-recovery-architecture.md`
  - `production_ready_code_examples.py`, `operational-guide.md`
- **Console findings:** Circular dependencies, anti-patterns, SPOFs, tech debt
- **Maturity levels:** Production Ready / Needs Hardening / Early Stage
- **Telemetry fields:** `score`, `scoreLabel`, finding counts by severity

### Normalization Required for P3

Map Opsera output → internal format:

```json
{
  "severity": "HIGH",
  "title": "Hardcoded Secret",
  "description": "API key exposed in config.js:12"
}
```

---

## 8. How to Scan a Local Repository

1. **IDE path (documented):** Open repo in Cursor/Claude Code with MCP configured; run `/security-scan` with path parameter.
2. **MCP programmatic path (for backend):**
   - Connect MCP client to `https://agent.opsera.ai/mcp` with Bearer token
   - Call `tools/call` for `mcp__opsera__security-scan` with `path: "/workspace/merged_repo"`
   - Execute all phases sequentially
   - Parse tool result content (text/markdown/structured blocks)
3. **Important:** Docs state source code stays **local** — MCP reads workspace files; only metadata/results go to Opsera portal.

For MergeGuard P3, `repo_path` from Daytona sandbox must be accessible to the MCP host. In practice, the analysis service runs **inside or alongside the sandbox** where the merged repo lives.

---

## 9. How to Analyze Architecture

Same MCP pattern:

1. Call `mcp__opsera__architecture-analyze` with repo path and context
2. Continue with `_execution_id` / `_phase_result` for passes 2 and 3
3. Collect risk findings: circular deps, anti-patterns, auth gaps, SPOFs
4. Call `mcp__opsera__report-telemetry` after completion

Analysis time: **5–15 minutes** for large codebases (per docs).

---

## 10. Best Way to Integrate Inside a Python Backend

### Recommended Architecture

```
FastAPI Route → SecurityAnalyzer / ArchitectureAnalyzer → OpseraClient → MCP HTTP (or Mock)
```

### Option A: MCP Python SDK (Production Path)

Use the official `mcp` Python package with `streamablehttp_client`:

```python
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async with streamablehttp_client(
    url="https://agent.opsera.ai/mcp",
    headers={"Authorization": f"Bearer {token}"},
) as (read, write, _):
    async with ClientSession(read, write) as session:
        await session.initialize()
        result = await session.call_tool(
            "mcp__opsera__security-scan",
            {"path": repo_path, "scan_type": "full", "severity_threshold": "all", "phase": 1},
        )
```

**Challenges:**
- OAuth browser flow not suitable for headless services
- Phased/multi-pass execution requires orchestration logic
- Output parsing is non-trivial (markdown/text, not strict JSON)
- Scan duration (minutes) may exceed HTTP timeout — consider async job pattern

### Option B: Mock Mode (Hackathon / Demo Path)

When `OPSERA_API_TOKEN` is missing or MCP call fails:

- Generate realistic deterministic findings based on repo_path hash
- Ensures demo continuity for MergeGuard dashboard (P4)
- Swap in real MCP client later without changing route/analyzer code

### Option C: Subprocess via Cursor/Claude SDK (Not Recommended)

Could spawn an agent with MCP configured, but adds heavy dependency and is fragile for production.

---

## Integration Decision for MergeGuard P3

| Aspect | Decision |
|--------|----------|
| Primary interface | `OpseraClient` abstraction |
| Live mode | MCP HTTP client when `OPSERA_API_TOKEN` set |
| Fallback | Mock mode with realistic findings |
| Isolation | All Opsera details hidden in `services/opsera_client.py` |
| Output | Normalized to `SecurityFinding` / `ArchitectureFinding` + scores |

---

## References

- [Opsera Agents Docs](https://docs.agents.opsera.ai/)
- [Security Scan Agent](https://docs.agents.opsera.ai/devsecops-agents/security-scan-agent)
- [Architecture Analyze Agent](https://docs.agents.opsera.ai/devsecops-agents/architecture-analyze-agent)
- [How It Works](https://docs.agents.opsera.ai/how-it-works)
- [Cursor Plugin](https://docs.agents.opsera.ai/marketplace/marketplace/cursor-plugin)
- [Claude Desktop Setup](https://docs.agents.opsera.ai/terminal-setup/claude-desktop)
- [GitHub: opsera-agents/opsera-devsecops](https://github.com/opsera-agents/opsera-devsecops)
- [Opsera Marketing / MCP Config](https://opsera.ai/agents/)

---

## Live Probe Results (2026-05-31)

```bash
# MCP requires auth
POST https://agent.opsera.ai/mcp → {"error":{"code":-32001,"message":"Authentication required"}}

# OAuth protected resource
GET https://agent.opsera.ai/.well-known/oauth-protected-resource
→ bearer_methods_supported: ["header"]

# OAuth server
GET https://agent.opsera.ai/.well-known/oauth-authorization-server
→ mcp_endpoint: https://agent.opsera.ai/mcp
```
