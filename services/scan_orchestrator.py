import logging
import os
from dataclasses import dataclass, field
from typing import Any

from models import AnalysisMode, ArchitectureFinding, SecurityFinding
from services.local_scanners import (
    analyze_architecture,
    check_tools,
    is_tool_installed,
    scan_dependencies,
    scan_sast,
    scan_secrets,
)
from services.local_scanners.parsers import (
    parse_mcp_architecture_findings,
    parse_mcp_security_findings,
)
from services.mcp_client import DiscoveredTools, OpseraMcpClient, OpseraMcpError

logger = logging.getLogger(__name__)

SECURITY_TOOLS = ["gitleaks", "semgrep", "grype", "checkov", "hadolint"]
EXPECTED_SECURITY_SCANNERS = ["gitleaks", "semgrep", "bandit", "pip-audit", "grype", "npm-audit"]


@dataclass
class SecurityScanResult:
    findings: list[SecurityFinding] = field(default_factory=list)
    local_scanners_attempted: list[str] = field(default_factory=list)
    local_scanners_succeeded: list[str] = field(default_factory=list)
    mcp_findings_count: int = 0
    mcp_phases_completed: int = 0


@dataclass
class ArchitectureScanResult:
    findings: list[ArchitectureFinding] = field(default_factory=list)
    local_analysis_ran: bool = False
    mcp_findings_count: int = 0
    mcp_passes_completed: int = 0


class ScanOrchestrator:
    """Agent layer: orchestrates Opsera MCP phases and local scan execution."""

    def __init__(
        self,
        mcp_client: OpseraMcpClient,
        discovered: DiscoveredTools,
    ) -> None:
        self.mcp = mcp_client
        self.discovered = discovered

    async def run_security_scan(self, repo_path: str) -> SecurityScanResult:
        logger.info("Scan orchestrator: security scan started for %s", repo_path)
        result = SecurityScanResult()

        mcp_results = await self._run_mcp_security_phases(repo_path)
        result.mcp_phases_completed = len(mcp_results)
        mcp_findings = parse_mcp_security_findings(mcp_results)
        result.mcp_findings_count = len(mcp_findings)

        local_findings, attempted, succeeded = self._run_local_security_scans(repo_path)
        result.local_scanners_attempted = attempted
        result.local_scanners_succeeded = succeeded

        result.findings = _dedupe_security(mcp_findings + local_findings)
        logger.info(
            "Scan orchestrator: security scan complete — %d findings "
            "(mcp=%d, local=%d, scanners=%s)",
            len(result.findings),
            result.mcp_findings_count,
            len(local_findings),
            succeeded,
        )
        return result

    async def run_architecture_analysis(self, repo_path: str) -> ArchitectureScanResult:
        logger.info("Scan orchestrator: architecture analysis started for %s", repo_path)
        result = ArchitectureScanResult()

        mcp_results, passes = await self._run_mcp_architecture_passes(repo_path)
        result.mcp_passes_completed = passes
        mcp_findings = parse_mcp_architecture_findings(mcp_results)
        result.mcp_findings_count = len(mcp_findings)

        local_findings, ran = analyze_architecture(repo_path)
        result.local_analysis_ran = ran

        result.findings = _dedupe_architecture(mcp_findings + local_findings)
        logger.info(
            "Scan orchestrator: architecture analysis complete — %d findings "
            "(mcp=%d, local=%d, local_ran=%s)",
            len(result.findings),
            result.mcp_findings_count,
            len(local_findings),
            ran,
        )
        return result

    async def _run_mcp_security_phases(self, repo_path: str) -> list[Any]:
        if not self.discovered.security_scan:
            logger.warning("No security-scan tool discovered in MCP tools/list")
            return []

        tool_name = self.discovered.security_scan
        logger.info("MCP security phase 1: initiating scan via %s", tool_name)

        tool_status = check_tools(SECURITY_TOOLS)
        tools_ready = any(tool_status.values())

        phase_args: list[dict[str, Any]] = [
            {
                "path": repo_path,
                "scan_type": "full",
                "severity_threshold": "all",
                "phase": 1,
                "user_confirmed": True,
            },
            {
                "path": repo_path,
                "phase": 2,
                "tools_ready": tools_ready,
            },
            {
                "path": repo_path,
                "phase": 3,
                "scan_type": "full",
                "tools_ready": tools_ready,
            },
            {
                "path": repo_path,
                "phase": 4,
                "scans_complete": True,
            },
            {
                "path": repo_path,
                "phase": 5,
                "reports_generated": True,
            },
            {
                "path": repo_path,
                "phase": 6,
            },
        ]

        results: list[Any] = []
        for idx, args in enumerate(phase_args, start=1):
            try:
                logger.info("MCP security phase %d: calling %s", idx, tool_name)
                response = await self.mcp.call_tool(tool_name, args)
                results.append(response)
            except OpseraMcpError as exc:
                logger.warning("MCP security phase %d failed: %s", idx, exc)
                break

        await self._report_telemetry(repo_path, scan_type="security")
        return results

    async def _run_mcp_architecture_passes(self, repo_path: str) -> tuple[list[Any], int]:
        if not self.discovered.architecture_analyze:
            logger.warning("No architecture-analyze tool discovered in MCP tools/list")
            return [], 0

        tool_name = self.discovered.architecture_analyze
        results: list[Any] = []
        passes = 0

        logger.info("MCP architecture pass 1: initiating via %s", tool_name)
        try:
            pass1 = await self.mcp.call_tool(
                tool_name,
                {
                    "path": repo_path,
                    "project_name": os.path.basename(repo_path.rstrip("/")),
                },
            )
            results.append(pass1)
            passes = 1
        except OpseraMcpError as exc:
            logger.warning("MCP architecture pass 1 failed: %s", exc)
            return results, passes

        execution_id = _extract_field(pass1, "_execution_id")
        if not execution_id:
            logger.info("MCP architecture: no _execution_id; single-pass only")
            return results, passes

        logger.info("MCP architecture pass 2: continuing execution %s", execution_id)
        try:
            pass2 = await self.mcp.call_tool(
                tool_name,
                {
                    "path": repo_path,
                    "_execution_id": execution_id,
                    "_phase_result": pass1,
                },
            )
            results.append(pass2)
            passes = 2
        except OpseraMcpError as exc:
            logger.warning("MCP architecture pass 2 failed: %s", exc)
            return results, passes

        logger.info("MCP architecture pass 3: fetching detailed report")
        try:
            pass3 = await self.mcp.call_tool(
                tool_name,
                {
                    "path": repo_path,
                    "_execution_id": execution_id,
                    "_phase_result": pass2,
                    "output_format": "detailed",
                },
            )
            results.append(pass3)
            passes = 3
        except OpseraMcpError as exc:
            logger.warning("MCP architecture pass 3 failed: %s", exc)

        await self._report_telemetry(repo_path, scan_type="architecture")
        return results, passes

    async def _report_telemetry(self, repo_path: str, scan_type: str) -> None:
        telemetry_tool = _find_tool_by_keyword(self.discovered, "telemetry")
        if not telemetry_tool:
            return
        try:
            await self.mcp.call_tool(
                telemetry_tool,
                {"path": repo_path, "scan_type": scan_type, "source": "mergeguard-p3"},
            )
            logger.info("Telemetry reported via %s", telemetry_tool)
        except OpseraMcpError as exc:
            logger.debug("Telemetry report skipped: %s", exc)

    def _run_local_security_scans(
        self, repo_path: str
    ) -> tuple[list[SecurityFinding], list[str], list[str]]:
        findings: list[SecurityFinding] = []
        attempted: list[str] = []
        succeeded: list[str] = []

        logger.info("Local security phase: checking tools")
        check_tools(SECURITY_TOOLS)

        secret_findings, secrets_ran = scan_secrets(repo_path)
        if is_tool_installed("gitleaks") or secrets_ran:
            attempted.append("gitleaks")
            if secrets_ran:
                succeeded.append("gitleaks")
        findings.extend(secret_findings)

        sast_findings, sast_ran, sast_name = scan_sast(repo_path)
        if sast_name != "none":
            attempted.append(sast_name)
            if sast_ran:
                succeeded.append(sast_name)
        findings.extend(sast_findings)

        dep_findings, dep_ran, dep_name = scan_dependencies(repo_path)
        if dep_name != "none":
            attempted.append(dep_name)
            if dep_ran:
                succeeded.append(dep_name)
        findings.extend(dep_findings)

        logger.info(
            "Local security scans: attempted=%s succeeded=%s findings=%d",
            attempted,
            succeeded,
            len(findings),
        )
        return findings, attempted, succeeded


def resolve_analysis_mode(
    security: SecurityScanResult | None,
    architecture: ArchitectureScanResult | None,
    *,
    used_mock: bool,
) -> AnalysisMode:
    if used_mock:
        return AnalysisMode.MOCK

    has_live_signal = False
    has_partial_failure = False

    if security:
        if security.local_scanners_succeeded or security.mcp_findings_count > 0:
            has_live_signal = True
        # Partial only when a scanner was attempted but did not succeed (not merely optional tools missing)
        attempted = set(security.local_scanners_attempted)
        succeeded = set(security.local_scanners_succeeded)
        if attempted and attempted - succeeded:
            has_partial_failure = True

    if architecture:
        if architecture.local_analysis_ran or architecture.mcp_findings_count > 0:
            has_live_signal = True

    if has_live_signal:
        return AnalysisMode.PARTIAL if has_partial_failure else AnalysisMode.LIVE

    return AnalysisMode.MOCK


def get_local_tool_status() -> dict[str, bool]:
    tools = SECURITY_TOOLS + ["bandit", "pip-audit", "npm"]
    return check_tools(tools)


def _find_tool_by_keyword(discovered: DiscoveredTools, keyword: str) -> str | None:
    for tool in discovered.all_tools:
        if keyword in tool.name.lower():
            return tool.name
    return None


def _extract_field(result: Any, field: str) -> Any:
    import json

    if isinstance(result, dict):
        if field in result:
            return result[field]
        structured = result.get("structuredContent")
        if isinstance(structured, dict) and field in structured:
            return structured[field]
        content = result.get("content", [])
        text_parts = [
            block if isinstance(block, str) else block.get("text", "")
            for block in content
            if isinstance(block, (str, dict))
        ]
        text = "\n".join(text_parts)
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict) and field in parsed:
                return parsed[field]
        except json.JSONDecodeError:
            pass
    return None


def _dedupe_security(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[SecurityFinding] = []
    for finding in findings:
        key = (finding.severity.value, finding.title, finding.description)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def _dedupe_architecture(findings: list[ArchitectureFinding]) -> list[ArchitectureFinding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[ArchitectureFinding] = []
    for finding in findings:
        key = (finding.severity.value, finding.title, finding.description)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique
