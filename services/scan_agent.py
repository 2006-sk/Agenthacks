import json
import logging
import os
from typing import Any

from models import ArchitectureFinding, SecurityFinding
from services.agent_brain import (
    AgentBrain,
    AgentBrainError,
    _mandatory_security_scanner_names,
    parse_agent_architecture_findings,
    parse_agent_security_findings,
)
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
from services.scan_orchestrator import (
    SECURITY_TOOLS,
    ArchitectureScanResult,
    ScanOrchestrator,
    SecurityScanResult,
    _dedupe_architecture,
    _dedupe_security,
    _extract_field,
    _find_tool_by_keyword,
)

logger = logging.getLogger(__name__)

MAX_AGENT_STEPS = 8


class ScanAgent:
    """LLM-driven agent that interprets Opsera MCP phases and executes local scans."""

    def __init__(
        self,
        mcp_client: OpseraMcpClient,
        discovered: DiscoveredTools,
        brain: AgentBrain | None = None,
    ) -> None:
        self.mcp = mcp_client
        self.discovered = discovered
        self.brain = brain or AgentBrain()

    async def run_security_scan(self, repo_path: str) -> SecurityScanResult:
        logger.info("Scan agent: security scan started for %s", repo_path)
        if not self.discovered.security_scan:
            raise AgentBrainError("No security-scan tool discovered")

        tool_name = self.discovered.security_scan
        tool_status = check_tools(SECURITY_TOOLS + ["bandit", "pip-audit"])

        result = SecurityScanResult()
        mcp_results: list[Any] = []
        findings: list[SecurityFinding] = []
        attempted: list[str] = []
        succeeded: list[str] = []
        local_output_log: list[str] = []
        security_scanners_ran = False

        phase = 1
        mcp_response = await self.mcp.call_tool(
            tool_name,
            {
                "path": repo_path,
                "scan_type": "full",
                "severity_threshold": "all",
                "phase": phase,
                "user_confirmed": True,
            },
        )
        mcp_results.append(mcp_response)
        result.mcp_phases_completed = 1

        for step in range(MAX_AGENT_STEPS):
            response_text = extract_mcp_text(mcp_response)
            decision = self.brain.decide_security_step(
                repo_path=repo_path,
                phase=phase,
                mcp_response_text=response_text,
                tool_status=tool_status,
                local_scan_output="\n".join(local_output_log),
                steps_remaining=MAX_AGENT_STEPS - step,
                security_scanners_ran=security_scanners_ran,
            )

            findings.extend(parse_agent_security_findings(decision.security_findings))

            scanners_to_run = decision.scanners
            if phase >= 3 and not security_scanners_ran:
                scanners_to_run = _mandatory_security_scanner_names(tool_status)

            if scanners_to_run:
                scan_findings, att, succ, output = self._run_security_scanners(
                    repo_path, scanners_to_run
                )
                findings.extend(scan_findings)
                attempted.extend(att)
                succeeded.extend(succ)
                if succ:
                    security_scanners_ran = True
                if output:
                    local_output_log.append(output)

            if decision.done or decision.action == "complete":
                if security_scanners_ran:
                    logger.info("Scan agent: security complete at phase %d (step %d)", phase, step + 1)
                    break
                logger.info("Scan agent: ignoring done=true until security scanners have run")

            if decision.action == "abort":
                raise AgentBrainError(f"Agent aborted security scan: {decision.reasoning}")

            phase += 1
            mcp_args: dict[str, Any] = {
                "path": repo_path,
                "phase": phase,
                **decision.mcp_args,
            }
            if phase == 2 and "tools_ready" not in mcp_args:
                mcp_args["tools_ready"] = any(tool_status.values())
            if phase >= 4 and "scans_complete" not in mcp_args:
                mcp_args["scans_complete"] = bool(succeeded)

            try:
                mcp_response = await self.mcp.call_tool(tool_name, mcp_args)
                mcp_results.append(mcp_response)
                result.mcp_phases_completed += 1
            except OpseraMcpError as exc:
                logger.warning("Scan agent: MCP phase %d failed: %s", phase, exc)
                break

        if not security_scanners_ran:
            logger.info("Scan agent: running mandatory security scanners before finish")
            mandatory = _mandatory_security_scanner_names(tool_status)
            scan_findings, att, succ, _ = self._run_security_scanners(repo_path, mandatory)
            findings.extend(scan_findings)
            attempted.extend(att)
            succeeded.extend(succ)
            security_scanners_ran = bool(succ)

        await self._report_telemetry(repo_path, "security")

        mcp_findings = parse_mcp_security_findings(mcp_results)
        result.mcp_findings_count = len(mcp_findings)
        result.local_scanners_attempted = attempted
        result.local_scanners_succeeded = succeeded
        result.findings = _dedupe_security(findings + mcp_findings)

        if not succeeded and result.mcp_findings_count == 0:
            raise AgentBrainError(
                "Agent security scan: no local scanners succeeded and no MCP findings"
            )

        logger.info(
            "Scan agent: security complete — %d findings (agent+mcp), scanners=%s",
            len(result.findings),
            succeeded,
        )
        return result

    async def run_architecture_analysis(self, repo_path: str) -> ArchitectureScanResult:
        logger.info("Scan agent: architecture analysis started for %s", repo_path)
        if not self.discovered.architecture_analyze:
            raise AgentBrainError("No architecture-analyze tool discovered")

        tool_name = self.discovered.architecture_analyze
        result = ArchitectureScanResult()
        mcp_results: list[Any] = []
        findings: list[ArchitectureFinding] = []
        local_output_log: list[str] = []
        execution_id: str | None = None
        pass_num = 1
        architecture_ran = False

        mcp_response = await self.mcp.call_tool(
            tool_name,
            {
                "path": repo_path,
                "project_name": os.path.basename(repo_path.rstrip("/")),
            },
        )
        mcp_results.append(mcp_response)
        result.mcp_passes_completed = 1
        execution_id = _extract_field(mcp_response, "_execution_id")

        for step in range(MAX_AGENT_STEPS):
            response_text = extract_mcp_text(mcp_response)
            decision = self.brain.decide_architecture_step(
                repo_path=repo_path,
                pass_num=pass_num,
                mcp_response_text=response_text,
                execution_id=execution_id,
                local_scan_output="\n".join(local_output_log),
                steps_remaining=MAX_AGENT_STEPS - step,
                architecture_ran=architecture_ran,
            )

            findings.extend(parse_agent_architecture_findings(decision.architecture_findings))

            if "architecture" in decision.scanners or not architecture_ran:
                local_findings, ran = analyze_architecture(repo_path)
                findings.extend(local_findings)
                if ran:
                    architecture_ran = True
                    result.local_analysis_ran = True
                local_output_log.append(f"architecture findings: {len(local_findings)}")

            if decision.done or decision.action == "complete":
                if architecture_ran:
                    logger.info("Scan agent: architecture complete at pass %d", pass_num)
                    break
                logger.info("Scan agent: ignoring done=true until architecture analyzer has run")

            if decision.action == "abort":
                raise AgentBrainError(f"Agent aborted architecture: {decision.reasoning}")

            pass_num += 1
            mcp_args: dict[str, Any] = {"path": repo_path, **decision.mcp_args}
            if execution_id:
                mcp_args["_execution_id"] = execution_id
                mcp_args["_phase_result"] = mcp_response
            if pass_num >= 3 and "output_format" not in mcp_args:
                mcp_args["output_format"] = "detailed"

            try:
                mcp_response = await self.mcp.call_tool(tool_name, mcp_args)
                mcp_results.append(mcp_response)
                result.mcp_passes_completed += 1
            except OpseraMcpError as exc:
                logger.warning("Scan agent: architecture pass %d failed: %s", pass_num, exc)
                break

        if not architecture_ran:
            logger.info("Scan agent: running mandatory architecture analyzer before finish")
            local_findings, ran = analyze_architecture(repo_path)
            findings.extend(local_findings)
            architecture_ran = ran
            result.local_analysis_ran = ran

        await self._report_telemetry(repo_path, "architecture")

        mcp_findings = parse_mcp_architecture_findings(mcp_results)
        result.mcp_findings_count = len(mcp_findings)
        result.findings = _dedupe_architecture(findings + mcp_findings)

        if not result.findings and not result.local_analysis_ran:
            raise AgentBrainError("Agent architecture analysis produced no results")

        logger.info("Scan agent: architecture complete — %d findings", len(result.findings))
        return result

    def _run_security_scanners(
        self, repo_path: str, scanners: list[str]
    ) -> tuple[list[SecurityFinding], list[str], list[str], str]:
        findings: list[SecurityFinding] = []
        attempted: list[str] = []
        succeeded: list[str] = []
        outputs: list[str] = []

        for scanner in scanners:
            if scanner == "gitleaks":
                if is_tool_installed("gitleaks"):
                    attempted.append("gitleaks")
                f, ran = scan_secrets(repo_path)
                if ran:
                    succeeded.append("gitleaks")
                findings.extend(f)
                outputs.append(f"gitleaks: {len(f)} findings")
            elif scanner in ("bandit", "semgrep"):
                f, ran, name = scan_sast(repo_path)
                if name != "none":
                    attempted.append(name)
                if ran:
                    succeeded.append(name)
                findings.extend(f)
                outputs.append(f"{name}: {len(f)} findings")
            elif scanner in ("pip-audit", "dependency"):
                f, ran, name = scan_dependencies(repo_path)
                if name != "none":
                    attempted.append(name)
                if ran:
                    succeeded.append(name)
                findings.extend(f)
                outputs.append(f"{name}: {len(f)} findings")

        return findings, attempted, succeeded, "; ".join(outputs)

    async def _report_telemetry(self, repo_path: str, scan_type: str) -> None:
        telemetry_tool = _find_tool_by_keyword(self.discovered, "telemetry")
        if not telemetry_tool:
            return
        try:
            await self.mcp.call_tool(
                telemetry_tool,
                {"path": repo_path, "scan_type": scan_type, "source": "mergeguard-agent"},
            )
        except OpseraMcpError:
            pass


def extract_mcp_text(result: Any) -> str:
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        if "content" in result:
            parts: list[str] = []
            for block in result["content"]:
                if isinstance(block, str):
                    parts.append(block)
                elif isinstance(block, dict) and block.get("type") == "text":
                    parts.append(block.get("text", ""))
            return "\n".join(parts)
        if result.get("structuredContent"):
            return json.dumps(result["structuredContent"])
        return json.dumps(result)
    if isinstance(result, list):
        return json.dumps(result)
    return str(result)


async def run_agentic_analysis(
    mcp: OpseraMcpClient,
    discovered: DiscoveredTools,
    repo_path: str,
    brain: AgentBrain | None = None,
) -> tuple[SecurityScanResult, ArchitectureScanResult]:
    """Try full agentic scan; raises AgentBrainError on failure."""
    agent = ScanAgent(mcp, discovered, brain)
    security = await agent.run_security_scan(repo_path)
    architecture = await agent.run_architecture_analysis(repo_path)
    return security, architecture


async def run_orchestrator_analysis(
    mcp: OpseraMcpClient,
    discovered: DiscoveredTools,
    repo_path: str,
) -> tuple[SecurityScanResult, ArchitectureScanResult]:
    """Deterministic fallback orchestrator."""
    orchestrator = ScanOrchestrator(mcp, discovered)
    security = await orchestrator.run_security_scan(repo_path)
    architecture = await orchestrator.run_architecture_analysis(repo_path)
    return security, architecture
