import json
import logging
import os
import re
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

from models import ArchitectureFinding, ArchitectureSeverity, SecurityFinding, Severity

logger = logging.getLogger(__name__)

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_BASE_URL = "https://api.groq.com/openai/v1/chat/completions"
MAX_LLM_RETRIES = 2

ALLOWED_SCANNERS = frozenset(
    {"gitleaks", "bandit", "semgrep", "pip-audit", "dependency", "architecture"}
)


class AgentBrainError(Exception):
    """Raised when the LLM agent brain fails."""


class AgentDecision(BaseModel):
    action: Literal["mcp_continue", "run_scanners", "complete", "abort"] = "mcp_continue"
    reasoning: str = ""
    mcp_args: dict[str, Any] = Field(default_factory=dict)
    scanners: list[str] = Field(default_factory=list)
    security_findings: list[dict[str, str]] = Field(default_factory=list)
    architecture_findings: list[dict[str, str]] = Field(default_factory=list)
    done: bool = False


class AgentBrain:
    """Groq/Llama reasoning layer for Opsera MCP [AI-EXECUTED] workflows."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
    ) -> None:
        self.api_key = api_key or GROQ_API_KEY
        self.model = model or GROQ_MODEL

    @classmethod
    def is_available(cls) -> bool:
        return bool(os.getenv("GROQ_API_KEY", "").strip())

    def decide_security_step(
        self,
        *,
        repo_path: str,
        phase: int,
        mcp_response_text: str,
        tool_status: dict[str, bool],
        local_scan_output: str = "",
        steps_remaining: int = 5,
        security_scanners_ran: bool = False,
    ) -> AgentDecision:
        mandatory = _mandatory_security_scanner_names(tool_status)
        system = (
            "You are MergeGuard AI executing Opsera security-scan MCP phases.\n"
            "Respond with ONLY valid JSON:\n"
            '{"action":"mcp_continue|run_scanners|complete|abort",'
            '"reasoning":"brief",'
            '"mcp_args":{},'
            '"scanners":["gitleaks","bandit","semgrep","pip-audit"],'
            '"security_findings":[{"severity":"CRITICAL|HIGH|MEDIUM|LOW","title":"...","description":"..."}],'
            '"done":false}\n'
            "MANDATORY RULES (never violate):\n"
            f"1. At phase >= 3 you MUST set action=run_scanners and include scanners: {mandatory}\n"
            "2. Do NOT set done=true until mandatory scanners have run (security_scanners_ran=true).\n"
            "3. Auto-confirm Opsera yes/no prompts via mcp_args user_confirmed=true.\n"
            "4. Extract real findings from MCP text into security_findings (file paths required).\n"
            "5. Never emit summary-only findings like 'Bandit findings' without file paths.\n"
            "6. scanners must be from: gitleaks, bandit, semgrep, pip-audit.\n"
            "7. Use action=run_scanners (not mcp_continue) whenever MCP asks to execute scans."
        )
        user = (
            f"repo_path: {repo_path}\n"
            f"current_phase: {phase}\n"
            f"steps_remaining: {steps_remaining}\n"
            f"security_scanners_ran: {security_scanners_ran}\n"
            f"mandatory_scanners: {mandatory}\n"
            f"installed_tools: {json.dumps(tool_status)}\n"
            f"mcp_response:\n{mcp_response_text[:12000]}\n"
        )
        if local_scan_output:
            user += f"\nlocal_scan_output:\n{local_scan_output[:8000]}\n"

        decision = self._complete(system, user)
        return enforce_security_decision(decision, phase, tool_status, security_scanners_ran)

    def decide_architecture_step(
        self,
        *,
        repo_path: str,
        pass_num: int,
        mcp_response_text: str,
        execution_id: str | None = None,
        local_scan_output: str = "",
        steps_remaining: int = 3,
        architecture_ran: bool = False,
    ) -> AgentDecision:
        system = (
            "You are MergeGuard AI executing Opsera architecture-analyze MCP passes.\n"
            "Respond with ONLY valid JSON:\n"
            '{"action":"mcp_continue|run_scanners|complete|abort",'
            '"reasoning":"brief",'
            '"mcp_args":{},'
            '"scanners":["architecture"],'
            '"architecture_findings":[{"severity":"MAJOR|MEDIUM|MINOR","title":"...","description":"..."}],'
            '"done":false}\n'
            "MANDATORY RULES (never violate):\n"
            "1. You MUST include scanners=['architecture'] on every pass until architecture_ran=true.\n"
            "2. Set action=run_scanners when running the architecture analyzer.\n"
            "3. Do NOT set done=true until architecture_ran=true.\n"
            "4. Extract MCP findings with file paths; no vague summary-only titles.\n"
            "5. On pass >= 3 set mcp_args output_format=detailed."
        )
        user = (
            f"repo_path: {repo_path}\n"
            f"pass: {pass_num}\n"
            f"execution_id: {execution_id or 'none'}\n"
            f"steps_remaining: {steps_remaining}\n"
            f"architecture_ran: {architecture_ran}\n"
            f"mcp_response:\n{mcp_response_text[:12000]}\n"
        )
        if local_scan_output:
            user += f"\nlocal_scan_output:\n{local_scan_output[:8000]}\n"

        decision = self._complete(system, user)
        return enforce_architecture_decision(decision, pass_num, architecture_ran)

    def _complete(self, system: str, user: str) -> AgentDecision:
        if not self.api_key:
            raise AgentBrainError("GROQ_API_KEY not configured")

        last_error: Exception | None = None
        for attempt in range(1, MAX_LLM_RETRIES + 2):
            try:
                raw = self._call_groq(system, user)
                decision = self._parse_decision(raw)
                logger.info(
                    "Agent brain decision (attempt %d): action=%s done=%s scanners=%s",
                    attempt,
                    decision.action,
                    decision.done,
                    decision.scanners,
                )
                return decision
            except (AgentBrainError, ValidationError, json.JSONDecodeError) as exc:
                last_error = exc
                logger.warning("Agent brain parse failed (attempt %d): %s", attempt, exc)
                user += f"\nPrevious response was invalid JSON: {exc}. Return valid JSON only."

        raise AgentBrainError(f"Agent brain failed after retries: {last_error}")

    def _call_groq(self, system: str, user: str) -> str:
        import httpx

        payload = {
            "model": self.model,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        logger.info("Calling Groq model %s", self.model)
        response = httpx.post(
            GROQ_BASE_URL,
            headers=headers,
            json=payload,
            timeout=60.0,
        )
        if response.status_code >= 400:
            raise AgentBrainError(f"Groq API error {response.status_code}: {response.text[:500]}")

        data = response.json()
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise AgentBrainError(f"Unexpected Groq response shape: {data}") from exc

    def _call_groq_sync(self, system: str, user: str) -> str:
        """Public sync Groq call for verdict synthesis."""
        return self._call_groq(system, user)

    def _parse_decision(self, raw: str) -> AgentDecision:
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)

        data = json.loads(cleaned)
        decision = AgentDecision.model_validate(data)

        decision.scanners = [s for s in decision.scanners if s in ALLOWED_SCANNERS]
        return decision


def _mandatory_security_scanner_names(tool_status: dict[str, bool]) -> list[str]:
    scanners = ["bandit", "pip-audit"]
    if tool_status.get("semgrep"):
        scanners = ["semgrep", "pip-audit"]
    if tool_status.get("gitleaks"):
        scanners.insert(0, "gitleaks")
    return scanners


def _merge_scanners(requested: list[str], mandatory: list[str]) -> list[str]:
    merged: list[str] = []
    for name in mandatory + requested:
        if name in ALLOWED_SCANNERS and name not in merged:
            merged.append(name)
    return merged


def enforce_security_decision(
    decision: AgentDecision,
    phase: int,
    tool_status: dict[str, bool],
    security_scanners_ran: bool,
) -> AgentDecision:
    mandatory = _mandatory_security_scanner_names(tool_status)

    if phase >= 3 and not security_scanners_ran:
        decision.scanners = _merge_scanners(decision.scanners, mandatory)
        decision.action = "run_scanners"
        decision.done = False
        logger.info("Enforced mandatory security scanners at phase %d: %s", phase, decision.scanners)
    elif not security_scanners_ran and phase >= 2:
        decision.scanners = _merge_scanners(decision.scanners, mandatory)
        if decision.scanners:
            decision.action = "run_scanners"

    if not security_scanners_ran:
        decision.done = False

    decision.security_findings = [
        f for f in decision.security_findings if _is_real_finding(f)
    ]
    return decision


def enforce_architecture_decision(
    decision: AgentDecision,
    pass_num: int,
    architecture_ran: bool,
) -> AgentDecision:
    if not architecture_ran:
        decision.scanners = _merge_scanners(decision.scanners, ["architecture"])
        decision.action = "run_scanners"
        decision.done = False
        logger.info("Enforced mandatory architecture scanner at pass %d", pass_num)

    if pass_num >= 3 and "output_format" not in decision.mcp_args:
        decision.mcp_args["output_format"] = "detailed"

    if not architecture_ran:
        decision.done = False

    decision.architecture_findings = [
        f for f in decision.architecture_findings if _is_real_finding(f)
    ]
    return decision


def _is_real_finding(item: dict[str, str]) -> bool:
    title = (item.get("title") or "").lower()
    description = item.get("description") or ""
    vague_titles = {
        "bandit finding",
        "bandit findings",
        "pip-audit finding",
        "pip-audit findings",
        "finding",
        "findings",
        "local scan findings",
    }
    if title in vague_titles:
        return False
    if len(description) < 12:
        return False
    return True


def parse_agent_security_findings(items: list[dict[str, str]]) -> list[SecurityFinding]:
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    findings: list[SecurityFinding] = []
    for item in items:
        sev = mapping.get(str(item.get("severity", "MEDIUM")).upper(), Severity.MEDIUM)
        findings.append(
            SecurityFinding(
                severity=sev,
                title=item.get("title") or "Finding",
                description=item.get("description") or "",
            )
        )
    return findings


def parse_agent_architecture_findings(items: list[dict[str, str]]) -> list[ArchitectureFinding]:
    findings: list[ArchitectureFinding] = []
    severity_map = {
        "MAJOR": ArchitectureSeverity.MAJOR,
        "CRITICAL": ArchitectureSeverity.MAJOR,
        "HIGH": ArchitectureSeverity.MAJOR,
        "MEDIUM": ArchitectureSeverity.MEDIUM,
        "MINOR": ArchitectureSeverity.MINOR,
        "LOW": ArchitectureSeverity.MINOR,
    }
    for item in items:
        sev = severity_map.get(str(item.get("severity", "MEDIUM")).upper(), ArchitectureSeverity.MEDIUM)
        findings.append(
            ArchitectureFinding(
                severity=sev,
                title=item.get("title") or "Finding",
                description=item.get("description") or "",
            )
        )
    return findings
