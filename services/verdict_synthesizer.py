import json
import logging
import re
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from models import ArchitectureFinding, SecurityFinding, Verdict
from services.agent_brain import AgentBrain, AgentBrainError

logger = logging.getLogger(__name__)


class VerdictNarrative(BaseModel):
    summary: str
    root_cause: str = Field(alias="rootCause")
    impact: str
    confidence: float = Field(ge=0.0, le=1.0)

    model_config = {"populate_by_name": True}


def synthesize_verdict_narrative(
    *,
    security_findings: list[SecurityFinding],
    architecture_findings: list[ArchitectureFinding],
    security_score: int,
    architecture_score: int,
    overall_score: int,
    verdict: Verdict,
    repo_path: str,
) -> VerdictNarrative:
    """Produce summary/rootCause/impact/confidence via Groq, with rule-based fallback."""
    if AgentBrain.is_available():
        try:
            return _synthesize_with_groq(
                security_findings=security_findings,
                architecture_findings=architecture_findings,
                security_score=security_score,
                architecture_score=architecture_score,
                overall_score=overall_score,
                verdict=verdict,
                repo_path=repo_path,
            )
        except (AgentBrainError, ValidationError, json.JSONDecodeError) as exc:
            logger.warning("Groq verdict synthesis failed (%s); using fallback", exc)

    return _fallback_narrative(
        security_findings=security_findings,
        architecture_findings=architecture_findings,
        overall_score=overall_score,
        verdict=verdict,
        security_score=security_score,
        architecture_score=architecture_score,
    )


def _synthesize_with_groq(
    *,
    security_findings: list[SecurityFinding],
    architecture_findings: list[ArchitectureFinding],
    security_score: int,
    architecture_score: int,
    overall_score: int,
    verdict: Verdict,
    repo_path: str,
) -> VerdictNarrative:
    brain = AgentBrain()
    findings_payload = {
        "repo_path": repo_path,
        "verdict": "pass" if verdict == Verdict.APPROVE else "fail",
        "scores": {
            "security": security_score,
            "architecture": architecture_score,
            "overall": overall_score,
        },
        "security_findings": [
            {
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description[:500],
            }
            for f in security_findings
        ],
        "architecture_findings": [
            {
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description[:500],
            }
            for f in architecture_findings
        ],
    }

    system = (
        "You are MergeGuard AI summarizing a merge-readiness security and architecture scan.\n"
        "Given the findings JSON, write a clear executive verdict narrative.\n"
        "Respond with ONLY valid JSON:\n"
        '{"summary":"multi-sentence executive summary",'
        '"rootCause":"specific technical cause citing files/CVEs/rules",'
        '"impact":"business/user impact if merged",'
        '"confidence":0.92}\n'
        "Rules:\n"
        "- summary: 3-5 sentences, 250-500 chars. Cover verdict, top risks, scan scope, and score context.\n"
        "- Mention specific finding titles/CVEs where relevant; avoid one-line headlines.\n"
        "- rootCause: reference the highest-severity real finding with technical detail\n"
        "- impact: explain merge risk in plain language (2-3 sentences)\n"
        "- confidence: float 0.0-1.0 based on evidence quality and score\n"
        "- If verdict is pass with no findings, explain why merge looks safe and what was checked"
    )
    user = json.dumps(findings_payload, indent=2)

    raw = brain._call_groq_sync(system, user)
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)

    data: dict[str, Any] = json.loads(cleaned)
    narrative = VerdictNarrative.model_validate(data)
    logger.info("Groq verdict narrative: summary=%r confidence=%.2f", narrative.summary[:80], narrative.confidence)
    return narrative


def _build_long_summary(
    *,
    verdict: Verdict,
    security_findings: list[SecurityFinding],
    architecture_findings: list[ArchitectureFinding],
    security_score: int,
    architecture_score: int,
    overall_score: int,
) -> str:
    passed = verdict == Verdict.APPROVE
    verdict_label = "approved for merge" if passed else "blocked from merge"
    parts = [
        f"MergeGuard analysis {verdict_label} this pull request with an overall score of {overall_score}/100 "
        f"(security {security_score}/100, architecture {architecture_score}/100)."
    ]

    if security_findings:
        top = security_findings[:3]
        finding_lines = "; ".join(
            f"{f.title} ({f.severity.value})" for f in top
        )
        parts.append(
            f"Security scanning flagged {len(security_findings)} issue(s); "
            f"the most relevant are: {finding_lines}."
        )
    else:
        parts.append(
            "No security findings exceeded blocking thresholds in dependency, secret, or SAST scans."
        )

    if architecture_findings:
        top = architecture_findings[:2]
        arch_lines = "; ".join(f"{f.title} ({f.severity.value})" for f in top)
        parts.append(
            f"Architecture heuristics reported {len(architecture_findings)} note(s), including {arch_lines}."
        )
    else:
        parts.append("Architecture checks did not surface structural regressions in the scanned paths.")

    if passed:
        parts.append(
            "Residual findings were reviewed against MergeGuard thresholds and did not meet criteria for a hard block."
        )
    else:
        parts.append(
            "One or more findings exceed MergeGuard blocking thresholds and should be remediated before merge."
        )

    return " ".join(parts)


def _fallback_narrative(
    *,
    security_findings: list[SecurityFinding],
    architecture_findings: list[ArchitectureFinding],
    overall_score: int,
    verdict: Verdict,
    security_score: int = 0,
    architecture_score: int = 0,
) -> VerdictNarrative:
    top_security = security_findings[0] if security_findings else None
    top_arch = architecture_findings[0] if architecture_findings else None

    summary = _build_long_summary(
        verdict=verdict,
        security_findings=security_findings,
        architecture_findings=architecture_findings,
        security_score=security_score,
        architecture_score=architecture_score,
        overall_score=overall_score,
    )

    if verdict == Verdict.APPROVE and not security_findings and not architecture_findings:
        return VerdictNarrative(
            summary=summary,
            rootCause="No critical or high-severity findings in bandit, dependency, or architecture checks.",
            impact=(
                "Low merge risk based on scanned paths. No exploitable defects or structural regressions "
                "were identified at blocking severity. Standard post-merge monitoring is still recommended."
            ),
            confidence=min(0.95, max(0.6, overall_score / 100)),
        )

    primary = top_security or top_arch
    if primary is None:
        return VerdictNarrative(
            summary=summary,
            rootCause="Insufficient actionable findings to identify a single root cause.",
            impact="Review recommended before merge.",
            confidence=max(0.5, overall_score / 100),
        )

    passed = verdict == Verdict.APPROVE
    return VerdictNarrative(
        summary=summary,
        rootCause=primary.description[:400],
        impact=(
            "Security or architecture regressions may reach production if merged, including exposure from "
            "vulnerable dependencies or unresolved structural issues."
            if not passed
            else (
                "Residual findings are present but below blocking thresholds. Monitor dependency updates "
                "and re-scan after merge to catch drift."
            )
        ),
        confidence=min(0.99, max(0.55, overall_score / 100)),
    )
