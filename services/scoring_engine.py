import logging
import secrets
from datetime import datetime, timezone

from models import (
    AnalyzeRequest,
    ArchitectureFinding,
    SecurityFinding,
    Verdict,
    VerdictOutcome,
    VerdictResponse,
)
from services.finding_filters import filter_architecture_findings, filter_security_findings
from services.verdict_synthesizer import synthesize_verdict_narrative

logger = logging.getLogger(__name__)

SECURITY_PENALTIES = {
    "CRITICAL": 30,
    "HIGH": 15,
    "MEDIUM": 5,
    "LOW": 1,
}

ARCHITECTURE_PENALTIES = {
    "MAJOR": 20,
    "MEDIUM": 10,
    "MINOR": 5,
}


def compute_security_score(findings: list[SecurityFinding]) -> int:
    score = 100
    for finding in findings:
        score -= SECURITY_PENALTIES.get(finding.severity.value, 0)
    return max(0, min(100, score))


def compute_architecture_score(findings: list[ArchitectureFinding]) -> int:
    score = 100
    for finding in findings:
        score -= ARCHITECTURE_PENALTIES.get(finding.severity.value, 0)
    return max(0, min(100, score))


def compute_overall_score(security_score: int, architecture_score: int) -> int:
    return round((security_score + architecture_score) / 2)


def compute_verdict(
    security_findings: list[SecurityFinding],
    security_score: int,
    architecture_score: int,
) -> Verdict:
    critical_count = sum(1 for f in security_findings if f.severity.value == "CRITICAL")
    if critical_count > 0:
        return Verdict.BLOCK
    if security_score < 50 or architecture_score < 50:
        return Verdict.BLOCK
    return Verdict.APPROVE


def build_verdict_response(
    request: AnalyzeRequest,
    security_findings: list[SecurityFinding],
    architecture_findings: list[ArchitectureFinding],
    *,
    repo_path: str,
) -> VerdictResponse:
    logger.info("Verdict generation started")

    security_findings = filter_security_findings(security_findings)
    architecture_findings = filter_architecture_findings(architecture_findings)

    security_score = compute_security_score(security_findings)
    architecture_score = compute_architecture_score(architecture_findings)
    overall_score = compute_overall_score(security_score, architecture_score)
    internal_verdict = compute_verdict(security_findings, security_score, architecture_score)

    logger.info(
        "Scores computed: security=%d architecture=%d overall=%d verdict=%s",
        security_score,
        architecture_score,
        overall_score,
        internal_verdict.value,
    )

    narrative = synthesize_verdict_narrative(
        security_findings=security_findings,
        architecture_findings=architecture_findings,
        security_score=security_score,
        architecture_score=architecture_score,
        overall_score=overall_score,
        verdict=internal_verdict,
        repo_path=repo_path,
    )

    outcome = VerdictOutcome.PASS if internal_verdict == Verdict.APPROVE else VerdictOutcome.FAIL
    verdict_id = f"vrd_{secrets.token_hex(12)}"
    predicted_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return VerdictResponse(
        schema_version=1,
        pr_number=request.pr_number,
        head_sha=request.head_sha,
        verdict=outcome,
        confidence=round(narrative.confidence, 2),
        summary=narrative.summary,
        root_cause=narrative.root_cause,
        impact=narrative.impact,
        evidence_url=request.sandbox_url,
        predicted_at=predicted_at,
        verdict_id=verdict_id,
    )
