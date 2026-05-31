from enum import Enum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ArchitectureSeverity(str, Enum):
    MAJOR = "MAJOR"
    MEDIUM = "MEDIUM"
    MINOR = "MINOR"


class Verdict(str, Enum):
    APPROVE = "APPROVE"
    BLOCK = "BLOCK"


class AnalyzeRequest(BaseModel):
    """P1+P2+P3 unified request: merge a public PR locally, then analyze merged repo."""

    model_config = ConfigDict(populate_by_name=True)

    # P1/P2 — virtual merge (preferred)
    repo_url: str | None = Field(
        None,
        alias="repoUrl",
        description="Public GitHub repo URL to clone and merge",
    )
    pr_number: int = Field(..., alias="prNumber", description="Pull request number")
    base_branch: str = Field("main", alias="baseBranch", description="Base branch to merge into")
    head_sha: str = Field("unknown", alias="headSha", description="Optional PR HEAD SHA")
    job_id: str | None = Field(None, alias="jobId", description="Caller job identifier")

    # Dev override — skip merge, analyze existing folder directly
    repo_path: str | None = Field(
        None,
        alias="repoPath",
        description="Direct path to merged repo (skips clone/merge when set with repoUrl omitted)",
    )

    # Sandbox metadata (auto-generated during merge if omitted)
    sandbox_id: str | None = Field(None, alias="sandboxId")
    sandbox_url: str | None = Field(None, alias="sandboxUrl")

    keep_sandbox: bool = Field(
        False,
        alias="keepSandbox",
        description="If true, do not delete local workspace after analyze",
    )

    @model_validator(mode="after")
    def validate_input_mode(self) -> Self:
        has_merge = bool(self.repo_url and self.repo_url.strip())
        has_path = bool(self.repo_path and self.repo_path.strip())
        if not has_merge and not has_path:
            raise ValueError("Provide repoUrl for merge flow or repoPath for direct analyze")
        if has_merge and has_path:
            raise ValueError("Provide repoUrl or repoPath, not both")
        if self.pr_number <= 0:
            raise ValueError("prNumber must be a positive integer")
        return self

    @property
    def uses_merge_flow(self) -> bool:
        return bool(self.repo_url and self.repo_url.strip())


class VerdictOutcome(str, Enum):
    PASS = "pass"
    FAIL = "fail"


class VerdictResponse(BaseModel):
    """MergeGuard PR verdict envelope (schemaVersion 1)."""

    model_config = ConfigDict(populate_by_name=True)

    schema_version: int = Field(1, alias="schemaVersion")
    pr_number: int = Field(..., alias="prNumber")
    head_sha: str = Field(..., alias="headSha")
    verdict: VerdictOutcome
    confidence: float = Field(..., ge=0.0, le=1.0)
    security_score: int = Field(..., ge=0, le=100, alias="securityScore")
    architecture_score: int = Field(..., ge=0, le=100, alias="architectureScore")
    summary: str
    root_cause: str = Field(..., alias="rootCause")
    impact: str
    evidence_url: str = Field(..., alias="evidenceUrl")
    predicted_at: str = Field(..., alias="predictedAt")
    verdict_id: str = Field(..., alias="verdictId")


class SecurityFinding(BaseModel):
    severity: Severity
    title: str
    description: str


class ArchitectureFinding(BaseModel):
    severity: ArchitectureSeverity
    title: str
    description: str


class AnalysisMode(str, Enum):
    LIVE = "live"
    PARTIAL = "partial"
    MOCK = "mock"


class ScanEngine(str, Enum):
    AGENT = "agent"
    ORCHESTRATOR = "orchestrator"
    MOCK = "mock"


class AnalyzeResponse(BaseModel):
    mode: AnalysisMode
    engine: ScanEngine = Field(
        default=ScanEngine.MOCK,
        description="Which scan brain ran: agent (Groq), orchestrator, or mock",
    )
    security_score: int = Field(..., ge=0, le=100)
    architecture_score: int = Field(..., ge=0, le=100)
    overall_score: int = Field(..., ge=0, le=100)
    verdict: Verdict
    security_findings: list[SecurityFinding]
    architecture_findings: list[ArchitectureFinding]
