from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic.alias_generators import to_camel

from pr_oracle_daytona.models import CommandLog

CamelModelConfig = ConfigDict(
    alias_generator=to_camel,
    populate_by_name=True,
    serialize_by_alias=True,
)


class V2MergeStep(BaseModel):
    model_config = CamelModelConfig

    step: int | None = None
    step_type: Literal["checkout_base", "fetch_pr", "merge_pr"] = Field(alias="type")
    branch: str | None = None
    commit_sha: str | None = None
    pr_number: int | None = None
    local_branch: str | None = None
    git_ref: str | None = None

    @model_validator(mode="after")
    def validate_step_fields(self) -> "V2MergeStep":
        if self.step_type == "checkout_base":
            if not self.branch and not self.commit_sha:
                raise ValueError("checkout_base step must include branch or commitSha")
        elif self.step_type == "fetch_pr":
            if self.pr_number is None or not self.local_branch or not self.git_ref:
                raise ValueError(
                    "fetch_pr step must include prNumber, localBranch, and gitRef"
                )
        elif self.step_type == "merge_pr":
            if self.pr_number is None or not self.local_branch:
                raise ValueError("merge_pr step must include prNumber and localBranch")
        return self


class V2SandboxRequest(BaseModel):
    model_config = CamelModelConfig

    repo_url: str
    job_id: str
    description: str | None = None
    pr_numbers: list[int]
    merge_steps: list[V2MergeStep]
    sandbox_branch_name: str | None = None
    should_push_to_github: bool = False
    mode: Literal["local", "daytona"] = "local"

    @field_validator("repo_url", "job_id")
    @classmethod
    def validate_required_strings(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("field must not be empty")
        return value.strip()

    @field_validator("pr_numbers")
    @classmethod
    def validate_pr_numbers(cls, value: list[int]) -> list[int]:
        if not value:
            raise ValueError("prNumbers must contain at least one positive integer")
        for pr in value:
            if pr <= 0:
                raise ValueError("prNumbers must contain positive integers")
        return value

    @model_validator(mode="after")
    def normalize_merge_steps(self) -> "V2SandboxRequest":
        if not self.merge_steps:
            raise ValueError("mergeSteps must not be empty")
        numbered: list[V2MergeStep] = []
        for index, merge_step in enumerate(self.merge_steps, start=1):
            numbered.append(
                merge_step.model_copy(update={"step": merge_step.step or index})
            )
        self.merge_steps = sorted(numbered, key=lambda item: item.step or 0)
        return self


class V2SandboxInfo(BaseModel):
    model_config = CamelModelConfig

    mode: Literal["local", "daytona"]
    sandbox_id: str | None = None
    workspace_path: str
    repo_path: str
    sandbox_url: str | None = None
    preview_url: str | None = None
    branch_name: str | None = None
    base_branch: str | None = None
    base_commit_sha: str | None = None
    merge_branch: str | None = None
    pushed_to_github: bool = False


class V2JobDetails(BaseModel):
    model_config = CamelModelConfig

    description: str | None = None
    pr_numbers: list[int]
    repo_url: str
    repo_owner: str
    repo_name: str
    base_branch: str | None = None
    merge_branch: str | None = None
    merge_steps_executed: int
    merge_steps_total: int
    created_at: str
    duration_ms: int


class V2SandboxUrls(BaseModel):
    model_config = CamelModelConfig

    detail_url: str
    logs_url: str
    status_url: str
    delete_url: str


class V2SandboxResponse(BaseModel):
    model_config = CamelModelConfig

    run_id: str
    job_id: str
    status: str
    merged_prs: list[int]
    failed_step: str | None = None
    failed_pr: int | None = None
    sandbox: V2SandboxInfo
    details: V2JobDetails
    logs: list[CommandLog]
    urls: V2SandboxUrls


class V2StatusResponse(BaseModel):
    model_config = CamelModelConfig

    run_id: str
    job_id: str
    status: str
    sandbox: V2SandboxInfo
    ready: bool


class V2LogsResponse(BaseModel):
    model_config = CamelModelConfig

    run_id: str
    job_id: str
    status: str
    logs: list[CommandLog]


class V2DeleteResponse(BaseModel):
    model_config = CamelModelConfig

    run_id: str
    job_id: str
    deleted: bool
    message: str


def utc_now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()
