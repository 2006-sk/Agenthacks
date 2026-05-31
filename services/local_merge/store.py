import logging
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator

from services.local_merge.sandbox_service import MergeSandboxResult

logger = logging.getLogger(__name__)

_RUNS: dict[str, MergeSandboxResult] = {}


class SandboxStatusResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    run_id: str = Field(..., alias="runId")
    sandbox_id: str = Field(..., alias="sandboxId")
    status: str
    repo_path: str = Field(..., alias="repoPath")
    workspace_path: str = Field(..., alias="workspacePath")
    sandbox_url: str = Field(..., alias="sandboxUrl")
    ready: bool


def save_run(result: MergeSandboxResult) -> None:
    _RUNS[result.run_id] = result


def get_run(run_id: str) -> MergeSandboxResult | None:
    return _RUNS.get(run_id)


def delete_run(run_id: str) -> MergeSandboxResult | None:
    return _RUNS.pop(run_id, None)


def get_status(run_id: str) -> SandboxStatusResponse | None:
    run = get_run(run_id)
    if run is None:
        return None
    return SandboxStatusResponse(
        runId=run.run_id,
        sandboxId=run.sandbox_id,
        status=run.status,
        repoPath=run.repo_path,
        workspacePath=run.workspace_path,
        sandboxUrl=run.sandbox_url,
        ready=run.status == "merged",
    )
