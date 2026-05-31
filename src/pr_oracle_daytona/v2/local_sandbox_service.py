import shutil
import subprocess
import time
import uuid
from pathlib import Path

from pr_oracle_daytona.command_utils import (
    build_tokenized_github_url,
    redact_secret,
    safe_repo_url,
    sanitize_command,
)
from pr_oracle_daytona.models import CommandLog
from pr_oracle_daytona.settings import Settings
from pr_oracle_daytona.v2.merge_steps import (
    default_sandbox_branch_name,
    extract_base_info,
    extract_merge_branch,
    merge_step_command,
    merge_step_log_name,
    parse_repo_owner_name,
    workspace_folder_name,
)
from pr_oracle_daytona.v2.models import (
    V2JobDetails,
    V2SandboxInfo,
    V2SandboxRequest,
    V2SandboxResponse,
    V2SandboxUrls,
    utc_now_iso,
)
from pr_oracle_daytona.v2.store import save_v2_run

GITHUB_PUSH_DISABLED_MSG = (
    "GitHub push disabled for hackathon safety. "
    "Virtual merged state exists only inside the local workspace."
)


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _sandboxes_root() -> Path:
    return _project_root() / ".local" / "sandboxes"


def _secrets(settings: Settings) -> list[str]:
    return [value for value in (settings.github_token, settings.daytona_api_key) if value]


def _run_shell(
    step: str,
    command: str,
    cwd: Path,
    secrets: list[str],
) -> CommandLog:
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            shell=True,
            capture_output=True,
            text=True,
            check=False,
        )
        output_parts = [part for part in (result.stdout, result.stderr) if part]
        raw_output = "\n".join(output_parts).strip() or "(no output)"
        duration_ms = int((time.perf_counter() - started) * 1000)
        return CommandLog(
            step=step,
            command=sanitize_command(command, secrets),
            exit_code=result.returncode,
            output=redact_secret(raw_output, secrets),
            duration_ms=duration_ms,
        )
    except Exception as exc:
        duration_ms = int((time.perf_counter() - started) * 1000)
        return CommandLog(
            step=step,
            command=sanitize_command(command, secrets),
            exit_code=1,
            output=redact_secret(str(exc), secrets),
            duration_ms=duration_ms,
        )


def _build_urls(run_id: str) -> V2SandboxUrls:
    return V2SandboxUrls(
        detail_url=f"/v2/sandbox/{run_id}",
        logs_url=f"/v2/sandbox/{run_id}/logs",
        status_url=f"/v2/sandbox/{run_id}/status",
        delete_url=f"/v2/sandbox/{run_id}",
    )


def _build_details(
    req: V2SandboxRequest,
    *,
    merge_steps_executed: int,
    started_at: str,
    duration_ms: int,
) -> V2JobDetails:
    owner, name = parse_repo_owner_name(req.repo_url)
    base_branch, _ = extract_base_info(req.merge_steps)
    return V2JobDetails(
        description=req.description,
        pr_numbers=req.pr_numbers,
        repo_url=safe_repo_url(req.repo_url),
        repo_owner=owner,
        repo_name=name,
        base_branch=base_branch,
        merge_branch=extract_merge_branch(req.merge_steps),
        merge_steps_executed=merge_steps_executed,
        merge_steps_total=len(req.merge_steps),
        created_at=started_at,
        duration_ms=duration_ms,
    )


class LocalSandboxService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()

    def create_sandbox(self, req: V2SandboxRequest) -> V2SandboxResponse:
        run_id = str(uuid.uuid4())
        started = time.perf_counter()
        started_at = utc_now_iso()
        secrets = _secrets(self.settings)
        merged_prs: list[int] = []
        logs: list[CommandLog] = []
        folder_name = workspace_folder_name(req)
        workspace_path = _sandboxes_root() / folder_name
        repo_path = workspace_path / "repo"
        branch_name = default_sandbox_branch_name(req)
        base_branch, base_commit_sha = extract_base_info(req.merge_steps)
        merge_branch = extract_merge_branch(req.merge_steps)
        merge_steps_executed = 0

        def finish(
            status: str,
            failed_step: str | None = None,
            failed_pr: int | None = None,
        ) -> V2SandboxResponse:
            duration_ms = int((time.perf_counter() - started) * 1000)
            response = V2SandboxResponse(
                run_id=run_id,
                job_id=req.job_id,
                status=status,
                merged_prs=merged_prs,
                failed_step=failed_step,
                failed_pr=failed_pr,
                sandbox=V2SandboxInfo(
                    mode="local",
                    sandbox_id=None,
                    workspace_path=str(workspace_path.resolve()),
                    repo_path=str(repo_path.resolve()) if repo_path.exists() else str(repo_path.resolve()),
                    sandbox_url=None,
                    preview_url=None,
                    branch_name=branch_name if status == "merged" else None,
                    base_branch=base_branch,
                    base_commit_sha=base_commit_sha,
                    merge_branch=merge_branch,
                    pushed_to_github=False,
                ),
                details=_build_details(
                    req,
                    merge_steps_executed=merge_steps_executed,
                    started_at=started_at,
                    duration_ms=duration_ms,
                ),
                logs=logs,
                urls=_build_urls(run_id),
            )
            save_v2_run(response)
            return response

        if workspace_path.exists():
            logs.append(
                CommandLog(
                    step="workspace_create",
                    command=f"reuse existing {workspace_path}",
                    exit_code=0,
                    output=f"Using existing workspace {workspace_path}",
                    duration_ms=0,
                )
            )
        else:
            workspace_path.mkdir(parents=True, exist_ok=True)
            logs.append(
                CommandLog(
                    step="workspace_create",
                    command=f"mkdir {workspace_path}",
                    exit_code=0,
                    output=f"Created workspace {workspace_path}",
                    duration_ms=0,
                )
            )

        if not repo_path.exists():
            tokenized_url = build_tokenized_github_url(
                req.repo_url, self.settings.github_token
            )
            clone_cmd = f'git clone "{tokenized_url}" "{repo_path.name}"'
            clone_log = _run_shell("clone", clone_cmd, workspace_path, secrets)
            logs.append(clone_log)
            if clone_log.exit_code != 0:
                return finish("clone_failed", failed_step="clone")
        else:
            logs.append(
                CommandLog(
                    step="clone",
                    command=f"reuse existing {repo_path}",
                    exit_code=0,
                    output=f"Repository already present at {repo_path}",
                    duration_ms=0,
                )
            )

        for merge_step in req.merge_steps:
            command = merge_step_command(merge_step, base_branch)
            step_log = _run_shell(
                merge_step_log_name(merge_step),
                command,
                repo_path,
                secrets,
            )
            logs.append(step_log)
            merge_steps_executed += 1
            if step_log.exit_code != 0:
                status_map = {
                    "checkout_base": "checkout_base_failed",
                    "fetch_pr": "pr_fetch_failed",
                    "merge_pr": "merge_failed",
                }
                return finish(
                    status_map[merge_step.step_type],
                    failed_step=merge_step.step_type,
                    failed_pr=merge_step.pr_number,
                )
            if merge_step.step_type == "merge_pr" and merge_step.pr_number:
                merged_prs.append(merge_step.pr_number)

        branch_log = _run_shell(
            "sandbox_branch",
            f"git checkout -b {branch_name}",
            repo_path,
            secrets,
        )
        logs.append(branch_log)
        if branch_log.exit_code != 0:
            return finish("merge_failed", failed_step="sandbox_branch")

        if req.should_push_to_github:
            logs.append(
                CommandLog(
                    step="github_push",
                    command="git push origin (disabled)",
                    exit_code=0,
                    output=GITHUB_PUSH_DISABLED_MSG,
                    duration_ms=0,
                )
            )

        return finish("merged")

    def delete_sandbox(self, run: V2SandboxResponse) -> bool:
        workspace = Path(run.sandbox.workspace_path)
        if workspace.exists():
            shutil.rmtree(workspace, ignore_errors=True)
            return True
        return False
