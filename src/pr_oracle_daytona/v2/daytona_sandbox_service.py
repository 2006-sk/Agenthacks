import time
import uuid
from typing import Any

from pr_oracle_daytona.command_utils import (
    build_tokenized_github_url,
    redact_secret,
    safe_repo_url,
)
from pr_oracle_daytona.daytona_utils import (
    create_daytona_client,
    create_sandbox,
    run_command,
    secrets_list,
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
    "Virtual merged state exists only inside Daytona sandbox."
)


def _daytona_workspace_root(req: V2SandboxRequest) -> str:
    return f"/workspace/pr-oracle/{workspace_folder_name(req)}"


def _daytona_repo_dir(req: V2SandboxRequest) -> str:
    return f"{_daytona_workspace_root(req)}/repo"


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


class DaytonaSandboxService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()

    def create_sandbox(self, req: V2SandboxRequest) -> V2SandboxResponse:
        if self.settings.daytona_mock_mode:
            return self._mock_create(req)

        run_id = str(uuid.uuid4())
        started = time.perf_counter()
        started_at = utc_now_iso()
        secrets = secrets_list(self.settings)
        merged_prs: list[int] = []
        logs: list[CommandLog] = []
        sandbox: Any | None = None
        sandbox_id: str | None = None
        workspace_root = _daytona_workspace_root(req)
        repo_dir = _daytona_repo_dir(req)
        branch_name = default_sandbox_branch_name(req)
        base_branch, base_commit_sha = extract_base_info(req.merge_steps)
        merge_branch = extract_merge_branch(req.merge_steps)
        merge_steps_executed = 0

        def finish(
            status: str,
            failed_step: str | None = None,
            failed_pr: int | None = None,
            *,
            branch: str | None = None,
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
                    mode="daytona",
                    sandbox_id=sandbox_id,
                    workspace_path=workspace_root,
                    repo_path=repo_dir,
                    sandbox_url=None,
                    preview_url=None,
                    branch_name=branch,
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

        try:
            daytona = create_daytona_client(self.settings)
            sandbox = create_sandbox(daytona, self.settings)
            sandbox_id = getattr(sandbox, "id", None) or getattr(
                sandbox, "sandbox_id", None
            )
            logs.append(
                CommandLog(
                    step="sandbox_create",
                    command="daytona.create()",
                    exit_code=0,
                    output=f"Sandbox created: {sandbox_id}",
                    duration_ms=0,
                )
            )
        except Exception as exc:
            logs.append(
                CommandLog(
                    step="sandbox_create",
                    command="daytona.create()",
                    exit_code=1,
                    output=redact_secret(str(exc), secrets),
                    duration_ms=0,
                )
            )
            return finish("sandbox_create_failed", failed_step="sandbox_create")

        logs.append(
            run_command(sandbox, "workspace", f"mkdir -p {workspace_root}", secrets)
        )

        tokenized_url = build_tokenized_github_url(req.repo_url, self.settings.github_token)
        clone_cmd = f'cd {workspace_root} && git clone "{tokenized_url}" repo'
        clone_log = run_command(sandbox, "clone", clone_cmd, secrets)
        logs.append(clone_log)
        if clone_log.exit_code != 0:
            return finish("clone_failed", failed_step="clone")

        for merge_step in req.merge_steps:
            command = f"cd {repo_dir} && {merge_step_command(merge_step, base_branch)}"
            step_log = run_command(
                sandbox,
                merge_step_log_name(merge_step),
                command,
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

        branch_cmd = f"cd {repo_dir} && git checkout -b {branch_name}"
        branch_log = run_command(sandbox, "sandbox_branch", branch_cmd, secrets)
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

        return finish("merged", branch=branch_name)

    def delete_sandbox(self, run: V2SandboxResponse) -> bool:
        sandbox_id = run.sandbox.sandbox_id
        if not sandbox_id or self.settings.daytona_mock_mode:
            return True
        try:
            daytona = create_daytona_client(self.settings)
            sandbox = daytona.get(sandbox_id)
            daytona.delete(sandbox)
            return True
        except Exception:
            return False

    def _mock_create(self, req: V2SandboxRequest) -> V2SandboxResponse:
        run_id = str(uuid.uuid4())
        started_at = utc_now_iso()
        short_id = run_id.split("-")[0]
        sandbox_id = f"mock-sandbox-{short_id}"
        workspace_root = _daytona_workspace_root(req)
        repo_dir = _daytona_repo_dir(req)
        branch_name = default_sandbox_branch_name(req)
        base_branch, base_commit_sha = extract_base_info(req.merge_steps)
        merge_branch = extract_merge_branch(req.merge_steps)
        preview_url = "http://localhost:3000"
        safe_url = safe_repo_url(req.repo_url)

        logs: list[CommandLog] = [
            CommandLog(
                step="sandbox_create",
                command="daytona.create() [mock]",
                exit_code=0,
                output=f"Mock sandbox created: {sandbox_id}",
                duration_ms=120,
            ),
            CommandLog(
                step="workspace",
                command=f"mkdir -p {workspace_root}",
                exit_code=0,
                output=f"Created workspace {workspace_root}",
                duration_ms=10,
            ),
            CommandLog(
                step="clone",
                command=f"git clone {safe_url} repo",
                exit_code=0,
                output=f"Cloned {safe_url} into {repo_dir}",
                duration_ms=850,
            ),
        ]

        merged_prs: list[int] = []
        for merge_step in req.merge_steps:
            command = merge_step_command(merge_step, base_branch)
            logs.append(
                CommandLog(
                    step=merge_step_log_name(merge_step),
                    command=command,
                    exit_code=0,
                    output=f"Mock executed {merge_step.step_type}",
                    duration_ms=200,
                )
            )
            if merge_step.step_type == "merge_pr" and merge_step.pr_number:
                merged_prs.append(merge_step.pr_number)

        logs.append(
            CommandLog(
                step="sandbox_branch",
                command=f"git checkout -b {branch_name}",
                exit_code=0,
                output=f"Created sandbox branch {branch_name}",
                duration_ms=90,
            )
        )
        logs.append(
            CommandLog(
                step="preview",
                command="create_signed_preview_url(3000) [mock]",
                exit_code=0,
                output="Mock signed preview URL generated",
                duration_ms=50,
            )
        )

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

        response = V2SandboxResponse(
            run_id=run_id,
            job_id=req.job_id,
            status="merged",
            merged_prs=merged_prs,
            failed_step=None,
            failed_pr=None,
            sandbox=V2SandboxInfo(
                mode="daytona",
                sandbox_id=sandbox_id,
                workspace_path=workspace_root,
                repo_path=repo_dir,
                sandbox_url=preview_url,
                preview_url=preview_url,
                branch_name=branch_name,
                base_branch=base_branch,
                base_commit_sha=base_commit_sha,
                merge_branch=merge_branch,
                pushed_to_github=False,
            ),
            details=_build_details(
                req,
                merge_steps_executed=len(req.merge_steps),
                started_at=started_at,
                duration_ms=1200,
            ),
            logs=logs,
            urls=_build_urls(run_id),
        )
        save_v2_run(response)
        return response
