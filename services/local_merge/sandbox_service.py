import logging
import os
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SANDBOXES_ROOT = PROJECT_ROOT / ".local" / "sandboxes"
DEFAULT_BASE_URL = os.getenv("MERGEGUARD_BASE_URL", "http://127.0.0.1:8000")


@dataclass
class CommandLog:
    step: str
    command: str
    exit_code: int
    output: str
    duration_ms: int


@dataclass
class MergeSandboxResult:
    run_id: str
    job_id: str
    repo_path: str
    workspace_path: str
    sandbox_id: str
    sandbox_url: str
    status: str
    merged_prs: list[int]
    logs: list[CommandLog]


def sandboxes_root() -> Path:
    return SANDBOXES_ROOT


def normalize_public_clone_url(repo_url: str) -> str:
    url = repo_url.strip().rstrip("/")
    if url.endswith(".git"):
        return url
    return f"{url}.git"


def parse_repo_owner_name(repo_url: str) -> tuple[str, str]:
    parsed = urlparse(repo_url.rstrip("/"))
    path = parsed.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = path.split("/")
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return "unknown", path or "unknown"


def _run_shell(step: str, command: str, cwd: Path) -> CommandLog:
    started = time.perf_counter()
    logger.info("Local merge [%s]: %s", step, command)
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            shell=True,
            capture_output=True,
            text=True,
            check=False,
        )
        output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
        return CommandLog(
            step=step,
            command=command,
            exit_code=result.returncode,
            output=output or "(no output)",
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
    except OSError as exc:
        return CommandLog(
            step=step,
            command=command,
            exit_code=1,
            output=str(exc),
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


class LocalMergeSandbox:
    """P1/P2: clone public GitHub repo locally, virtual-merge PR branch, return repo_path."""

    def create_and_merge(
        self,
        *,
        repo_url: str,
        pr_number: int,
        base_branch: str = "main",
        job_id: str | None = None,
        head_sha: str | None = None,
        base_url: str | None = None,
    ) -> MergeSandboxResult:
        if pr_number <= 0:
            raise ValueError("prNumber must be a positive integer")

        run_id = str(uuid.uuid4())
        resolved_job_id = job_id or f"job-pr-{pr_number}"
        folder_name = f"pr-{pr_number}"
        workspace_path = sandboxes_root() / folder_name
        repo_path = workspace_path / "repo"
        sandbox_branch = f"sandbox/pr-{pr_number}"
        local_pr_branch = f"pr-{pr_number}"
        logs: list[CommandLog] = []
        base = (base_url or DEFAULT_BASE_URL).rstrip("/")

        if workspace_path.exists():
            self.delete_workspace(workspace_path)

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

        clone_url = normalize_public_clone_url(repo_url)
        clone_cmd = f'git clone "{clone_url}" "{repo_path.name}"'
        clone_log = _run_shell("clone", clone_cmd, workspace_path)
        logs.append(clone_log)
        if clone_log.exit_code != 0:
            return self._failed_result(
                run_id=run_id,
                job_id=resolved_job_id,
                workspace_path=workspace_path,
                repo_path=repo_path,
                base_url=base,
                status="clone_failed",
                logs=logs,
            )

        if head_sha and head_sha != "unknown":
            checkout_cmd = f"git checkout {head_sha}"
        else:
            checkout_cmd = f"git checkout {base_branch}"
        checkout_log = _run_shell("checkout_base", checkout_cmd, repo_path)
        logs.append(checkout_log)
        if checkout_log.exit_code != 0:
            return self._failed_result(
                run_id=run_id,
                job_id=resolved_job_id,
                workspace_path=workspace_path,
                repo_path=repo_path,
                base_url=base,
                status="checkout_base_failed",
                logs=logs,
            )

        fetch_cmd = f"git fetch origin pull/{pr_number}/head:{local_pr_branch}"
        fetch_log = _run_shell("fetch_pr", fetch_cmd, repo_path)
        logs.append(fetch_log)
        if fetch_log.exit_code != 0:
            return self._failed_result(
                run_id=run_id,
                job_id=resolved_job_id,
                workspace_path=workspace_path,
                repo_path=repo_path,
                base_url=base,
                status="pr_fetch_failed",
                logs=logs,
            )

        merge_cmd = f"git merge --no-edit {local_pr_branch}"
        merge_log = _run_shell("merge_pr", merge_cmd, repo_path)
        logs.append(merge_log)
        if merge_log.exit_code != 0:
            return self._failed_result(
                run_id=run_id,
                job_id=resolved_job_id,
                workspace_path=workspace_path,
                repo_path=repo_path,
                base_url=base,
                status="merge_failed",
                logs=logs,
            )

        branch_log = _run_shell(
            "sandbox_branch",
            f"git checkout -b {sandbox_branch}",
            repo_path,
        )
        logs.append(branch_log)
        if branch_log.exit_code != 0:
            return self._failed_result(
                run_id=run_id,
                job_id=resolved_job_id,
                workspace_path=workspace_path,
                repo_path=repo_path,
                base_url=base,
                status="sandbox_branch_failed",
                logs=logs,
            )

        logger.info(
            "Local merge complete: run_id=%s repo_path=%s pr=%d",
            run_id,
            repo_path,
            pr_number,
        )
        return MergeSandboxResult(
            run_id=run_id,
            job_id=resolved_job_id,
            repo_path=str(repo_path.resolve()),
            workspace_path=str(workspace_path.resolve()),
            sandbox_id=run_id,
            sandbox_url=f"{base}/sandboxes/{run_id}",
            status="merged",
            merged_prs=[pr_number],
            logs=logs,
        )

    def delete_workspace(self, workspace_path: str | Path) -> bool:
        path = Path(workspace_path)
        if not path.exists():
            return True
        import shutil

        shutil.rmtree(path, ignore_errors=True)
        logger.info("Deleted local sandbox workspace: %s", path)
        return True

    def _failed_result(
        self,
        *,
        run_id: str,
        job_id: str,
        workspace_path: Path,
        repo_path: Path,
        base_url: str,
        status: str,
        logs: list[CommandLog],
    ) -> MergeSandboxResult:
        return MergeSandboxResult(
            run_id=run_id,
            job_id=job_id,
            repo_path=str(repo_path.resolve()) if repo_path.exists() else str(repo_path),
            workspace_path=str(workspace_path.resolve()),
            sandbox_id=run_id,
            sandbox_url=f"{base_url}/sandboxes/{run_id}",
            status=status,
            merged_prs=[],
            logs=logs,
        )
