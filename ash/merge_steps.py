from urllib.parse import urlparse

from pr_oracle_daytona.v2.models import V2MergeStep, V2SandboxRequest


def parse_repo_owner_name(repo_url: str) -> tuple[str, str]:
    parsed = urlparse(repo_url.rstrip("/"))
    path = parsed.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = path.split("/")
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return "unknown", path or "unknown"


def default_sandbox_branch_name(req: V2SandboxRequest) -> str:
    if req.sandbox_branch_name:
        return req.sandbox_branch_name
    primary_pr = req.pr_numbers[0]
    return f"sandbox/pr-{primary_pr}"


def workspace_folder_name(req: V2SandboxRequest) -> str:
    return f"pr-{req.pr_numbers[0]}"


def extract_base_info(steps: list[V2MergeStep]) -> tuple[str | None, str | None]:
    for step in steps:
        if step.step_type == "checkout_base":
            return step.branch, step.commit_sha
    return None, None


def extract_merge_branch(steps: list[V2MergeStep]) -> str | None:
    for step in steps:
        if step.step_type == "fetch_pr":
            return step.local_branch
    return None


def checkout_base_command(step: V2MergeStep, default_branch: str | None) -> str:
    branch = step.branch or default_branch or "main"
    if step.commit_sha:
        return f"git fetch origin {branch} && git checkout {step.commit_sha}"
    return f"git checkout {branch} && git pull origin {branch}"


def fetch_pr_command(step: V2MergeStep) -> str:
    return f"git fetch origin {step.git_ref}:{step.local_branch}"


def merge_pr_command(step: V2MergeStep) -> str:
    return f"git merge --no-edit {step.local_branch}"


def merge_step_command(step: V2MergeStep, default_branch: str | None) -> str:
    if step.step_type == "checkout_base":
        return checkout_base_command(step, default_branch)
    if step.step_type == "fetch_pr":
        return fetch_pr_command(step)
    return merge_pr_command(step)


def merge_step_log_name(step: V2MergeStep) -> str:
    return step.step_type
