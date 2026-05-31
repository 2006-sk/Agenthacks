import logging
import os

from fastapi import APIRouter, HTTPException

from models import AnalyzeRequest, VerdictResponse
from services.local_merge import LocalMergeSandbox
from services.local_merge.store import delete_run, get_status, save_run
from services.opsera_client import OpseraClient
from services.scoring_engine import build_verdict_response

logger = logging.getLogger(__name__)

router = APIRouter()
merge_service = LocalMergeSandbox()


def _validate_repo_path(repo_path: str) -> None:
    if not os.path.isdir(repo_path):
        raise HTTPException(
            status_code=400,
            detail=f"Repository path does not exist or is not a directory: {repo_path}",
        )


def _resolve_analyze_context(request: AnalyzeRequest) -> tuple[str, AnalyzeRequest, str | None]:
    """Return (repo_path, enriched_request, workspace_path_for_cleanup)."""
    if request.uses_merge_flow:
        assert request.repo_url
        sandbox = merge_service.create_and_merge(
            repo_url=request.repo_url,
            pr_number=request.pr_number,
            base_branch=request.base_branch,
            job_id=request.job_id,
            head_sha=request.head_sha,
        )
        save_run(sandbox)

        if sandbox.status != "merged":
            merge_service.delete_workspace(sandbox.workspace_path)
            delete_run(sandbox.run_id)
            raise HTTPException(
                status_code=422,
                detail={
                    "message": f"Virtual merge failed: {sandbox.status}",
                    "runId": sandbox.run_id,
                    "sandboxUrl": sandbox.sandbox_url,
                },
            )

        enriched = request.model_copy(
            update={
                "repo_path": sandbox.repo_path,
                "sandbox_id": sandbox.sandbox_id,
                "sandbox_url": sandbox.sandbox_url,
            }
        )
        cleanup_path = None if request.keep_sandbox else sandbox.workspace_path
        logger.info(
            "P1/P2 complete: merged PR #%d at %s (sandbox=%s)",
            request.pr_number,
            sandbox.repo_path,
            sandbox.sandbox_id,
        )
        return sandbox.repo_path, enriched, cleanup_path

    assert request.repo_path
    _validate_repo_path(request.repo_path)
    enriched = request.model_copy(
        update={
            "sandbox_id": request.sandbox_id or "local-direct",
            "sandbox_url": request.sandbox_url or "http://127.0.0.1:8000/sandboxes/local-direct",
        }
    )
    return request.repo_path, enriched, None


@router.post("/analyze", response_model=VerdictResponse)
def analyze(request: AnalyzeRequest) -> VerdictResponse:
    logger.info(
        "Analyze request: repoUrl=%s repoPath=%s prNumber=%s headSha=%s",
        request.repo_url,
        request.repo_path,
        request.pr_number,
        request.head_sha,
    )

    workspace_to_cleanup: str | None = None
    saved_run_id: str | None = None
    try:
        repo_path, ctx, workspace_to_cleanup = _resolve_analyze_context(request)
        if ctx.uses_merge_flow and ctx.sandbox_id:
            saved_run_id = ctx.sandbox_id

        logger.info("P3 analyze starting on %s", repo_path)
        opsera_client = OpseraClient()
        analysis = opsera_client.run_analysis(repo_path)

        response = build_verdict_response(
            ctx,
            analysis.security_findings,
            analysis.architecture_findings,
            repo_path=repo_path,
        )
        logger.info(
            "P3 complete: verdict=%s confidence=%.2f verdictId=%s evidence=%s",
            response.verdict.value,
            response.confidence,
            response.verdict_id,
            response.evidence_url,
        )
        return response
    finally:
        if workspace_to_cleanup:
            merge_service.delete_workspace(workspace_to_cleanup)
        if saved_run_id and not request.keep_sandbox:
            delete_run(saved_run_id)


@router.get("/sandboxes/{run_id}")
def get_sandbox_status(run_id: str):
    status = get_status(run_id)
    if status is None:
        raise HTTPException(status_code=404, detail={"message": "Sandbox not found", "runId": run_id})
    return status
