import logging

from fastapi import APIRouter, HTTPException
from pydantic import ValidationError

from pr_oracle_daytona.settings import get_settings
from pr_oracle_daytona.v2.models import V2SandboxRequest
from pr_oracle_daytona.v2.service import V2SandboxService

logger = logging.getLogger(__name__)

router = APIRouter()
settings = get_settings()


def _service() -> V2SandboxService:
    return V2SandboxService(settings)


@router.post("/sandbox")
def create_v2_sandbox(req: V2SandboxRequest):
    service = _service()
    try:
        return service.create_sandbox(req)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc
    except Exception as exc:
        logger.exception("Unexpected error creating v2 sandbox")
        raise HTTPException(
            status_code=500,
            detail={"message": "Internal server error"},
        ) from exc


@router.get("/sandbox/{run_id}")
def get_v2_sandbox(run_id: str):
    service = _service()
    result = service.get_run(run_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail={"message": "Run not found", "runId": run_id},
        )
    return result


@router.get("/sandbox/{run_id}/logs")
def get_v2_logs(run_id: str):
    service = _service()
    result = service.get_logs(run_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail={"message": "Run not found", "runId": run_id},
        )
    return result


@router.get("/sandbox/{run_id}/status")
def get_v2_status(run_id: str):
    service = _service()
    result = service.get_status(run_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail={"message": "Run not found", "runId": run_id},
        )
    return result


@router.delete("/sandbox/{run_id}")
def delete_v2_sandbox(run_id: str):
    service = _service()
    result = service.delete_sandbox(run_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail={"message": "Run not found", "runId": run_id},
        )
    return result
