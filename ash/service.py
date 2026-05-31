from pr_oracle_daytona.settings import Settings
from pr_oracle_daytona.v2.daytona_sandbox_service import DaytonaSandboxService
from pr_oracle_daytona.v2.local_sandbox_service import LocalSandboxService
from pr_oracle_daytona.v2.models import (
    V2DeleteResponse,
    V2LogsResponse,
    V2SandboxRequest,
    V2SandboxResponse,
    V2StatusResponse,
)
from pr_oracle_daytona.v2.store import delete_v2_run, get_v2_run


class V2SandboxService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()
        self._local = LocalSandboxService(self.settings)
        self._daytona = DaytonaSandboxService(self.settings)

    def create_sandbox(self, req: V2SandboxRequest) -> V2SandboxResponse:
        if req.mode == "daytona":
            return self._daytona.create_sandbox(req)
        return self._local.create_sandbox(req)

    def get_run(self, run_id: str) -> V2SandboxResponse | None:
        return get_v2_run(run_id)

    def get_status(self, run_id: str) -> V2StatusResponse | None:
        run = get_v2_run(run_id)
        if run is None:
            return None
        return V2StatusResponse(
            run_id=run.run_id,
            job_id=run.job_id,
            status=run.status,
            sandbox=run.sandbox,
            ready=run.status == "merged",
        )

    def get_logs(self, run_id: str) -> V2LogsResponse | None:
        run = get_v2_run(run_id)
        if run is None:
            return None
        return V2LogsResponse(
            run_id=run.run_id,
            job_id=run.job_id,
            status=run.status,
            logs=run.logs,
        )

    def delete_sandbox(self, run_id: str) -> V2DeleteResponse | None:
        run = get_v2_run(run_id)
        if run is None:
            return None

        deleted = False
        message = "Sandbox deleted"
        if run.sandbox.mode == "local":
            deleted = self._local.delete_sandbox(run)
        else:
            deleted = self._daytona.delete_sandbox(run)
            if not deleted:
                message = "Sandbox delete attempted but Daytona removal failed"

        delete_v2_run(run_id)
        return V2DeleteResponse(
            run_id=run.run_id,
            job_id=run.job_id,
            deleted=deleted,
            message=message,
        )
