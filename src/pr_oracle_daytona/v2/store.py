import logging
from pathlib import Path

from pr_oracle_daytona.v2.models import V2SandboxResponse

logger = logging.getLogger(__name__)

V2_RUNS: dict[str, V2SandboxResponse] = {}


def _runs_jsonl_path() -> Path:
    project_root = Path(__file__).resolve().parents[3]
    return project_root / ".local" / "v2-runs.jsonl"


def _append_jsonl(record: V2SandboxResponse) -> None:
    try:
        path = _runs_jsonl_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(record.model_dump_json(by_alias=True) + "\n")
    except OSError as exc:
        logger.warning("Failed to append v2 run to JSONL: %s", exc)


def save_v2_run(run: V2SandboxResponse) -> None:
    V2_RUNS[run.run_id] = run
    _append_jsonl(run)


def get_v2_run(run_id: str) -> V2SandboxResponse | None:
    return V2_RUNS.get(run_id)


def delete_v2_run(run_id: str) -> V2SandboxResponse | None:
    return V2_RUNS.pop(run_id, None)
