import logging
import shutil
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 120


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    skipped: bool = False
    skip_reason: str = ""


def is_tool_installed(name: str) -> bool:
    return shutil.which(name) is not None


def run_command(
    command: list[str],
    *,
    cwd: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> CommandResult:
    logger.info("Executing: %s (cwd=%s, timeout=%ss)", " ".join(command), cwd, timeout)
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(
            command=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
    except subprocess.TimeoutExpired as exc:
        logger.warning("Command timed out after %ss: %s", timeout, " ".join(command))
        return CommandResult(
            command=command,
            returncode=-1,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
            timed_out=True,
        )
    except OSError as exc:
        logger.warning("Command failed to start: %s (%s)", " ".join(command), exc)
        return CommandResult(
            command=command,
            returncode=-1,
            stdout="",
            stderr=str(exc),
        )


def check_tools(names: list[str]) -> dict[str, bool]:
    status = {name: is_tool_installed(name) for name in names}
    for name, installed in status.items():
        logger.info("Tool check: %s -> %s", name, "installed" if installed else "missing")
    return status
