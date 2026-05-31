import time
from typing import Any

from pr_oracle_daytona.command_utils import redact_secret, sanitize_command
from pr_oracle_daytona.models import CommandLog
from pr_oracle_daytona.settings import Settings


def secrets_list(settings: Settings) -> list[str]:
    return [value for value in (settings.github_token, settings.daytona_api_key) if value]


def create_daytona_client(settings: Settings) -> Any:
    from daytona import Daytona, DaytonaConfig

    config = DaytonaConfig(
        api_key=settings.daytona_api_key or None,
        api_url=settings.daytona_api_url,
        target=settings.daytona_target,
    )
    return Daytona(config)


def create_sandbox(daytona: Any, settings: Settings) -> Any:
    del settings
    return daytona.create()


def run_command(
    sandbox: Any,
    step: str,
    command: str,
    secrets: list[str],
) -> CommandLog:
    started = time.perf_counter()
    try:
        response = sandbox.process.exec(command)
        exit_code = getattr(response, "exit_code", 0)
        stdout = ""
        if hasattr(response, "artifacts") and response.artifacts is not None:
            stdout = getattr(response.artifacts, "stdout", "") or ""
        if not stdout:
            stdout = getattr(response, "result", "") or ""
        stderr = ""
        if hasattr(response, "artifacts") and response.artifacts is not None:
            stderr = getattr(response.artifacts, "stderr", "") or ""
        output_parts = [part for part in (stdout, stderr) if part]
        raw_output = "\n".join(output_parts).strip() or "(no output)"
        duration_ms = int((time.perf_counter() - started) * 1000)
        return CommandLog(
            step=step,
            command=sanitize_command(command, secrets),
            exit_code=int(exit_code),
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
