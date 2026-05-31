import logging

from models import SecurityFinding
from services.local_scanners.parsers import parse_gitleaks_json
from services.local_scanners.runner import is_tool_installed, run_command

logger = logging.getLogger(__name__)


def scan_secrets(repo_path: str) -> tuple[list[SecurityFinding], bool]:
    """Run gitleaks secret detection. Returns (findings, ran_successfully)."""
    if not is_tool_installed("gitleaks"):
        logger.info("gitleaks not installed; skipping secret scan")
        return [], False

    result = run_command(
        [
            "gitleaks",
            "detect",
            "--source",
            repo_path,
            "--no-git",
            "--report-format",
            "json",
        ],
        cwd=repo_path,
    )

    if result.timed_out:
        logger.warning("gitleaks scan timed out")
        return [], False

    output = result.stdout.strip()
    if not output and result.returncode not in (0, 1):
        logger.warning("gitleaks failed: %s", result.stderr[:200])
        return [], False

    findings = parse_gitleaks_json(output or "[]")
    logger.info("gitleaks scan complete: %d findings", len(findings))
    return findings, True
