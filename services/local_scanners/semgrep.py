import logging
import os

from models import SecurityFinding
from services.local_scanners.parsers import parse_bandit_json, parse_semgrep_json
from services.local_scanners.runner import is_tool_installed, run_command

logger = logging.getLogger(__name__)


def scan_sast(repo_path: str) -> tuple[list[SecurityFinding], bool, str]:
    """Run semgrep or bandit fallback. Returns (findings, ran_successfully, scanner_name)."""
    if is_tool_installed("semgrep"):
        return _run_semgrep(repo_path)
    if _has_python_files(repo_path):
        return _run_bandit(repo_path)
    logger.info("No SAST tool available (semgrep/bandit); skipping")
    return [], False, "none"


def _has_python_files(repo_path: str) -> bool:
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in {".git", ".venv", "node_modules", "__pycache__"}]
        if any(f.endswith(".py") for f in files):
            return True
    return False


def _run_semgrep(repo_path: str) -> tuple[list[SecurityFinding], bool, str]:
    result = run_command(
        [
            "semgrep",
            "--config",
            "auto",
            "--json",
            "--quiet",
            repo_path,
        ],
        cwd=repo_path,
    )

    if result.timed_out:
        logger.warning("semgrep scan timed out")
        return [], False, "semgrep"

    output = result.stdout.strip()
    if not output and result.returncode not in (0, 1):
        logger.warning("semgrep failed: %s", result.stderr[:200])
        return [], False, "semgrep"

    findings = parse_semgrep_json(output or '{"results": []}')
    logger.info("semgrep scan complete: %d findings", len(findings))
    return findings, True, "semgrep"


def _run_bandit(repo_path: str) -> tuple[list[SecurityFinding], bool, str]:
    bandit_cmd = "bandit"
    if not is_tool_installed("bandit"):
        venv_bandit = os.path.join(repo_path, ".venv", "bin", "bandit")
        if os.path.isfile(venv_bandit):
            bandit_cmd = venv_bandit
        else:
            logger.info("bandit not installed; skipping Python SAST")
            return [], False, "bandit"

    targets = _project_scan_targets(repo_path)
    if not targets:
        logger.info("No project Python targets found for bandit")
        return [], False, "bandit"

    result = run_command(
        [
            bandit_cmd,
            "-r",
            *targets,
            "-x",
            ".venv,node_modules,.git,__pycache__,bob,dist,build",
            "-f",
            "json",
            "-q",
        ],
        cwd=repo_path,
    )

    if result.timed_out:
        logger.warning("bandit scan timed out")
        return [], False, "bandit"

    output = result.stdout.strip()
    if not output and result.returncode not in (0, 1):
        logger.warning("bandit failed: %s", result.stderr[:200])
        return [], False, "bandit"

    findings = parse_bandit_json(output or '{"results": []}')
    findings = _filter_project_findings(repo_path, findings)
    logger.info("bandit scan complete: %d findings", len(findings))
    return findings, True, "bandit"


def _project_scan_targets(repo_path: str) -> list[str]:
    targets: list[str] = []
    for subdir in ("services", "routes", "scripts", "backend", "app", "src", "lib"):
        path = os.path.join(repo_path, subdir)
        if os.path.isdir(path):
            targets.append(path)
    for filename in ("app.py", "models.py", "main.py"):
        path = os.path.join(repo_path, filename)
        if os.path.isfile(path):
            targets.append(path)
    if not targets:
        targets = [repo_path]
    return targets


def _filter_project_findings(
    repo_path: str, findings: list[SecurityFinding]
) -> list[SecurityFinding]:
    skip_markers = ("/.venv/", "/node_modules/", "/.git/", "/__pycache__/")
    filtered: list[SecurityFinding] = []
    for finding in findings:
        if any(marker in finding.description for marker in skip_markers):
            continue
        filtered.append(finding)
    return filtered
