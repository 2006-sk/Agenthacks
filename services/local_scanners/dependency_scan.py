import json
import logging
import os

from models import SecurityFinding
from services.local_scanners.parsers import parse_grype_json, parse_pip_audit_json
from services.local_scanners.runner import is_tool_installed, run_command

logger = logging.getLogger(__name__)


def scan_dependencies(repo_path: str) -> tuple[list[SecurityFinding], bool, str]:
    """Run dependency vulnerability scan. Returns (findings, ran_successfully, scanner_name)."""
    requirements = os.path.join(repo_path, "requirements.txt")
    package_json = os.path.join(repo_path, "package.json")

    if os.path.isfile(requirements):
        findings, ran, name = _scan_python_deps(repo_path, requirements)
        if ran:
            return findings, ran, name

    if os.path.isfile(package_json):
        findings, ran = _scan_npm_deps(repo_path)
        if ran:
            return findings, ran, "npm-audit"

    if is_tool_installed("grype"):
        findings, ran = _scan_grype(repo_path)
        if ran:
            return findings, ran, "grype"

    logger.info("No dependency manifest found or scanners unavailable")
    return [], False, "none"


def _scan_python_deps(repo_path: str, requirements: str) -> tuple[list[SecurityFinding], bool, str]:
    pip_audit_cmd = "pip-audit"
    if not is_tool_installed("pip-audit"):
        venv_pip_audit = os.path.join(repo_path, ".venv", "bin", "pip-audit")
        if os.path.isfile(venv_pip_audit):
            pip_audit_cmd = venv_pip_audit
        else:
            logger.info("pip-audit not installed; skipping Python dependency scan")
            return [], False, "pip-audit"

    result = run_command(
        [pip_audit_cmd, "-r", requirements, "--format", "json", "--progress-spinner", "off"],
        cwd=repo_path,
    )

    if result.timed_out:
        return [], False, "pip-audit"

    output = result.stdout.strip()
    if not output:
        if result.returncode == 0:
            return [], True, "pip-audit"
        logger.warning("pip-audit failed: %s", result.stderr[:200])
        return [], False, "pip-audit"

    findings = parse_pip_audit_json(output)
    logger.info("pip-audit scan complete: %d findings", len(findings))
    return findings, True, "pip-audit"


def _scan_npm_deps(repo_path: str) -> tuple[list[SecurityFinding], bool]:
    if not is_tool_installed("npm"):
        logger.info("npm not installed; skipping npm audit")
        return [], False

    result = run_command(
        ["npm", "audit", "--json"],
        cwd=repo_path,
    )

    if result.timed_out:
        return [], False

    output = result.stdout.strip()
    if not output:
        return [], False

    findings = _parse_npm_audit(output)
    logger.info("npm audit complete: %d findings", len(findings))
    return findings, True


def _scan_grype(repo_path: str) -> tuple[list[SecurityFinding], bool]:
    result = run_command(
        ["grype", repo_path, "-o", "json"],
        cwd=repo_path,
    )

    if result.timed_out:
        return [], False

    output = result.stdout.strip()
    if not output:
        return [], False

    findings = parse_grype_json(output)
    logger.info("grype scan complete: %d findings", len(findings))
    return findings, True


def _parse_npm_audit(raw: str) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return findings

    vulnerabilities = data.get("vulnerabilities", {})
    if not isinstance(vulnerabilities, dict):
        return findings

    for name, vuln in vulnerabilities.items():
        if not isinstance(vuln, dict):
            continue
        from models import Severity

        severity_raw = str(vuln.get("severity", "moderate")).upper()
        severity = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MODERATE": Severity.MEDIUM,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }.get(severity_raw, Severity.MEDIUM)

        title = vuln.get("name") or name
        via = vuln.get("via", [])
        description = f"npm vulnerability in {name}"
        if via and isinstance(via[0], dict):
            description = via[0].get("title") or via[0].get("url") or description

        findings.append(
            SecurityFinding(
                severity=severity,
                title=f"Vulnerable npm package: {title}",
                description=description,
            )
        )
    return findings
