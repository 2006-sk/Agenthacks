import json
import logging
from typing import Any

from models import ArchitectureFinding, ArchitectureSeverity, SecurityFinding, Severity

logger = logging.getLogger(__name__)


def _map_security_severity(value: str) -> Severity:
    normalized = value.upper()
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.LOW,
    }
    return mapping.get(normalized, Severity.MEDIUM)


def _map_architecture_severity(value: str) -> ArchitectureSeverity:
    normalized = value.upper()
    mapping = {
        "MAJOR": ArchitectureSeverity.MAJOR,
        "CRITICAL": ArchitectureSeverity.MAJOR,
        "HIGH": ArchitectureSeverity.MAJOR,
        "MEDIUM": ArchitectureSeverity.MEDIUM,
        "MINOR": ArchitectureSeverity.MINOR,
        "LOW": ArchitectureSeverity.MINOR,
    }
    return mapping.get(normalized, ArchitectureSeverity.MEDIUM)


def parse_gitleaks_json(raw: str) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Failed to parse gitleaks JSON output")
        return findings

    if not isinstance(data, list):
        return findings

    for item in data:
        if not isinstance(item, dict):
            continue
        file_path = item.get("File") or item.get("file") or "unknown"
        rule = item.get("RuleID") or item.get("rule") or "Secret detected"
        description = item.get("Description") or item.get("description") or ""
        match = item.get("Match") or item.get("match") or ""
        findings.append(
            SecurityFinding(
                severity=Severity.HIGH,
                title=f"Secret leak: {rule}",
                description=f"{description} in {file_path}" + (f" ({match[:80]})" if match else ""),
            )
        )
    return findings


def parse_bandit_json(raw: str) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Failed to parse bandit JSON output")
        return findings

    results = data.get("results", []) if isinstance(data, dict) else []
    for item in results:
        if not isinstance(item, dict):
            continue
        severity = _map_security_severity(str(item.get("issue_severity", "MEDIUM")))
        title = item.get("test_name") or item.get("test_id") or "Bandit finding"
        filename = item.get("filename", "unknown")
        line = item.get("line_number", "?")
        text = item.get("issue_text") or item.get("issue_cwe", {}).get("link", "")
        findings.append(
            SecurityFinding(
                severity=severity,
                title=title,
                description=f"{text} at {filename}:{line}",
            )
        )
    return findings


def parse_semgrep_json(raw: str) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Failed to parse semgrep JSON output")
        return findings

    results = data.get("results", []) if isinstance(data, dict) else []
    for item in results:
        if not isinstance(item, dict):
            continue
        extra = item.get("extra", {})
        severity = _map_security_severity(str(extra.get("severity", "MEDIUM")))
        title = extra.get("message") or item.get("check_id") or "Semgrep finding"
        path = item.get("path", "unknown")
        start = item.get("start", {})
        line = start.get("line", "?")
        findings.append(
            SecurityFinding(
                severity=severity,
                title=title,
                description=f"{path}:{line}",
            )
        )
    return findings


def parse_pip_audit_json(raw: str) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Failed to parse pip-audit JSON output")
        return findings

    if not isinstance(data, dict):
        return findings

    dependencies = data.get("dependencies", [])
    for dep in dependencies:
        if not isinstance(dep, dict):
            continue
        name = dep.get("name", "unknown")
        version = dep.get("version", "?")
        vulns = dep.get("vulns", [])
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            vuln_id = vuln.get("id") or "CVE"
            description = vuln.get("description") or f"Vulnerability in {name}=={version}"
            findings.append(
                SecurityFinding(
                    severity=Severity.HIGH,
                    title=f"Vulnerable dependency: {name}",
                    description=f"{vuln_id}: {description}",
                )
            )
    return findings


def parse_grype_json(raw: str) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Failed to parse grype JSON output")
        return findings

    matches = data.get("matches", []) if isinstance(data, dict) else []
    for match in matches:
        if not isinstance(match, dict):
            continue
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        severity = _map_security_severity(str(vuln.get("severity", "MEDIUM")))
        title = vuln.get("id") or "Dependency vulnerability"
        pkg = artifact.get("name", "unknown")
        version = artifact.get("version", "?")
        description = vuln.get("description") or f"{pkg}=={version}"
        findings.append(
            SecurityFinding(
                severity=severity,
                title=f"Vulnerable dependency: {pkg}",
                description=description,
            )
        )
    return findings


def parse_mcp_security_findings(raw_results: list[Any]) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    for result in raw_results:
        findings.extend(_findings_from_mcp_result(result, kind="security"))
    return _dedupe_security(findings)


def parse_mcp_architecture_findings(raw_results: list[Any]) -> list[ArchitectureFinding]:
    findings: list[ArchitectureFinding] = []
    for result in raw_results:
        findings.extend(_findings_from_mcp_result(result, kind="architecture"))
    return _dedupe_architecture(findings)


def _extract_content_text(result: Any) -> str:
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        if "content" in result:
            parts: list[str] = []
            for block in result["content"]:
                if isinstance(block, str):
                    parts.append(block)
                elif isinstance(block, dict) and block.get("type") == "text":
                    parts.append(block.get("text", ""))
            return "\n".join(parts)
        if "structuredContent" in result and result["structuredContent"]:
            return json.dumps(result["structuredContent"])
        return json.dumps(result)
    if isinstance(result, list):
        return json.dumps(result)
    return str(result)


def _findings_from_mcp_result(result: Any, kind: str) -> list[Any]:
    text = _extract_content_text(result)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    findings: list[Any] = []
    if isinstance(data, dict):
        items = data.get("findings") or data.get("issues") or data.get("results") or []
        if isinstance(items, list):
            for item in items:
                finding = _normalize_finding_item(item, kind)
                if finding:
                    findings.append(finding)
    elif isinstance(data, list):
        for item in data:
            finding = _normalize_finding_item(item, kind)
            if finding:
                findings.append(finding)
    return findings


def _normalize_finding_item(item: Any, kind: str) -> SecurityFinding | ArchitectureFinding | None:
    if not isinstance(item, dict):
        return None

    title = item.get("title") or item.get("name") or item.get("rule") or "Finding"
    description = (
        item.get("description")
        or item.get("message")
        or item.get("detail")
        or item.get("recommendation")
        or ""
    )
    severity_raw = str(item.get("severity") or item.get("level") or "MEDIUM").upper()

    if kind == "security":
        return SecurityFinding(
            severity=_map_security_severity(severity_raw),
            title=title,
            description=description,
        )

    return ArchitectureFinding(
        severity=_map_architecture_severity(severity_raw),
        title=title,
        description=description,
    )


def _dedupe_security(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[SecurityFinding] = []
    for finding in findings:
        key = (finding.severity.value, finding.title, finding.description)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def _dedupe_architecture(findings: list[ArchitectureFinding]) -> list[ArchitectureFinding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[ArchitectureFinding] = []
    for finding in findings:
        key = (finding.severity.value, finding.title, finding.description)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique
