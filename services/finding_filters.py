from models import ArchitectureFinding, SecurityFinding, Severity


def filter_security_findings(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    return [f for f in findings if _is_actionable_security(f)]


def filter_architecture_findings(findings: list[ArchitectureFinding]) -> list[ArchitectureFinding]:
    return [f for f in findings if _is_actionable_architecture(f)]


def _is_actionable_security(finding: SecurityFinding) -> bool:
    title = finding.title.lower().strip()
    description = finding.description.strip()

    vague_titles = {
        "bandit finding",
        "bandit findings",
        "pip-audit finding",
        "pip-audit findings",
        "finding",
        "findings",
        "local scan findings",
    }
    if title in vague_titles:
        return False
    if title.endswith(" finding") and len(description) < 80:
        return False
    if len(description) < 20:
        return False
    if finding.severity == Severity.CRITICAL and "finding in" in description.lower():
        return False
    return True


def _is_actionable_architecture(finding: ArchitectureFinding) -> bool:
    title = finding.title.lower().strip()
    vague_titles = {
        "local scan findings",
        "no issues found in repository structure",
        "technology stack detected",
    }
    if title in vague_titles:
        return False
    if "repository structure analyzed" in finding.description.lower():
        return False
    if "technology stack detected" in title:
        return False
    return True
