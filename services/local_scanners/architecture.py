import ast
import logging
import os
import re
from collections import defaultdict

from models import ArchitectureFinding, ArchitectureSeverity

logger = logging.getLogger(__name__)

SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".opsera", "bob", "dist", "build"}
MAX_FILE_LINES = 500
OPSERA_INTERNALS = {"mcp_client", "opsera_oauth", "scan_orchestrator"}


def analyze_architecture(repo_path: str) -> tuple[list[ArchitectureFinding], bool]:
    """Pure-Python architecture heuristics. Always runs if Python files exist."""
    findings: list[ArchitectureFinding] = []

    python_files = _collect_python_files(repo_path)
    if not python_files:
        logger.info("No Python files found for architecture analysis")
        return [], False

    findings.extend(_detect_large_files(repo_path, python_files))
    findings.extend(_detect_circular_imports(repo_path, python_files))
    findings.extend(_detect_layer_violations(repo_path, python_files))

    logger.info("Local architecture analysis complete: %d findings", len(findings))
    return findings, True


def _collect_python_files(repo_path: str) -> list[str]:
    files: list[str] = []
    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in filenames:
            if filename.endswith(".py"):
                files.append(os.path.join(root, filename))
    return files


def _detect_large_files(
    repo_path: str, python_files: list[str]
) -> list[ArchitectureFinding]:
    findings: list[ArchitectureFinding] = []
    for path in python_files:
        try:
            with open(path, encoding="utf-8", errors="ignore") as handle:
                line_count = sum(1 for _ in handle)
        except OSError:
            continue

        if line_count > MAX_FILE_LINES:
            rel = os.path.relpath(path, repo_path)
            severity = (
                ArchitectureSeverity.MAJOR
                if line_count > MAX_FILE_LINES * 2
                else ArchitectureSeverity.MEDIUM
            )
            findings.append(
                ArchitectureFinding(
                    severity=severity,
                    title="Oversized module",
                    description=f"{rel} has {line_count} lines (threshold: {MAX_FILE_LINES})",
                )
            )
    return findings


def _module_name(repo_path: str, file_path: str) -> str:
    rel = os.path.relpath(file_path, repo_path)
    parts = rel.replace(os.sep, ".").replace(".py", "").split(".")
    return ".".join(parts)


def _extract_imports(file_path: str) -> set[str]:
    imports: set[str] = set()
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as handle:
            tree = ast.parse(handle.read(), filename=file_path)
    except (OSError, SyntaxError):
        return imports

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    return imports


def _build_import_graph(repo_path: str, python_files: list[str]) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = defaultdict(set)
    module_paths = {_module_name(repo_path, path): path for path in python_files}

    for module, path in module_paths.items():
        raw_imports = _extract_imports(path)
        for imp in raw_imports:
            for candidate in module_paths:
                if candidate.endswith(imp) or candidate.split(".")[-1] == imp:
                    if candidate != module:
                        graph[module].add(candidate)
    return graph


def _detect_circular_imports(
    repo_path: str, python_files: list[str]
) -> list[ArchitectureFinding]:
    findings: list[ArchitectureFinding] = []
    services_files = [f for f in python_files if "/services/" in f.replace(os.sep, "/")]
    if len(services_files) < 2:
        return findings

    graph = _build_import_graph(repo_path, services_files)
    visited: set[str] = set()
    stack: list[str] = []
    cycles: list[tuple[str, ...]] = []

    def dfs(node: str) -> None:
        if node in stack:
            idx = stack.index(node)
            cycles.append(tuple(stack[idx:] + [node]))
            return
        if node in visited:
            return
        visited.add(node)
        stack.append(node)
        for neighbor in graph.get(node, set()):
            dfs(neighbor)
        stack.pop()

    for node in graph:
        dfs(node)

    seen_cycles: set[tuple[str, ...]] = set()
    for cycle in cycles:
        normalized = tuple(sorted(set(cycle)))
        if normalized in seen_cycles or len(normalized) < 2:
            continue
        seen_cycles.add(normalized)
        chain = " <-> ".join(cycle)
        findings.append(
            ArchitectureFinding(
                severity=ArchitectureSeverity.MEDIUM,
                title="Circular dependency",
                description=f"Import cycle detected in services: {chain}",
            )
        )
    return findings


def _detect_layer_violations(
    repo_path: str, python_files: list[str]
) -> list[ArchitectureFinding]:
    findings: list[ArchitectureFinding] = []
    route_files = [f for f in python_files if "/routes/" in f.replace(os.sep, "/")]

    for path in route_files:
        rel = os.path.relpath(path, repo_path)
        try:
            with open(path, encoding="utf-8", errors="ignore") as handle:
                content = handle.read()
        except OSError:
            continue

        for internal in OPSERA_INTERNALS:
            pattern = rf"from\s+services\.{internal}\s+import|import\s+services\.{internal}"
            if re.search(pattern, content):
                findings.append(
                    ArchitectureFinding(
                        severity=ArchitectureSeverity.MINOR,
                        title="Layer violation",
                        description=(
                            f"{rel} imports Opsera internal module services.{internal} "
                            "directly; routes should use OpseraClient only"
                        ),
                    )
                )
    return findings
