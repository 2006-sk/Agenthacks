import asyncio
import hashlib
import logging
import os
from dataclasses import dataclass

from models import AnalysisMode, ArchitectureFinding, ScanEngine, SecurityFinding
from services.agent_brain import AgentBrain, AgentBrainError
from services.mcp_client import DiscoveredTools, OpseraMcpClient, OpseraMcpError
from services.opsera_oauth import OPSERA_MCP_URL, OpseraOAuth, OpseraOAuthError
from services.scan_agent import run_agentic_analysis, run_orchestrator_analysis
from services.scan_orchestrator import (
    ArchitectureScanResult,
    SecurityScanResult,
    get_local_tool_status,
    resolve_analysis_mode,
)

logger = logging.getLogger(__name__)

OPSERA_MOCK_MODE = os.getenv("OPSERA_MOCK_MODE", "").lower() in ("1", "true", "yes")

_discovered_tools_cache: DiscoveredTools | None = None


class OpseraClientError(Exception):
    """Raised when Opsera MCP communication fails."""


@dataclass
class AnalysisResult:
    security_findings: list[SecurityFinding]
    architecture_findings: list[ArchitectureFinding]
    mode: AnalysisMode
    engine: ScanEngine
    security_scan: SecurityScanResult | None = None
    architecture_scan: ArchitectureScanResult | None = None


class OpseraClient:
    """Abstraction over Opsera Security Scan and Architecture Analysis."""

    def __init__(
        self,
        mcp_url: str | None = None,
        oauth: OpseraOAuth | None = None,
        force_mock: bool | None = None,
    ) -> None:
        self.mcp_url = mcp_url or OPSERA_MCP_URL
        self.oauth = oauth or OpseraOAuth()
        self.force_mock = force_mock if force_mock is not None else OPSERA_MOCK_MODE
        self._last_security_scan: SecurityScanResult | None = None
        self._last_architecture_scan: ArchitectureScanResult | None = None
        self._last_engine: ScanEngine = ScanEngine.MOCK

    @property
    def uses_mock(self) -> bool:
        if self.force_mock:
            return True
        return not self.oauth.is_authenticated

    def run_analysis(self, repo_path: str) -> AnalysisResult:
        """Run analysis with cascade: agent (Groq) → orchestrator → mock."""
        if self.uses_mock:
            logger.info("Opsera analysis running in MOCK mode for %s", repo_path)
            return self._mock_result(repo_path)

        try:
            return asyncio.run(self._run_live_analysis(repo_path))
        except (OpseraClientError, OpseraOAuthError, OpseraMcpError) as exc:
            logger.warning("Live analysis failed (%s); falling back to mock", exc)
            return self._mock_result(repo_path)

    def run_security_scan(self, repo_path: str) -> list[SecurityFinding]:
        return self.run_analysis(repo_path).security_findings

    def run_architecture_analysis(self, repo_path: str) -> list[ArchitectureFinding]:
        return self.run_analysis(repo_path).architecture_findings

    @property
    def last_engine(self) -> ScanEngine:
        return self._last_engine

    async def list_tools(self) -> DiscoveredTools:
        global _discovered_tools_cache
        if _discovered_tools_cache is not None:
            return _discovered_tools_cache

        access_token = self.oauth.get_valid_access_token()
        mcp = OpseraMcpClient(self.mcp_url, access_token)
        _discovered_tools_cache = await mcp.list_tools()
        return _discovered_tools_cache

    async def _run_live_analysis(self, repo_path: str) -> AnalysisResult:
        mcp, discovered = await self._get_mcp_client()
        security_scan: SecurityScanResult | None = None
        architecture_scan: ArchitectureScanResult | None = None
        engine = ScanEngine.ORCHESTRATOR

        # Tier 1: Groq/Llama agentic flow
        if AgentBrain.is_available():
            try:
                logger.info("Analysis tier 1: Groq agent for %s", repo_path)
                security_scan, architecture_scan = await run_agentic_analysis(
                    mcp, discovered, repo_path, AgentBrain()
                )
                if _has_real_results(security_scan, architecture_scan):
                    engine = ScanEngine.AGENT
                    logger.info("Analysis tier 1 succeeded (agent)")
                    return self._build_live_result(
                        security_scan, architecture_scan, engine
                    )
                logger.warning("Agent returned no usable results; trying orchestrator")
            except (AgentBrainError, Exception) as exc:
                logger.warning("Analysis tier 1 failed (%s); trying orchestrator", exc)
        else:
            logger.info("GROQ_API_KEY not set; skipping agent tier")

        # Tier 2: deterministic orchestrator
        try:
            logger.info("Analysis tier 2: deterministic orchestrator for %s", repo_path)
            security_scan, architecture_scan = await run_orchestrator_analysis(
                mcp, discovered, repo_path
            )
            if _has_real_results(security_scan, architecture_scan):
                engine = ScanEngine.ORCHESTRATOR
                logger.info("Analysis tier 2 succeeded (orchestrator)")
                return self._build_live_result(
                    security_scan, architecture_scan, engine
                )
            logger.warning("Orchestrator returned no results; falling back to mock")
        except Exception as exc:
            logger.warning("Analysis tier 2 failed (%s); falling back to mock", exc)

        # Tier 3: mock
        logger.info("Analysis tier 3: mock fallback for %s", repo_path)
        return self._mock_result(repo_path)

    def _build_live_result(
        self,
        security_scan: SecurityScanResult,
        architecture_scan: ArchitectureScanResult,
        engine: ScanEngine,
    ) -> AnalysisResult:
        self._last_security_scan = security_scan
        self._last_architecture_scan = architecture_scan
        self._last_engine = engine

        mode = resolve_analysis_mode(
            security_scan,
            architecture_scan,
            used_mock=False,
        )

        return AnalysisResult(
            security_findings=security_scan.findings,
            architecture_findings=architecture_scan.findings,
            mode=mode,
            engine=engine,
            security_scan=security_scan,
            architecture_scan=architecture_scan,
        )

    def _mock_result(self, repo_path: str) -> AnalysisResult:
        self._last_engine = ScanEngine.MOCK
        return AnalysisResult(
            security_findings=_mock_security_findings(repo_path),
            architecture_findings=_mock_architecture_findings(repo_path),
            mode=AnalysisMode.MOCK,
            engine=ScanEngine.MOCK,
        )

    async def _get_mcp_client(self) -> tuple[OpseraMcpClient, DiscoveredTools]:
        global _discovered_tools_cache
        access_token = self.oauth.get_valid_access_token()
        mcp = OpseraMcpClient(self.mcp_url, access_token)
        if _discovered_tools_cache is None:
            _discovered_tools_cache = await mcp.list_tools()
        else:
            mcp._discovered = _discovered_tools_cache
        return mcp, _discovered_tools_cache


def _has_real_results(
    security: SecurityScanResult,
    architecture: ArchitectureScanResult,
) -> bool:
    return bool(
        security.local_scanners_succeeded
        or security.mcp_findings_count > 0
        or security.findings
        or architecture.local_analysis_ran
        or architecture.mcp_findings_count > 0
        or architecture.findings
    )


def get_scan_tool_status() -> dict[str, bool]:
    return get_local_tool_status()


def get_agent_status() -> dict[str, bool | str]:
    return {
        "groq_configured": AgentBrain.is_available(),
        "groq_model": os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
    }


def _mock_seed(repo_path: str) -> int:
    return int(hashlib.sha256(repo_path.encode()).hexdigest(), 16)


def _mock_security_findings(repo_path: str) -> list[SecurityFinding]:
    from models import Severity

    seed = _mock_seed(repo_path)
    catalog = [
        SecurityFinding(
            severity=Severity.HIGH,
            title="Hardcoded Secret",
            description="AWS access key exposed in config/settings.py",
        ),
        SecurityFinding(
            severity=Severity.MEDIUM,
            title="Vulnerable Dependency",
            description="requests==2.25.0 has known CVE-2024-35195",
        ),
        SecurityFinding(
            severity=Severity.CRITICAL,
            title="SQL Injection Risk",
            description="Unparameterized query in db/queries.py:87",
        ),
        SecurityFinding(
            severity=Severity.LOW,
            title="Missing Security Header",
            description="X-Content-Type-Options not set in middleware",
        ),
        SecurityFinding(
            severity=Severity.HIGH,
            title="Exposed API Token",
            description="GitHub token found in .env.example",
        ),
    ]
    count = 2 + (seed % 3)
    if seed % 5 == 0:
        count = 1
    return catalog[:count]


def _mock_architecture_findings(repo_path: str) -> list[ArchitectureFinding]:
    from models import ArchitectureSeverity

    seed = _mock_seed(repo_path)
    catalog = [
        ArchitectureFinding(
            severity=ArchitectureSeverity.MEDIUM,
            title="Circular Dependency",
            description="AuthService <-> PaymentService bidirectional import",
        ),
        ArchitectureFinding(
            severity=ArchitectureSeverity.MAJOR,
            title="God Module",
            description="services/legacy.py exceeds 2000 lines with mixed concerns",
        ),
        ArchitectureFinding(
            severity=ArchitectureSeverity.MINOR,
            title="Leaky Abstraction",
            description="Repository layer exposes ORM models to controllers",
        ),
        ArchitectureFinding(
            severity=ArchitectureSeverity.MEDIUM,
            title="Single Point of Failure",
            description="All background jobs routed through single Redis instance",
        ),
        ArchitectureFinding(
            severity=ArchitectureSeverity.MINOR,
            title="Missing Interface Segregation",
            description="NotificationService implements unused email/fax methods",
        ),
    ]
    count = 2 + (seed % 2)
    if seed % 7 == 0:
        count = 1
    return catalog[:count]
