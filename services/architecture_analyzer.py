import logging

from models import ArchitectureFinding
from services.opsera_client import OpseraClient

logger = logging.getLogger(__name__)


class ArchitectureAnalyzer:
    def __init__(self, opsera_client: OpseraClient | None = None) -> None:
        self.opsera_client = opsera_client or OpseraClient()

    def analyze(self, repo_path: str) -> list[ArchitectureFinding]:
        logger.info("Architecture scan started for %s", repo_path)
        findings = self.opsera_client.run_architecture_analysis(repo_path)
        logger.info("Architecture scan completed: %d findings", len(findings))
        return findings
