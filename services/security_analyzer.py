import logging

from models import SecurityFinding
from services.opsera_client import OpseraClient

logger = logging.getLogger(__name__)


class SecurityAnalyzer:
    def __init__(self, opsera_client: OpseraClient | None = None) -> None:
        self.opsera_client = opsera_client or OpseraClient()

    def analyze(self, repo_path: str) -> list[SecurityFinding]:
        logger.info("Security scan started for %s", repo_path)
        findings = self.opsera_client.run_security_scan(repo_path)
        logger.info("Security scan completed: %d findings", len(findings))
        return findings
