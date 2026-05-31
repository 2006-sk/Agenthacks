import base64
import hashlib
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx

logger = logging.getLogger(__name__)

OPSERA_ISSUER = os.getenv("OPSERA_OAUTH_ISSUER", "https://agent.opsera.ai")
OPSERA_MCP_URL = os.getenv("OPSERA_MCP_URL", "https://agent.opsera.ai/mcp")
OPSERA_REDIRECT_URI = os.getenv(
    "OPSERA_REDIRECT_URI", "http://127.0.0.1:8000/auth/opsera/callback"
)
OPSERA_DATA_DIR = Path(os.getenv("OPSERA_DATA_DIR", ".opsera"))
OPSERA_CLIENT_FILE = OPSERA_DATA_DIR / "oauth_client.json"
OPSERA_TOKENS_FILE = OPSERA_DATA_DIR / "tokens.json"
OPSERA_PKCE_FILE = OPSERA_DATA_DIR / "pkce_state.json"


class OpseraOAuthError(Exception):
    """Raised when Opsera OAuth operations fail."""


@dataclass
class OAuthTokens:
    access_token: str
    refresh_token: str | None = None
    expires_at: float | None = None
    token_type: str = "Bearer"

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() >= self.expires_at - 60

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OAuthTokens":
        expires_in = data.get("expires_in")
        expires_at = time.time() + float(expires_in) if expires_in else data.get("expires_at")
        return cls(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            expires_at=expires_at,
            token_type=data.get("token_type", "Bearer"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_at": self.expires_at,
            "token_type": self.token_type,
        }


class OpseraOAuth:
    """OAuth 2.0 PKCE flow for Opsera MCP (no static API keys)."""

    def __init__(
        self,
        issuer: str | None = None,
        redirect_uri: str | None = None,
        data_dir: Path | None = None,
    ) -> None:
        self.issuer = issuer or OPSERA_ISSUER
        self.redirect_uri = redirect_uri or OPSERA_REDIRECT_URI
        self.data_dir = data_dir or OPSERA_DATA_DIR
        self.client_file = self.data_dir / "oauth_client.json"
        self.tokens_file = self.data_dir / "tokens.json"
        self.pkce_file = self.data_dir / "pkce_state.json"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._metadata: dict[str, Any] | None = None

    @property
    def is_authenticated(self) -> bool:
        try:
            self.get_valid_access_token()
            return True
        except OpseraOAuthError:
            return False

    def fetch_metadata(self) -> dict[str, Any]:
        if self._metadata is not None:
            return self._metadata
        url = f"{self.issuer}/.well-known/oauth-authorization-server"
        with httpx.Client(timeout=30.0) as client:
            response = client.get(url)
            response.raise_for_status()
            self._metadata = response.json()
            return self._metadata

    def ensure_client(self) -> dict[str, Any]:
        if self.client_file.exists():
            return json.loads(self.client_file.read_text())

        metadata = self.fetch_metadata()
        register_url = metadata.get("registration_endpoint", f"{self.issuer}/register")
        payload = {
            "client_name": "mergeguard-p3",
            "redirect_uris": [self.redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }
        with httpx.Client(timeout=30.0) as client:
            response = client.post(register_url, json=payload)
            response.raise_for_status()
            client_data = response.json()

        self.client_file.write_text(json.dumps(client_data, indent=2))
        logger.info("Registered Opsera OAuth client: %s", client_data.get("client_id"))
        return client_data

    @staticmethod
    def _generate_pkce() -> tuple[str, str]:
        verifier = secrets.token_urlsafe(64)
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        return verifier, challenge

    def start_login(self) -> str:
        client = self.ensure_client()
        verifier, challenge = self._generate_pkce()
        state = secrets.token_urlsafe(32)

        self.pkce_file.write_text(
            json.dumps(
                {
                    "state": state,
                    "code_verifier": verifier,
                    "created_at": time.time(),
                },
                indent=2,
            )
        )

        metadata = self.fetch_metadata()
        params = {
            "response_type": "code",
            "client_id": client["client_id"],
            "redirect_uri": self.redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "scope": "openid profile email",
        }
        authorize_url = f"{metadata['authorization_endpoint']}?{urlencode(params)}"
        logger.info("Opsera OAuth login started")
        return authorize_url

    def complete_login(self, code: str, state: str) -> OAuthTokens:
        if not self.pkce_file.exists():
            raise OpseraOAuthError("Missing PKCE state; start login at /auth/opsera/login")

        pkce_data = json.loads(self.pkce_file.read_text())
        if pkce_data.get("state") != state:
            raise OpseraOAuthError("OAuth state mismatch")

        client = self.ensure_client()
        metadata = self.fetch_metadata()
        token_url = metadata["token_endpoint"]

        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": client["client_id"],
            "code_verifier": pkce_data["code_verifier"],
        }

        with httpx.Client(timeout=30.0) as client_http:
            response = client_http.post(token_url, data=payload)
            if response.status_code >= 400:
                raise OpseraOAuthError(
                    f"Token exchange failed ({response.status_code}): {response.text}"
                )
            token_data = response.json()

        tokens = OAuthTokens.from_dict(token_data)
        self.save_tokens(tokens)
        self.pkce_file.unlink(missing_ok=True)
        logger.info("Opsera OAuth login completed")
        return tokens

    def save_tokens(self, tokens: OAuthTokens) -> None:
        self.tokens_file.write_text(json.dumps(tokens.to_dict(), indent=2))

    def load_tokens(self) -> OAuthTokens | None:
        if not self.tokens_file.exists():
            return None
        data = json.loads(self.tokens_file.read_text())
        return OAuthTokens.from_dict(data)

    def refresh_tokens(self, tokens: OAuthTokens) -> OAuthTokens:
        if not tokens.refresh_token:
            raise OpseraOAuthError("No refresh token available; re-login required")

        client = self.ensure_client()
        metadata = self.fetch_metadata()
        token_url = metadata["token_endpoint"]

        payload = {
            "grant_type": "refresh_token",
            "refresh_token": tokens.refresh_token,
            "client_id": client["client_id"],
        }

        with httpx.Client(timeout=30.0) as client_http:
            response = client_http.post(token_url, data=payload)
            if response.status_code >= 400:
                raise OpseraOAuthError(
                    f"Token refresh failed ({response.status_code}): {response.text}"
                )
            token_data = response.json()

        refreshed = OAuthTokens.from_dict(token_data)
        if not refreshed.refresh_token and tokens.refresh_token:
            refreshed.refresh_token = tokens.refresh_token
        self.save_tokens(refreshed)
        logger.info("Opsera OAuth token refreshed")
        return refreshed

    def get_valid_access_token(self) -> str:
        tokens = self.load_tokens()
        if tokens is None:
            raise OpseraOAuthError("Not authenticated; visit /auth/opsera/login")

        if tokens.is_expired:
            tokens = self.refresh_tokens(tokens)

        return tokens.access_token

    def clear_session(self) -> None:
        self.tokens_file.unlink(missing_ok=True)
        self.pkce_file.unlink(missing_ok=True)
        logger.info("Opsera OAuth session cleared")
