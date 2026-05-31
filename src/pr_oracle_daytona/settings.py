import os
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    github_token: str = Field(default="", alias="GITHUB_TOKEN")
    daytona_api_key: str = Field(default="", alias="DAYTONA_API_KEY")
    daytona_api_url: str = Field(
        default="https://app.daytona.io/api",
        alias="DAYTONA_API_URL",
    )
    daytona_target: str = Field(default="us", alias="DAYTONA_TARGET")
    daytona_mock_mode: bool = Field(default=False, alias="DAYTONA_MOCK_MODE")

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            github_token=os.getenv("GITHUB_TOKEN", ""),
            daytona_api_key=os.getenv("DAYTONA_API_KEY", ""),
            daytona_api_url=os.getenv("DAYTONA_API_URL", "https://app.daytona.io/api"),
            daytona_target=os.getenv("DAYTONA_TARGET", "us"),
            daytona_mock_mode=os.getenv("DAYTONA_MOCK_MODE", "").lower()
            in ("1", "true", "yes"),
        )


@lru_cache
def get_settings() -> Settings:
    return Settings.from_env()
