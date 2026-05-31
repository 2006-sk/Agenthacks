from urllib.parse import urlparse, urlunparse


def build_tokenized_github_url(repo_url: str, token: str) -> str:
    if not token:
        return repo_url
    parsed = urlparse(repo_url.rstrip("/"))
    if not parsed.netloc.endswith("github.com"):
        return repo_url
    return urlunparse(parsed._replace(netloc=f"{token}@github.com"))


def safe_repo_url(repo_url: str) -> str:
    parsed = urlparse(repo_url.rstrip("/"))
    if "@" in parsed.netloc:
        host = parsed.netloc.split("@", 1)[-1]
        return urlunparse(parsed._replace(netloc=host))
    return repo_url


def redact_secret(text: str, secrets: list[str]) -> str:
    redacted = text
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "***")
    return redacted


def sanitize_command(command: str, secrets: list[str]) -> str:
    return redact_secret(command, secrets)
