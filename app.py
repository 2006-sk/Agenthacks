import logging
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI

load_dotenv(Path(__file__).resolve().parent / ".env")

from routes.analyze import router as analyze_router
from routes.oauth import router as oauth_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

app = FastAPI(
    title="MergeGuard AI",
    description="P1 virtual merge + P2 local sandbox + P3 Opsera security/architecture analysis",
    version="2.0.0",
)

app.include_router(analyze_router)
app.include_router(oauth_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
