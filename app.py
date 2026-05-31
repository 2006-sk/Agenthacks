import logging
import sys
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
load_dotenv(ROOT / ".env")
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pr_oracle_daytona.v2.router import router as v2_sandbox_router
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

app.include_router(v2_sandbox_router, prefix="/v2", tags=["P1/P2 v2"])
app.include_router(analyze_router)
app.include_router(oauth_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
