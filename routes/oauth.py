import logging

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import RedirectResponse

from services.opsera_client import OpseraClient, get_agent_status, get_scan_tool_status
from services.opsera_oauth import OpseraOAuth, OpseraOAuthError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/opsera", tags=["opsera-oauth"])


@router.get("/login")
def login() -> RedirectResponse:
    oauth = OpseraOAuth()
    try:
        authorize_url = oauth.start_login()
    except OpseraOAuthError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return RedirectResponse(url=authorize_url, status_code=302)


@router.get("/callback")
def callback(
    code: str = Query(...),
    state: str = Query(...),
) -> dict[str, str]:
    oauth = OpseraOAuth()
    try:
        oauth.complete_login(code=code, state=state)
    except OpseraOAuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "status": "authenticated",
        "message": "Opsera OAuth complete. Call GET /auth/opsera/tools to verify MCP tools.",
    }


@router.get("/status")
def status() -> dict[str, bool | str]:
    oauth = OpseraOAuth()
    agent = get_agent_status()
    return {
        "authenticated": oauth.is_authenticated,
        "mcp_url": oauth.fetch_metadata().get("mcp_endpoint", "https://agent.opsera.ai/mcp"),
        "agent_tier": "groq" if agent["groq_configured"] else "orchestrator_only",
        **agent,
    }


@router.get("/tools")
async def list_tools() -> dict:
    """Call live MCP tools/list — verify actual tool names before scanning."""
    client = OpseraClient()
    try:
        discovered = await client.list_tools()
    except OpseraOAuthError as exc:
        raise HTTPException(
            status_code=401,
            detail=f"{exc}. Visit /auth/opsera/login first.",
        ) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {
        "tool_count": len(discovered.all_tools),
        "tool_names": [tool.name for tool in discovered.all_tools],
        "resolved_security_tool": discovered.security_scan,
        "resolved_architecture_tool": discovered.architecture_analyze,
        "tools": discovered.summary(),
    }


@router.get("/scan-status")
def scan_status() -> dict:
    """Return which local security/architecture tools are installed."""
    tools = get_scan_tool_status()
    return {
        "tools": tools,
        "installed": [name for name, ok in tools.items() if ok],
        "missing": [name for name, ok in tools.items() if not ok],
    }


@router.post("/logout")
def logout() -> dict[str, str]:
    OpseraOAuth().clear_session()
    return {"status": "logged_out"}
