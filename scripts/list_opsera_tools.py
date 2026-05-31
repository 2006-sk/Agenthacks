#!/usr/bin/env python3
"""List Opsera MCP tools via live tools/list (requires OAuth login first)."""

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from services.opsera_client import OpseraClient
from services.opsera_oauth import OpseraOAuth, OpseraOAuthError


async def main() -> int:
    oauth = OpseraOAuth()
    if not oauth.is_authenticated:
        print("Not authenticated.")
        print("1. Start server: uvicorn app:app --reload")
        print("2. Open: http://127.0.0.1:8000/auth/opsera/login")
        print("3. Re-run: python scripts/list_opsera_tools.py")
        return 1

    client = OpseraClient()
    discovered = await client.list_tools()

    output = {
        "tool_count": len(discovered.all_tools),
        "tool_names": [tool.name for tool in discovered.all_tools],
        "resolved_security_tool": discovered.security_scan,
        "resolved_architecture_tool": discovered.architecture_analyze,
        "tools": discovered.summary(),
    }
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(asyncio.run(main()))
    except OpseraOAuthError as exc:
        print(f"OAuth error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
