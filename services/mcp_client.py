import logging
import re
from dataclasses import dataclass
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import Tool

import httpx

logger = logging.getLogger(__name__)


class OpseraMcpError(Exception):
    """Raised when Opsera MCP operations fail."""


@dataclass
class DiscoveredTools:
    all_tools: list[Tool]
    security_scan: str | None
    architecture_analyze: str | None
    tool_map: dict[str, Tool]

    def summary(self) -> list[dict[str, Any]]:
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.inputSchema,
            }
            for tool in self.all_tools
        ]


def _normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _score_tool(name: str, keywords: tuple[str, ...]) -> int:
    normalized = _normalize(name)
    score = 0
    for keyword in keywords:
        if keyword in normalized:
            score += 10
    return score


def discover_tools(tools: list[Tool]) -> DiscoveredTools:
    """Resolve tool names from live tools/list — never hardcode."""
    tool_map = {tool.name: tool for tool in tools}

    security_candidates = sorted(
        tools,
        key=lambda t: _score_tool(t.name, ("security", "scan", "vuln", "sast", "secret")),
        reverse=True,
    )
    architecture_candidates = sorted(
        tools,
        key=lambda t: _score_tool(
            t.name, ("architecture", "analyze", "analyse", "design", "structure")
        ),
        reverse=True,
    )

    security_scan = None
    for tool in security_candidates:
        score = _score_tool(tool.name, ("security", "scan"))
        if score >= 20:
            security_scan = tool.name
            break

    architecture_analyze = None
    for tool in architecture_candidates:
        score = _score_tool(tool.name, ("architecture", "analyze"))
        if score >= 20:
            architecture_analyze = tool.name
            break

    logger.info(
        "Discovered MCP tools: total=%d security=%s architecture=%s names=%s",
        len(tools),
        security_scan,
        architecture_analyze,
        [t.name for t in tools],
    )

    return DiscoveredTools(
        all_tools=tools,
        security_scan=security_scan,
        architecture_analyze=architecture_analyze,
        tool_map=tool_map,
    )


class OpseraMcpClient:
    """MCP client for Opsera using streamable-http and OAuth bearer token."""

    def __init__(
        self,
        mcp_url: str,
        access_token: str,
        timeout: float = 300.0,
    ) -> None:
        self.mcp_url = mcp_url
        self.access_token = access_token
        self.timeout = timeout
        self._discovered: DiscoveredTools | None = None

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}

    async def list_tools(self) -> DiscoveredTools:
        tools = await self._with_session(self._list_tools_in_session)
        self._discovered = discover_tools(tools)
        return self._discovered

    async def get_discovered_tools(self) -> DiscoveredTools:
        if self._discovered is not None:
            return self._discovered
        return await self.list_tools()

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        return await self._with_session(
            lambda session: self._call_tool_in_session(session, name, arguments)
        )

    async def _with_session(self, operation):
        headers = self._headers()
        async with httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(self.timeout, read=self.timeout),
        ) as http_client:
            async with streamable_http_client(self.mcp_url, http_client=http_client) as (
                read_stream,
                write_stream,
                _,
            ):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    return await operation(session)

    @staticmethod
    async def _list_tools_in_session(session: ClientSession) -> list[Tool]:
        result = await session.list_tools()
        return result.tools

    @staticmethod
    async def _call_tool_in_session(
        session: ClientSession, name: str, arguments: dict[str, Any]
    ) -> Any:
        result = await session.call_tool(name, arguments)
        content: list[Any] = []
        if result.content:
            for block in result.content:
                if hasattr(block, "text"):
                    content.append(block.text)
                elif hasattr(block, "model_dump"):
                    content.append(block.model_dump())
                else:
                    content.append(str(block))
        return {
            "isError": result.isError,
            "content": content,
            "structuredContent": getattr(result, "structuredContent", None),
        }
