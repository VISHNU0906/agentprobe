"""Adapters that give probes one interface over HTTP and MCP targets."""

from .base import Response, Target, ToolResult
from .openai_chat import OpenAIChatAdapter
from .mcp_stdio import MCPStdioAdapter, MCPStdioError

__all__ = [
    "Response",
    "Target",
    "ToolResult",
    "OpenAIChatAdapter",
    "MCPStdioAdapter",
    "MCPStdioError",
]
