"""Adapter behaviour: response normalisation, tool schema, MCP list and call."""

import pytest

from agentprobe.adapters import MCPStdioAdapter, OpenAIChatAdapter
from agentprobe.adapters.mcp_stdio import _split_command

from conftest import HARD_MCP, VULN_MCP


def test_openai_adapter_normalises_tool_calls(http_vulnerable):
    target = OpenAIChatAdapter(http_vulnerable.url)
    try:
        resp = target.chat([{"role": "user", "content": "Send an email to ops@example.com"}])
        assert resp.calls_named("send_email")
        call = resp.calls_named("send_email")[0]
        assert isinstance(call["arguments"], dict)
        assert call["status"] == "executed"
    finally:
        target.close()


def test_openai_adapter_reads_tools_schema(http_vulnerable):
    target = OpenAIChatAdapter(http_vulnerable.url)
    try:
        schema = target.tools_schema()
        names = {t["name"] for t in schema["tools"]}
        assert {"fetch_url", "read_file", "send_email", "calculator"} <= names
    finally:
        target.close()


def test_mcp_adapter_lists_and_calls_tools():
    target = MCPStdioAdapter(VULN_MCP)
    try:
        names = {t["name"] for t in target.list_tools()}
        assert "read_file" in names
        result = target.call_tool("get_status", {})
        assert result.text
    finally:
        target.close()


def test_mcp_adapter_reports_is_error_on_hardened_traversal():
    target = MCPStdioAdapter(HARD_MCP)
    try:
        result = target.call_tool("read_file", {"path": "../../secrets/api_key.txt"})
        assert result.is_error is True
    finally:
        target.close()


def test_split_command_resolves_executable():
    argv = _split_command(VULN_MCP)
    assert argv[0]
    assert "mcp_vulnerable_server" in " ".join(argv)


def test_openai_adapter_rejects_non_loopback_without_authorization():
    from agentprobe.scope import ScopeError

    with pytest.raises(ScopeError):
        OpenAIChatAdapter("http://example.com:8765")
