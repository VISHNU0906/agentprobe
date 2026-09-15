"""Common target interface shared by the HTTP and MCP adapters.

A probe never talks to a transport directly. It calls the methods on a target
and reads a small set of plain data structures. This keeps probes independent
of whether the target is an OpenAI-style HTTP endpoint or an MCP server.
"""


class Response:
    """The result of one chat turn.

    text        assistant message text
    tool_calls  list of dicts, each with name, arguments (parsed), status, result
    raw         the untouched decoded payload, for evidence and debugging
    """

    def __init__(self, text, tool_calls, raw):
        self.text = text or ""
        self.tool_calls = tool_calls or []
        self.raw = raw

    def calls_named(self, name):
        return [c for c in self.tool_calls if c.get("name") == name]


class ToolResult:
    """The result of one MCP ``tools/call``."""

    def __init__(self, text, is_error, raw):
        self.text = text or ""
        self.is_error = is_error
        self.raw = raw


class Target:
    """Interface a probe relies on. Not every target supports every method.

    ``kind`` is either ``"openai"`` or ``"mcp"``. Probes use it to decide
    whether they apply. Methods that a target does not support raise
    ``NotImplementedError`` and the probe is reported as skipped.
    """

    kind = "unknown"

    def chat(self, messages):
        raise NotImplementedError

    def tools_schema(self):
        raise NotImplementedError

    def list_tools(self):
        raise NotImplementedError

    def call_tool(self, name, args):
        raise NotImplementedError

    def close(self):
        pass
