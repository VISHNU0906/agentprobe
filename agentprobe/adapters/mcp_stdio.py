"""Adapter for an MCP server over stdio, newline-delimited JSON-RPC 2.0.

It launches a subprocess, runs the ``initialize`` handshake, sends the
``notifications/initialized`` notification, and then supports ``tools/list``
and ``tools/call``. It reads the child's stdout on a background thread and
matches responses to requests by id, which avoids the missing ``select`` on
Windows pipes.

No external MCP SDK is used.
"""

import json
import os
import queue
import shlex
import shutil
import subprocess
import threading

from .base import ToolResult, Target


class MCPStdioError(RuntimeError):
    pass


def _split_command(command):
    """Split a command line into argv, resolving the executable on PATH.

    On Windows, ``shlex.split`` in posix mode would eat backslashes in paths,
    so posix mode follows ``os.name``. The first token is resolved with
    ``shutil.which`` so entries like ``npx`` map to ``npx.cmd``.
    """
    argv = shlex.split(command, posix=(os.name != "nt"))
    if not argv:
        raise MCPStdioError("empty command")
    if os.name == "nt":
        argv = [a.strip('"') for a in argv]
    resolved = shutil.which(argv[0])
    if resolved:
        argv[0] = resolved
    elif argv[0] in ("python", "python3"):
        # Some systems expose only the interpreter that is running us.
        import sys

        argv[0] = sys.executable
    return argv


class MCPStdioAdapter(Target):
    kind = "mcp"

    def __init__(self, command, first_timeout=60, timeout=30, cwd=None):
        self.command = command
        self.timeout = timeout
        self._id = 0
        self._q = queue.Queue()
        argv = _split_command(command)
        self._proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=cwd,
        )
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self._initialize(first_timeout)

    def _read_loop(self):
        for line in self._proc.stdout:
            self._q.put(line)
        self._q.put(None)

    def _next_id(self):
        self._id += 1
        return self._id

    def _send(self, obj):
        self._proc.stdin.write((json.dumps(obj) + "\n").encode("utf-8"))
        self._proc.stdin.flush()

    def _await(self, want_id, timeout):
        """Read lines until a JSON response with the wanted id arrives."""
        while True:
            try:
                line = self._q.get(timeout=timeout)
            except queue.Empty:
                raise MCPStdioError("timeout waiting for id %s" % want_id)
            if line is None:
                raise MCPStdioError("server closed before id %s" % want_id)
            line = line.decode("utf-8", "replace").strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue  # skip any non-JSON log line
            if msg.get("id") == want_id:
                return msg

    def _request(self, method, params, timeout):
        rid = self._next_id()
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        msg = self._await(rid, timeout)
        if "error" in msg:
            raise MCPStdioError(str(msg["error"]))
        return msg.get("result", {})

    def _initialize(self, first_timeout):
        self.server_info = self._request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "agentprobe", "version": "1.0.0"},
            },
            first_timeout,
        )
        # Notification: no id, no reply expected.
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def list_tools(self):
        result = self._request("tools/list", {}, self.timeout)
        return result.get("tools", [])

    def call_tool(self, name, args):
        result = self._request("tools/call", {"name": name, "arguments": args}, self.timeout)
        parts = []
        for block in result.get("content", []):
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
        return ToolResult("\n".join(parts), bool(result.get("isError")), result)

    def close(self):
        try:
            if self._proc.stdin and not self._proc.stdin.closed:
                self._proc.stdin.close()
        except OSError:
            pass
        self._proc.terminate()
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
