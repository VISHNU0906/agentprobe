"""Shared test fixtures: HTTP mock servers on an ephemeral port, MCP commands."""

import sys
import threading

import pytest

from agentprobe.targets import agent_common

VULN_MCP = '"%s" -m agentprobe.targets.mcp_vulnerable_server' % sys.executable
HARD_MCP = '"%s" -m agentprobe.targets.mcp_hardened_server' % sys.executable


class RunningServer:
    def __init__(self, server):
        self.server = server
        self.port = server.server_address[1]
        self.url = "http://127.0.0.1:%d" % self.port


@pytest.fixture
def http_vulnerable():
    yield from _serve(agent_common.VULNERABLE)


@pytest.fixture
def http_hardened():
    yield from _serve(agent_common.HARDENED)


def _serve(policy):
    server = agent_common.serve(policy, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield RunningServer(server)
    finally:
        server.shutdown()
        thread.join(timeout=5)
