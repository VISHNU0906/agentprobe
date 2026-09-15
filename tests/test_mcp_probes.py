"""Every applicable probe must fire on the vulnerable MCP server and none on the hardened one."""

from agentprobe.adapters import MCPStdioAdapter
from agentprobe.probes import PROBES, run_all

from conftest import HARD_MCP, VULN_MCP

MCP_PROBE_IDS = {p.id for p in PROBES if "mcp" in p.applies_to}


def _scan(command):
    target = MCPStdioAdapter(command)
    try:
        return {r.probe.id: r for r in run_all(target)}
    finally:
        target.close()


def test_all_mcp_probes_fire_on_vulnerable():
    results = _scan(VULN_MCP)
    for pid in MCP_PROBE_IDS:
        assert results[pid].status == "fired", (pid, results[pid].evidence)


def test_no_mcp_probe_fires_on_hardened():
    results = _scan(HARD_MCP)
    for pid in MCP_PROBE_IDS:
        assert results[pid].status == "not_fired", (pid, results[pid].evidence)


def test_http_probes_are_skipped_on_mcp():
    results = _scan(VULN_MCP)
    for pid, r in results.items():
        if pid not in MCP_PROBE_IDS:
            assert r.status == "skipped"
