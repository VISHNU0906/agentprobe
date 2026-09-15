"""CLI smoke test: a scan against a running mock agent writes findings files."""

import json
import os

from agentprobe.__main__ import main

from conftest import VULN_MCP


def test_cli_scan_http_writes_findings(http_vulnerable, tmp_path):
    out = str(tmp_path / "http_vuln")
    code = main(["scan", "--openai", http_vulnerable.url, "--out", out])
    assert code == 0
    data = json.loads(open(os.path.join(out, "findings.json"), encoding="utf-8").read())
    assert data["summary"]["fired"] >= 1
    assert os.path.exists(os.path.join(out, "report.md"))


def test_cli_scan_mcp_writes_findings(tmp_path):
    out = str(tmp_path / "mcp_vuln")
    code = main(["scan", "--mcp", VULN_MCP, "--out", out])
    assert code == 0
    data = json.loads(open(os.path.join(out, "findings.json"), encoding="utf-8").read())
    assert data["summary"]["fired"] >= 1


def test_cli_scan_requires_exactly_one_target(tmp_path):
    code = main(["scan", "--out", str(tmp_path / "x")])
    assert code == 2


def test_cli_rejects_both_targets(tmp_path):
    code = main(["scan", "--openai", "http://127.0.0.1:1", "--mcp", "x", "--out", str(tmp_path)])
    assert code == 2
