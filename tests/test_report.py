"""Report building and rendering."""

import json

from agentprobe import report
from agentprobe.probes import PROBES, ProbeResult


def _sample_results():
    fired = ProbeResult(PROBES[0], "fired", "marker seen")
    skipped = ProbeResult(PROBES[-1], "skipped", "does not apply")
    return [fired, skipped]


def test_build_findings_counts_statuses():
    findings = report.build_findings("http://127.0.0.1:1", "openai", _sample_results())
    assert findings["summary"]["fired"] == 1
    assert findings["summary"]["skipped"] == 1
    assert len(findings["findings"]) == 2


def test_render_markdown_has_table_and_evidence():
    findings = report.build_findings("http://127.0.0.1:1", "openai", _sample_results())
    md = report.render_markdown(findings)
    assert "| Probe |" in md
    assert "marker seen" in md


def test_write_all_creates_files(tmp_path):
    findings = report.build_findings("http://127.0.0.1:1", "openai", _sample_results())
    json_path, md_path = report.write_all(findings, str(tmp_path / "out"))
    data = json.loads(open(json_path, encoding="utf-8").read())
    assert data["target_kind"] == "openai"
    assert open(md_path, encoding="utf-8").read().startswith("# agentprobe findings")
