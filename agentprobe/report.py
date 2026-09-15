"""Findings output: a JSON file and a markdown report.

The JSON file is the machine-readable record, one entry per probe with its
status and evidence string. The markdown report is a short human summary that
lists what fired, what did not, and what was skipped.
"""

import json
import os
from datetime import datetime, timezone


def build_findings(target_label, target_kind, results):
    """Assemble a findings document from a list of ProbeResult."""
    entries = [r.as_dict() for r in results]
    summary = {"fired": 0, "not_fired": 0, "skipped": 0, "error": 0}
    for entry in entries:
        summary[entry["status"]] = summary.get(entry["status"], 0) + 1
    return {
        "tool": "agentprobe",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target_label": target_label,
        "target_kind": target_kind,
        "summary": summary,
        "findings": entries,
    }


def write_json(findings, path):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(findings, handle, indent=2)
        handle.write("\n")


_STATUS_LABEL = {
    "fired": "FIRED",
    "not_fired": "not fired",
    "skipped": "skipped",
    "error": "ERROR",
}


def render_markdown(findings):
    """Render a findings document as a markdown report string."""
    lines = []
    lines.append("# agentprobe findings")
    lines.append("")
    lines.append("Target: " + findings["target_label"] + " (" + findings["target_kind"] + ")")
    lines.append("")
    lines.append("Generated: " + findings["generated_at"])
    lines.append("")
    s = findings["summary"]
    lines.append(
        "Summary: fired %d, not fired %d, skipped %d, error %d"
        % (s.get("fired", 0), s.get("not_fired", 0), s.get("skipped", 0), s.get("error", 0))
    )
    lines.append("")
    lines.append("| Probe | Category | Severity | Status | Evidence |")
    lines.append("| --- | --- | --- | --- | --- |")
    for f in findings["findings"]:
        evidence = f["evidence"].replace("|", "\\|")
        lines.append(
            "| %s | %s | %s | %s | %s |"
            % (f["name"], f["category"], f["severity"], _STATUS_LABEL[f["status"]], evidence)
        )
    lines.append("")
    lines.append("Severity is a fixed property of each probe, not a score for the target.")
    lines.append("")
    return "\n".join(lines)


def write_markdown(findings, path):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render_markdown(findings))


def write_all(findings, out_dir):
    """Write findings.json and report.md into ``out_dir``, creating it if needed."""
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "findings.json")
    md_path = os.path.join(out_dir, "report.md")
    write_json(findings, json_path)
    write_markdown(findings, md_path)
    return json_path, md_path
