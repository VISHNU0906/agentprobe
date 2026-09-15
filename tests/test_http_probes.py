"""Every applicable probe must fire on the vulnerable HTTP agent and none on the hardened one."""

from agentprobe.adapters import OpenAIChatAdapter
from agentprobe.probes import PROBES, run_all

HTTP_PROBE_IDS = {p.id for p in PROBES if "openai" in p.applies_to}


def _scan(url):
    target = OpenAIChatAdapter(url)
    try:
        return {r.probe.id: r for r in run_all(target)}
    finally:
        target.close()


def test_all_http_probes_fire_on_vulnerable(http_vulnerable):
    results = _scan(http_vulnerable.url)
    for pid in HTTP_PROBE_IDS:
        assert results[pid].status == "fired", (pid, results[pid].evidence)


def test_no_http_probe_fires_on_hardened(http_hardened):
    results = _scan(http_hardened.url)
    for pid in HTTP_PROBE_IDS:
        assert results[pid].status == "not_fired", (pid, results[pid].evidence)


def test_mcp_probes_are_skipped_on_http(http_vulnerable):
    results = _scan(http_vulnerable.url)
    for pid, r in results.items():
        if pid not in HTTP_PROBE_IDS:
            assert r.status == "skipped"


def test_evidence_strings_are_present_when_fired(http_vulnerable):
    results = _scan(http_vulnerable.url)
    for pid in HTTP_PROBE_IDS:
        assert results[pid].evidence.strip()
