"""Command line entry point for agentprobe.

    python -m agentprobe serve --target vulnerable --port 8765
    python -m agentprobe scan --openai http://127.0.0.1:8765 --out results/http_vulnerable
    python -m agentprobe scan --mcp "python -m agentprobe.targets.mcp_vulnerable_server" \
        --out results/mcp_vulnerable
"""

import argparse
import sys

from . import report
from .adapters import MCPStdioAdapter, OpenAIChatAdapter
from .probes import run_all
from .scope import ScopeError, load_scope_file
from .targets import agent_common


def _cmd_serve(args):
    policy = agent_common.VULNERABLE if args.target == "vulnerable" else agent_common.HARDENED
    server = agent_common.serve(policy, port=args.port)
    host, port = server.server_address
    print("serving %s mock agent on http://%s:%d" % (args.target, host, port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
    return 0


def _print_summary(findings):
    print("Target: %s (%s)" % (findings["target_label"], findings["target_kind"]))
    for f in findings["findings"]:
        print("  [%-9s] %-42s %s" % (f["status"], f["name"], f["category"]))
    s = findings["summary"]
    print(
        "Summary: fired %d, not fired %d, skipped %d, error %d"
        % (s.get("fired", 0), s.get("not_fired", 0), s.get("skipped", 0), s.get("error", 0))
    )


def _cmd_scan(args):
    if bool(args.openai) == bool(args.mcp):
        print("error: pass exactly one of --openai or --mcp", file=sys.stderr)
        return 2
    target = None
    try:
        if args.openai:
            scope_hosts = load_scope_file(args.scope) if args.scope else set()
            target = OpenAIChatAdapter(
                args.openai, authorized=args.authorized, scope_hosts=scope_hosts
            )
            label = args.openai
        else:
            target = MCPStdioAdapter(args.mcp)
            label = args.mcp
        results = run_all(target)
        findings = report.build_findings(label, target.kind, results)
    except ScopeError as exc:
        print("scope error: %s" % exc, file=sys.stderr)
        return 2
    finally:
        if target is not None:
            target.close()
    json_path, md_path = report.write_all(findings, args.out)
    _print_summary(findings)
    print("wrote %s" % json_path)
    print("wrote %s" % md_path)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="agentprobe", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run a mock agent HTTP server")
    serve.add_argument("--target", choices=["vulnerable", "hardened"], required=True)
    serve.add_argument("--port", type=int, default=8765)
    serve.set_defaults(func=_cmd_serve)

    scan = sub.add_parser("scan", help="run the probe catalogue against a target")
    scan.add_argument("--openai", help="base URL of an OpenAI-style chat endpoint")
    scan.add_argument(
        "--mcp", help="command that launches an MCP server over stdio (local process only)"
    )
    scan.add_argument("--out", required=True, help="output directory for findings")
    scan.add_argument(
        "--authorized",
        action="store_true",
        help="assert authorisation for a non-loopback HTTP target",
    )
    scan.add_argument("--scope", help="scope file listing allowed non-loopback hosts")
    scan.set_defaults(func=_cmd_scan)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
