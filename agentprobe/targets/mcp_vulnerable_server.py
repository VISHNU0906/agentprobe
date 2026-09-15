"""Vulnerable mock MCP server over stdio.

    python -m agentprobe.targets.mcp_vulnerable_server
"""

from . import mcp_common


def main():
    mcp_common.run(mcp_common.VULNERABLE)


if __name__ == "__main__":
    main()
