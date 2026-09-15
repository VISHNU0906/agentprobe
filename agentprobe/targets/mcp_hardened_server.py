"""Hardened mock MCP server over stdio.

    python -m agentprobe.targets.mcp_hardened_server
"""

from . import mcp_common


def main():
    mcp_common.run(mcp_common.HARDENED)


if __name__ == "__main__":
    main()
