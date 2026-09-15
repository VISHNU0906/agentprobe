"""Run the deliberately vulnerable mock agent HTTP server.

    python -m agentprobe.targets.agent_vulnerable [port]
"""

import sys

from . import agent_common


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    server = agent_common.serve(agent_common.VULNERABLE, port=port)
    server.serve_forever()


if __name__ == "__main__":
    main()
