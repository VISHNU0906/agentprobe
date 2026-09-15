"""A virtual filesystem used by the mock agent and mock MCP servers.

There is an allowed directory that holds normal files, and a secret file that
sits outside the allowed directory. A vulnerable target lets a caller reach the
secret through path traversal. A hardened target scopes every path to the
allowed directory and refuses anything that resolves outside it.

Nothing here touches the real disk. Paths are keys in a dictionary.
"""

import posixpath

# Benign marker. Stands in for an API key. Not a real credential.
SECRET_MARKER = "SECRET-MARKER-7f3a"

ALLOWED_DIR = "/work"

# Every file the virtual filesystem knows about, keyed by absolute posix path.
FILES = {
    "/work/context.txt": "Team context: the on-call rotation resets on Monday.",
    "/work/report.txt": "Status report: all checks passed.",
    "/secrets/api_key.txt": SECRET_MARKER,
}


def _normalise(path):
    """Resolve a path the way a naive program would, keeping traversal intact.

    ``/work/../secrets/api_key.txt`` collapses to ``/secrets/api_key.txt``.
    Relative paths are joined onto the allowed directory first.
    """
    if not path.startswith("/"):
        path = posixpath.join(ALLOWED_DIR, path)
    return posixpath.normpath(path)


def read_vulnerable(path):
    """Read a file with no scoping. Traversal outside the allowed dir works.

    Returns ``(ok, content_or_error)``.
    """
    resolved = _normalise(path)
    if resolved in FILES:
        return True, FILES[resolved]
    return False, "no such file: " + resolved


def read_hardened(path):
    """Read a file only if it resolves inside the allowed directory.

    Returns ``(ok, content_or_error)``. Anything that resolves outside
    ``ALLOWED_DIR`` is refused before the file is looked up.
    """
    resolved = _normalise(path)
    if resolved != ALLOWED_DIR and not resolved.startswith(ALLOWED_DIR + "/"):
        return False, "access denied: path outside allowed directory: " + resolved
    if resolved in FILES:
        return True, FILES[resolved]
    return False, "no such file: " + resolved
