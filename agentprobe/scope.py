"""Scope guard for network targets.

By default the tool only talks to loopback addresses. A non-loopback target
requires two things: the ``--authorized`` flag, and a scope file that lists the
host. The check is a literal comparison. It does not resolve DNS, so a hostname
is only in scope if that exact hostname appears in the scope file.

This guard applies to HTTP targets. MCP targets here are local subprocesses and
do not open a network socket, so the scope guard does not gate them.
"""

import ipaddress


class ScopeError(RuntimeError):
    """Raised when a target is outside the allowed scope."""


def is_loopback(host):
    """Return True for loopback hosts by literal rule, without DNS lookup."""
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def load_scope_file(path):
    """Read a scope file into a set of host strings.

    One host per line. Blank lines and lines starting with ``#`` are ignored.
    """
    hosts = set()
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith("#"):
                hosts.add(line)
    return hosts


def enforce(host, authorized=False, scope_hosts=None):
    """Raise ScopeError unless the host is allowed.

    Loopback hosts are always allowed. Any other host needs both
    ``authorized`` and membership in ``scope_hosts``.
    """
    scope_hosts = scope_hosts or set()
    if is_loopback(host):
        return
    if not authorized:
        raise ScopeError(
            "target host %r is not loopback; pass --authorized and a --scope file" % host
        )
    if host not in scope_hosts:
        raise ScopeError(
            "target host %r is not listed in the scope file" % host
        )
