"""Scope guard: loopback allowed, non-loopback needs authorisation and scope."""

import pytest

from agentprobe import scope


def test_loopback_is_allowed_without_flags():
    scope.enforce("127.0.0.1")  # no exception
    scope.enforce("localhost")
    scope.enforce("::1")


def test_non_loopback_refused_without_authorized():
    with pytest.raises(scope.ScopeError):
        scope.enforce("198.51.100.10")


def test_non_loopback_allowed_when_authorized_and_in_scope():
    scope.enforce("198.51.100.10", authorized=True, scope_hosts={"198.51.100.10"})


def test_non_loopback_refused_when_host_absent_from_scope():
    with pytest.raises(scope.ScopeError):
        scope.enforce("198.51.100.10", authorized=True, scope_hosts={"203.0.113.5"})


def test_is_loopback_literal_only():
    assert scope.is_loopback("127.0.0.1") is True
    assert scope.is_loopback("10.0.0.1") is False
    assert scope.is_loopback("") is False


def test_load_scope_file(tmp_path):
    p = tmp_path / "scope.txt"
    p.write_text("# hosts\n198.51.100.10\n\nexample.internal\n", encoding="utf-8")
    hosts = scope.load_scope_file(str(p))
    assert hosts == {"198.51.100.10", "example.internal"}
