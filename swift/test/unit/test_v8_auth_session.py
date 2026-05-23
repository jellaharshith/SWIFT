"""v8.0 -- auth session propagation."""
from __future__ import annotations

from bounty.auth_session import (
    AuthSession,
    cli_args_for,
    clear_session,
    env_for_tool,
    get_session,
    set_session,
)


def setup_function():
    clear_session("E1")


def test_set_get_clear():
    s = AuthSession("E1", bearer="tok", cookies={"sid": "s1"})
    set_session(s)
    assert get_session("E1") is s
    clear_session("E1")
    assert get_session("E1") is None


def test_httpx_flags_include_bearer_and_cookie():
    s = AuthSession("E1", bearer="tok", cookies={"sid": "s1"})
    args = cli_args_for("httpx", s)
    joined = " ".join(args)
    assert "Cookie: sid=s1" in joined
    assert "Authorization: Bearer tok" in joined


def test_unknown_tool_returns_empty():
    s = AuthSession("E1", bearer="tok")
    assert cli_args_for("nmap", s) == []


def test_env_vars_for_tool():
    s = AuthSession("E1", bearer="tok", cookies={"sid": "s1"}, headers={"X-Token": "v"})
    set_session(s)
    env = env_for_tool("httpx", "E1")
    assert env["SWIFT_AUTH_BEARER"] == "tok"
    assert env["SWIFT_AUTH_COOKIE"].startswith("sid=")
    assert env["SWIFT_AUTH_H_X_TOKEN"] == "v"
    clear_session("E1")
