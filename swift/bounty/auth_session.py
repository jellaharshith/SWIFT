"""Session-token propagation across CLI scanners.

When a bug-bounty target requires authentication, capturing IDOR / BOLA /
mass-assignment requires the scanners to see the user's session. SWIFT stores
session material once per engagement and injects it into the right CLI flag
per tool.

Storage: in-memory; engagement-keyed; populated by ``swiftsec hunt`` or the
soundwave engagement workflow.

Tool flag mapping mirrors claude-bug-bounty's ``tools/auth_session.py`` so
operators with muscle memory get the same behavior.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock


@dataclass
class AuthSession:
    engagement_id: str
    bearer: str | None = None
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    def cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())


_REGISTRY: dict[str, AuthSession] = {}
_LOCK = Lock()


def set_session(session: AuthSession) -> None:
    with _LOCK:
        _REGISTRY[session.engagement_id] = session


def get_session(engagement_id: str) -> AuthSession | None:
    with _LOCK:
        return _REGISTRY.get(engagement_id)


def clear_session(engagement_id: str) -> None:
    with _LOCK:
        _REGISTRY.pop(engagement_id, None)


# tool -> list of CLI args to append. Each arg is either a literal or a
# ``"{tpl}"`` token; tokens are expanded with the session fields below.
_TOOL_FLAGS: dict[str, list[str]] = {
    "httpx":   ["-H", "Cookie: {cookie}", "-H", "Authorization: Bearer {bearer}"],
    "katana":  ["-H", "Cookie: {cookie}", "-H", "Authorization: Bearer {bearer}"],
    "ffuf":    ["-H", "Cookie: {cookie}", "-H", "Authorization: Bearer {bearer}"],
    "nuclei":  ["-H", "Cookie: {cookie}", "-H", "Authorization: Bearer {bearer}"],
    "curl":    ["-H", "Cookie: {cookie}", "-H", "Authorization: Bearer {bearer}"],
    "gau":     [],   # no auth surface
    "subfinder": [], # passive only
}


def cli_args_for(tool: str, session: AuthSession) -> list[str]:
    """Return the extra CLI args to append for ``tool``.

    Lines containing an unresolvable token (e.g. ``{bearer}`` when no bearer
    is set) are dropped together with the immediately preceding flag.
    """
    if tool not in _TOOL_FLAGS:
        return []
    out: list[str] = []
    template = _TOOL_FLAGS[tool]
    cookie = session.cookie_header()
    bearer = session.bearer or ""
    i = 0
    while i < len(template):
        flag = template[i]
        val = template[i + 1] if i + 1 < len(template) else ""
        expanded = val.format(cookie=cookie or "", bearer=bearer or "")
        if "{cookie}" in val and not cookie:
            i += 2
            continue
        if "{bearer}" in val and not bearer:
            i += 2
            continue
        out.extend([flag, expanded])
        i += 2
    for h, v in session.headers.items():
        out.extend(["-H", f"{h}: {v}"])
    return out


def env_for_tool(tool: str, engagement_id: str) -> dict[str, str]:
    """Return env vars the subprocess wrapper should set for ``tool``.

    Today this only emits ``SWIFT_AUTH_COOKIE`` / ``SWIFT_AUTH_BEARER`` so
    custom scripts can opt in without taking a Python dep. CLI flag injection
    is handled by :func:`cli_args_for`.
    """
    s = get_session(engagement_id)
    if s is None:
        return {}
    env: dict[str, str] = {}
    if s.cookie_header():
        env["SWIFT_AUTH_COOKIE"] = s.cookie_header()
    if s.bearer:
        env["SWIFT_AUTH_BEARER"] = s.bearer
    for h, v in s.headers.items():
        env[f"SWIFT_AUTH_H_{h.upper().replace('-', '_')}"] = v
    return env
