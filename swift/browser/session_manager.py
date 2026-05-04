"""Shared session state for multi-step probe chains.

SessionManager holds cookies, JWT tokens, Authorization headers, and captured
credentials across all probes in a single scan. This enables:
- Credential reuse: SQLi → leaked password → login → JWT → IDOR
- Session hijack: captured cookie → replay as different user
- Auth chain: form-login → token capture → privileged probe
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Credential:
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    source: str = ""          # "sqli_dump", "jwt_replay", "form_login", "http_response"
    target_url: str = ""


class SessionManager:
    """Shared authentication/session state threaded through all browser probes.

    Usage:
        session = SessionManager()
        # Before each probe:
        await session.attach(page)
        # After each probe:
        await session.capture(page)
        # Check what we have:
        session.has_auth  # True if cookies or JWT captured
    """

    def __init__(self):
        self._cookies: Dict[str, Dict[str, str]] = {}  # domain → {name: value}
        self._headers: Dict[str, str] = {}
        self._jwt: Optional[str] = None
        self._credentials: List[Credential] = []
        self._local_storage: Dict[str, str] = {}
        self._session_storage: Dict[str, str] = {}

    @property
    def has_auth(self) -> bool:
        return bool(self._cookies or self._jwt or self._headers.get("Authorization"))

    @property
    def jwt(self) -> Optional[str]:
        return self._jwt

    @property
    def captured_credentials(self) -> List[Credential]:
        return list(self._credentials)

    async def attach(self, page: Any) -> None:
        """Inject current session state into a Playwright page before navigation."""
        try:
            # Set cookies
            if self._cookies:
                flat = []
                for domain, jar in self._cookies.items():
                    for name, value in jar.items():
                        flat.append({"name": name, "value": value,
                                     "domain": domain, "path": "/"})
                if flat:
                    await page.context.add_cookies(flat)

            # Set Authorization header (JWT or API key)
            if self._headers:
                await page.set_extra_http_headers(self._headers)
            elif self._jwt:
                await page.set_extra_http_headers({"Authorization": f"Bearer {self._jwt}"})

            # Restore localStorage if any
            if self._local_storage:
                storage_json = json.dumps(self._local_storage)
                await page.add_init_script(
                    f"Object.entries({storage_json}).forEach(([k,v]) => localStorage.setItem(k,v))"
                )
        except Exception:
            pass  # Attach failure is non-fatal; probe continues unauthenticated

    async def capture(self, page: Any) -> None:
        """Snapshot cookies and storage from page after a probe interaction."""
        try:
            cookies = await page.context.cookies()
            for c in cookies:
                domain = c.get("domain", "")
                if domain not in self._cookies:
                    self._cookies[domain] = {}
                self._cookies[domain][c["name"]] = c["value"]

            # Try to capture JWT from localStorage/sessionStorage
            try:
                ls = await page.evaluate("() => ({...localStorage})")
                if isinstance(ls, dict):
                    self._local_storage.update(ls)
                    for k, v in ls.items():
                        if "token" in k.lower() or "jwt" in k.lower() or "auth" in k.lower():
                            if v and len(v) > 20:
                                self._jwt = v
                                self._headers["Authorization"] = f"Bearer {v}"
            except Exception:
                pass
        except Exception:
            pass  # Capture failure is non-fatal

    def remember_credential(self, cred: Credential) -> None:
        """Store a discovered credential for chain reuse."""
        self._credentials.append(cred)

    def inject_jwt(self, token: str) -> None:
        """Manually inject a JWT (e.g. from SQLi dump or response body)."""
        self._jwt = token
        self._headers["Authorization"] = f"Bearer {token}"

    def as_httpx_headers(self) -> Dict[str, str]:
        """Return headers suitable for httpx direct HTTP calls."""
        h = dict(self._headers)
        if self._jwt and "Authorization" not in h:
            h["Authorization"] = f"Bearer {self._jwt}"
        return h

    def to_dict(self) -> dict:
        return {
            "has_auth": self.has_auth,
            "cookie_domains": list(self._cookies.keys()),
            "has_jwt": self._jwt is not None,
            "credential_count": len(self._credentials),
            "captured_headers": list(self._headers.keys()),
        }

    def save(self, path: Path) -> None:
        """Save session state to JSON (non-sensitive summary only)."""
        path.write_text(json.dumps(self.to_dict(), indent=2))
