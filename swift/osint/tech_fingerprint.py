"""Technology fingerprinting via HTTP response headers and body patterns."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Tuple

import httpx

__all__ = ["TechFingerprint", "TechFingerprintResult", "run_tech_fingerprint"]

# (name, category, pattern_type, pattern)
# pattern_type: "header:<header-name>", "cookie:<prefix>", "body:<regex>"
_SIGNATURES: List[Tuple[str, str, str, str]] = [
    # Web servers
    ("nginx", "server", "header:server", r"nginx"),
    ("apache", "server", "header:server", r"apache"),
    ("iis", "server", "header:server", r"microsoft-iis"),
    ("caddy", "server", "header:server", r"caddy"),
    ("litespeed", "server", "header:server", r"litespeed"),
    # App frameworks (X-Powered-By)
    ("php", "language", "header:x-powered-by", r"php"),
    ("asp.net", "framework", "header:x-powered-by", r"asp\.net"),
    ("express", "framework", "header:x-powered-by", r"express"),
    ("django", "framework", "header:x-powered-by", r"django"),
    # Framework detection via body
    ("react", "frontend", "body", r'react\.production|"__reactFiber|react-dom'),
    ("vue", "frontend", "body", r'vue\.min\.js|vue@\d|__vue__|vue\.runtime'),
    ("angular", "frontend", "body", r'ng-version|angular\.min\.js|angular/core'),
    ("next.js", "frontend", "body", r'__NEXT_DATA__|_next/static'),
    ("nuxt", "frontend", "body", r'__nuxt__|_nuxt/'),
    ("svelte", "frontend", "body", r'svelte\.dev|__svelte'),
    # CMS
    ("wordpress", "cms", "body", r'/wp-content/|/wp-includes/'),
    ("drupal", "cms", "body", r'Drupal\.settings|/sites/default/files'),
    ("joomla", "cms", "body", r'/components/com_|Joomla!'),
    ("magento", "cms", "body", r'Mage\.Cookies|/skin/frontend/'),
    # JS libraries
    ("jquery", "library", "body", r'jquery[.-]\d+\.\d+'),
    ("bootstrap", "library", "body", r'bootstrap\.min\.js|bootstrap\.min\.css'),
    ("lodash", "library", "body", r'lodash\.min\.js|window\._'),
    # Languages via error/body
    ("ruby-on-rails", "framework", "body", r'Ruby on Rails|rails\.js|Turbolinks'),
    ("laravel", "framework", "body", r'laravel_session|XSRF-TOKEN.*laravel'),
    ("spring", "framework", "body", r'spring-security|Spring Boot'),
    # DB errors in body (exposure)
    ("postgresql", "database", "body", r'pg_query\(|psycopg2|PostgreSQL.*ERROR'),
    ("mysql", "database", "body", r'You have an error in your SQL syntax|mysql_query\('),
    ("mongodb", "database", "body", r'MongoError|mongodb://'),
    ("sqlite", "database", "body", r'SQLite.*Exception|sqlite3\.OperationalError'),
    # Cookie-based
    ("php-session", "language", "cookie:PHPSESSID", r"."),
    ("asp-session", "framework", "cookie:ASP.NET_SessionId", r"."),
    ("laravel-cookie", "framework", "cookie:laravel_session", r"."),
    ("django-csrf", "framework", "cookie:csrftoken", r"."),
    # CDN / hosting
    ("cloudflare", "cdn", "header:cf-ray", r"."),
    ("cloudfront", "cdn", "header:x-amz-cf-id", r"."),
    ("fastly", "cdn", "header:x-served-by", r"cache-"),
]


@dataclass
class TechFingerprint:
    name: str
    category: str
    confidence: float
    evidence: str


@dataclass
class TechFingerprintResult:
    target: str
    technologies: List[TechFingerprint] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


async def run_tech_fingerprint(url: str, timeout: int = 15) -> TechFingerprintResult:
    """Fingerprint technologies used by *url* via headers and body patterns.

    Args:
        url: Full URL to probe (e.g. "https://example.com").
        timeout: HTTP request timeout in seconds.

    Returns:
        TechFingerprintResult with detected technologies.
    """
    result = TechFingerprintResult(target=url)
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; SWIFT-Scanner/5.0; +https://github.com/SWIFT)"
        )
    }

    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=False,  # noqa: S501 — fingerprinting may hit self-signed certs
        ) as client:
            resp = await client.get(url, headers=headers)
    except httpx.TimeoutException:
        result.errors.append("tech_fingerprint: request timed out")
        return result
    except Exception as exc:
        result.errors.append(f"tech_fingerprint: {exc}")
        return result

    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
    body = resp.text[:100_000]  # cap at 100 KB for pattern matching
    cookies = {c.name for c in resp.cookies}

    seen: set[str] = set()

    for name, category, pattern_type, pattern in _SIGNATURES:
        if name in seen:
            continue
        evidence: str | None = None

        if pattern_type.startswith("header:"):
            header_name = pattern_type[7:]
            header_val = resp_headers.get(header_name, "")
            if header_val and re.search(pattern, header_val, re.IGNORECASE):
                evidence = f"{header_name}: {header_val[:120]}"
        elif pattern_type.startswith("cookie:"):
            cookie_name = pattern_type[7:]
            if any(c.lower().startswith(cookie_name.lower()) for c in cookies):
                evidence = f"cookie: {cookie_name}"
        elif pattern_type == "body":
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                start = max(0, m.start() - 20)
                evidence = f"body: ...{body[start:m.end() + 20]}..."

        if evidence is not None:
            seen.add(name)
            result.technologies.append(
                TechFingerprint(
                    name=name,
                    category=category,
                    confidence=0.85,
                    evidence=evidence[:200],
                )
            )

    return result
