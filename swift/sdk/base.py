"""Base classes for SWIFT probe modules."""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from agent.models import Vulnerability


class Phase(str, Enum):
    OSINT = "osint"
    ACTIVE = "active"
    POST_EXPLOIT = "post_exploit"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnType(str, Enum):
    SSRF = "ssrf"
    OOB_SSRF = "oob_ssrf"
    SQLI = "sqli"
    XSS = "xss"
    IDOR = "idor"
    JWT = "jwt"
    OAUTH = "oauth"
    WEBSOCKET = "websocket"
    BIZLOGIC = "bizlogic"
    GRAPHQL = "graphql"
    CSRF = "csrf"
    SSTI = "ssti"
    OPEN_REDIRECT = "open_redirect"
    PRIV_ESC = "priv_esc"
    API_KEY = "api_key"
    SMUGGLING = "smuggling"
    CLOUD_MISCONFIGURATION = "cloud_misconfiguration"
    SUPPLY_CHAIN = "supply_chain"
    CREDENTIAL_BREACH = "credential_breach"
    KERBEROAST = "kerberoast"
    MOBILE_HARDCODED_SECRET = "mobile_hardcoded_secret"
    DEPENDENCY_CONFUSION = "dependency_confusion"


@dataclass
class Finding:
    """Standardised vulnerability finding produced by a BaseModule probe."""

    module: str
    vuln_type: VulnType
    severity: Severity
    title: str
    description: str
    target_url: str
    confidence: float
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request_evidence: str | None = None
    response_evidence: str | None = None
    screenshot_path: Path | None = None
    oob_confirmed: bool = False
    chain_primitive: str | None = None
    cwe_id: int | None = None
    cvss_vector: str | None = None
    remediation: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_metadata: dict = field(default_factory=dict)

    def to_vulnerability(self) -> Vulnerability:
        from agent.models import Vulnerability
        return Vulnerability(
            id=self.id,
            file_path=self.target_url,
            line_number=0,
            vuln_type=self.vuln_type.value,
            description=self.description,
            confidence=self.confidence,
            severity=self.severity.value,
            code_snippet=self.request_evidence or "",
            cwe_id=f"CWE-{self.cwe_id}" if self.cwe_id else None,
            exploit_description=self.title,
            remediation=self.remediation,
        )


class BaseModule(ABC):
    """Abstract base for all SWIFT probe modules.

    Subclasses MUST define: name, phase, vuln_types, author, version
    """

    name: str = ""
    phase: Phase = Phase.ACTIVE
    vuln_types: ClassVar[list[VulnType]] = []
    author: str = ""
    version: str = ""
    requires: ClassVar[list[str]] = []

    @abstractmethod
    async def probe(self, target, session, roe) -> list[Finding]: ...

    async def on_finding(self, finding: Finding) -> None: pass  # noqa: B027
    async def on_complete(self, findings: list[Finding]) -> None: pass  # noqa: B027

    @classmethod
    def validate_subclass(cls) -> None:
        for attr in ("name", "phase", "vuln_types", "author", "version"):
            if not getattr(cls, attr, None):
                raise NotImplementedError(
                    f"{cls.__name__} must define class variable '{attr}'"
                )
