"""Supply chain vulnerability probe — dependency confusion + typosquatting."""
from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import urlparse

import httpx

from sdk.base import BaseModule, Finding, Phase, Severity, VulnType

try:
    from audit.decorators import audit_logged
    from sdk.decorators import roe_gated
except ImportError:
    def audit_logged(x):
        def dec(f): return f
        return dec
    def roe_gated(x):
        def dec(f): return f
        return dec


def _typosquats(name: str) -> list[str]:
    variants: set[str] = set()
    for i in range(len(name) - 1):
        s = list(name)
        s[i], s[i + 1] = s[i + 1], s[i]
        variants.add("".join(s))
    variants.add(name.replace("-", ""))
    variants.add(name + "-lib")
    variants.add(name + "-utils")
    return [v for v in variants if v != name]


class SupplyChainProbe(BaseModule):
    name = "supply_chain"
    phase = Phase.OSINT
    vuln_types = [VulnType.SUPPLY_CHAIN, VulnType.DEPENDENCY_CONFUSION]  # noqa: RUF012
    author = "swift-core"
    version = "1.0"

    @roe_gated("osint")
    @audit_logged("probe_executed")
    async def probe(self, target, session, roe) -> list[Finding]:
        base_url = str(target)
        params = getattr(target, "params", {}) or {}
        findings: list[Finding] = []

        parsed = urlparse(base_url)
        parts = parsed.netloc.split(":")[0].split(".")
        org = parts[-2] if len(parts) >= 2 else parts[0]

        package_names: list[str] = list(params.get("package_names", [org]))
        if org not in package_names:
            package_names.insert(0, org)

        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            for path in ["/requirements.txt", "/package.json"]:
                try:
                    resp = await client.get(base_url.rstrip("/") + path)
                    if resp.status_code == 200:
                        if path.endswith(".txt"):
                            names = re.findall(r"^([a-zA-Z0-9_\-]+)", resp.text, re.MULTILINE)
                        else:
                            pkg = json.loads(resp.text)
                            deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
                            names = list(deps.keys())
                        package_names.extend(names[:20])
                except Exception:
                    pass

            for pkg_name in set(package_names):
                tasks = [
                    self._check_pypi(client, pkg_name, base_url),
                    self._check_npm(client, pkg_name, base_url),
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, Finding):
                        findings.append(r)

            for pkg_name in list(set(package_names))[:5]:
                for typo in _typosquats(pkg_name):
                    try:
                        resp = await client.get(f"https://pypi.org/pypi/{typo}/json", timeout=5)
                        if resp.status_code == 200:
                            findings.append(Finding(
                                module=self.name,
                                vuln_type=VulnType.SUPPLY_CHAIN,
                                severity=Severity.MEDIUM,
                                title=f"Typosquat risk: '{typo}' on PyPI (mirrors '{pkg_name}')",
                                description=f"Package '{typo}' exists on PyPI — typo variant of '{pkg_name}'. Developers may install wrong package.",
                                target_url=base_url,
                                confidence=0.85,
                                remediation=f"Register '{typo}' on PyPI to block typosquatting of '{pkg_name}'.",
                            ))
                    except Exception:
                        pass

        return findings

    async def _check_pypi(self, client: httpx.AsyncClient, name: str, base_url: str):
        try:
            resp = await client.get(f"https://pypi.org/pypi/{name}/json", timeout=8)
            if resp.status_code == 404:
                return Finding(
                    module=self.name,
                    vuln_type=VulnType.DEPENDENCY_CONFUSION,
                    severity=Severity.HIGH,
                    title=f"Dependency confusion: '{name}' not on PyPI",
                    description=f"'{name}' not registered on PyPI. Attacker could publish malicious package with same name.",
                    target_url=base_url,
                    confidence=0.96,
                    request_evidence=f"GET https://pypi.org/pypi/{name}/json → 404",
                    remediation=f"Register '{name}' on PyPI as placeholder to prevent dependency confusion.",
                )
        except Exception:
            pass
        return None

    async def _check_npm(self, client: httpx.AsyncClient, name: str, base_url: str):
        try:
            resp = await client.get(f"https://registry.npmjs.org/{name}", timeout=8)
            if resp.status_code == 404:
                return Finding(
                    module=self.name,
                    vuln_type=VulnType.DEPENDENCY_CONFUSION,
                    severity=Severity.HIGH,
                    title=f"Dependency confusion: '{name}' not on NPM",
                    description=f"'{name}' not registered on NPM. Attacker could publish malicious package.",
                    target_url=base_url,
                    confidence=0.96,
                    request_evidence=f"GET https://registry.npmjs.org/{name} → 404",
                    remediation=f"Register '{name}' on NPM to prevent dependency confusion.",
                )
        except Exception:
            pass
        return None
