"""Mobile APK static analysis probe — apktool decompile + secret grep."""
from __future__ import annotations

import asyncio
import glob
import os
import re
import tempfile
from pathlib import Path

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

PATTERNS = {
    "api_key": (
        re.compile(r'(?i)(api[_-]?key|apikey|secret|token|password)\s*[=:]\s*[\'"][a-zA-Z0-9_\-]{10,}[\'"]'),
        Severity.CRITICAL,
        VulnType.MOBILE_HARDCODED_SECRET,
    ),
    "hardcoded_creds": (
        re.compile(r'(?i)(username|password|passwd|pwd)\s*[=:]\s*[\'"][^\'"]{4,}[\'"]'),
        Severity.CRITICAL,
        VulnType.MOBILE_HARDCODED_SECRET,
    ),
    "http_endpoint": (
        re.compile(r'http://[a-zA-Z0-9./:\-_?&=]+'),
        Severity.HIGH,
        VulnType.MOBILE_HARDCODED_SECRET,
    ),
}

SCAN_EXTS = (".smali", ".xml", ".java", ".kt", ".json", ".properties")


class MobileStaticProbe(BaseModule):
    name = "mobile_static"
    phase = Phase.ACTIVE
    vuln_types = [VulnType.MOBILE_HARDCODED_SECRET]  # noqa: RUF012
    author = "swift-core"
    version = "1.0"

    @roe_gated("active_scan")
    @audit_logged("probe_executed")
    async def probe(self, target, session, roe) -> list[Finding]:
        params = getattr(target, "params", {}) or {}
        apk_path = params.get("apk_path", "")

        if not apk_path:
            apks = glob.glob("*.apk") + glob.glob("**/*.apk", recursive=True)
            if not apks:
                return []
            apk_path = apks[0]

        apk_path = str(Path(apk_path).resolve())
        if not os.path.exists(apk_path):
            return []

        findings: list[Finding] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = os.path.join(tmpdir, "decompiled")
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "run", "--rm",
                    "-v", f"{apk_path}:/app.apk:ro",
                    "-v", f"{tmpdir}:/output",
                    "kalilinux/kali-rolling",
                    "apktool", "d", "/app.apk", "-o", "/output/decompiled", "-f",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=120)
            except Exception:
                return []

            found: dict[str, list[str]] = {}
            scan_root = output_dir if os.path.exists(output_dir) else tmpdir
            for root, _, files in os.walk(scan_root):
                for fname in files:
                    if not fname.endswith(SCAN_EXTS):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        content = Path(fpath).read_text(encoding="utf-8", errors="replace")
                        for pname, (regex, sev, vtype) in PATTERNS.items():
                            matches = regex.findall(content)
                            if matches:
                                found.setdefault(pname, []).extend(
                                    f"{fname}: {m}" for m in matches[:3]
                                )
                    except Exception:
                        continue

            for pname, examples in found.items():
                _, severity, vuln_type = PATTERNS[pname]
                findings.append(Finding(
                    module=self.name,
                    vuln_type=vuln_type,
                    severity=severity,
                    title=f"APK secret: {pname} ({len(examples)} hit(s))",
                    description=f"Found {pname} in decompiled APK. Examples: {'; '.join(examples[:3])}",
                    target_url=apk_path,
                    confidence=0.95,
                    request_evidence=f"apktool d {os.path.basename(apk_path)}",
                    response_evidence="\n".join(examples[:5]),
                    remediation="Remove hardcoded secrets. Use Android Keystore. Obfuscate with ProGuard/R8.",
                ))

        return findings
