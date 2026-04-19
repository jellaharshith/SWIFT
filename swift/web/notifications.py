"""Email notifications for SWIFT scan completion using stdlib smtplib."""
from __future__ import annotations

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from agent.models import ScanResult
from log.logger import get_logger

logger = get_logger("web.notifications")

_SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
_SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
_SMTP_USER = os.environ.get("SMTP_USER", "")
_SMTP_PASS = os.environ.get("SMTP_PASS", "")
_FROM_EMAIL = os.environ.get("FROM_EMAIL", _SMTP_USER)


def send_scan_complete(recipient_email: str, scan_result: ScanResult) -> None:
    """Send an email notification when a scan completes.

    Args:
        recipient_email: Destination email address.
        scan_result: Completed ScanResult to summarise in the email.

    Raises:
        RuntimeError: If SMTP credentials are not configured or sending fails.
    """
    if not _SMTP_USER or not _SMTP_PASS:
        logger.warning(
            "SMTP credentials not configured — skipping notification for scan %s.",
            scan_result.scan_id,
        )
        return

    vuln_count = len(scan_result.vulnerabilities)
    patch_count = len(scan_result.patches)
    severity_summary = _build_severity_summary(scan_result)

    subject = f"[SWIFT] Scan {scan_result.scan_id} complete — {vuln_count} vulnerabilities found"
    body = (
        f"SWIFT Scan Complete\n"
        f"{'=' * 40}\n\n"
        f"Scan ID:       {scan_result.scan_id}\n"
        f"Repository:    {scan_result.repo_path}\n"
        f"Files scanned: {scan_result.files_scanned}\n"
        f"Vulns found:   {vuln_count}\n"
        f"Patches gen:   {patch_count}\n"
        f"Duration:      {scan_result.duration_seconds:.1f}s\n"
        f"Cost:          ${scan_result.total_cost_usd:.4f}\n"
        f"Timestamp:     {scan_result.timestamp}\n"
    )
    if severity_summary:
        body += f"\nSeverity breakdown:\n{severity_summary}\n"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = _FROM_EMAIL
    msg["To"] = recipient_email
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(_SMTP_HOST, _SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.login(_SMTP_USER, _SMTP_PASS)
            server.sendmail(_FROM_EMAIL, [recipient_email], msg.as_string())
        logger.info(
            "Scan complete notification sent to %s for scan %s.",
            recipient_email,
            scan_result.scan_id,
        )
    except Exception as exc:
        logger.error(
            "Failed to send notification for scan %s: %s",
            scan_result.scan_id,
            exc,
        )
        raise RuntimeError(f"Email notification failed: {exc}") from exc


def _build_severity_summary(scan_result: ScanResult) -> str:
    """Build a text summary of vulnerability severities.

    Args:
        scan_result: Completed scan result.

    Returns:
        Multi-line string with counts per severity level, or empty string if no vulns.
    """
    if not scan_result.vulnerabilities:
        return ""

    counts: dict[str, int] = {}
    for vuln in scan_result.vulnerabilities:
        counts[vuln.severity] = counts.get(vuln.severity, 0) + 1

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    lines = []
    for level in order:
        if level in counts:
            lines.append(f"  {level}: {counts[level]}")
    for level, count in counts.items():
        if level not in order:
            lines.append(f"  {level}: {count}")
    return "\n".join(lines)
