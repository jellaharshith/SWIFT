#!/usr/bin/env python3
"""Convert swift JSON scan report to PDF using reportlab."""

import html
import json
import sys
from pathlib import Path
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER


SEVERITY_COLORS = {
    "critical": colors.HexColor("#c0392b"),
    "high":     colors.HexColor("#e67e22"),
    "medium":   colors.HexColor("#f1c40f"),
    "low":      colors.HexColor("#27ae60"),
    "info":     colors.HexColor("#2980b9"),
}


def _sev_color(sev: str):
    return SEVERITY_COLORS.get(str(sev).lower(), colors.grey)


def build_pdf(json_path: str, pdf_path: str) -> None:
    with open(json_path) as f:
        data = json.load(f)

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("title", parent=styles["Title"],
                                  fontSize=22, spaceAfter=6, textColor=colors.HexColor("#1a1a2e"))
    h2 = ParagraphStyle("h2", parent=styles["Heading2"],
                         fontSize=13, spaceBefore=12, spaceAfter=4,
                         textColor=colors.HexColor("#16213e"))
    normal = styles["Normal"]
    small = ParagraphStyle("small", parent=normal, fontSize=9, textColor=colors.grey)
    code_style = ParagraphStyle("code", parent=normal, fontName="Courier",
                                 fontSize=8, backColor=colors.HexColor("#f5f5f5"))

    story = []

    # Header
    target = data.get("target", data.get("url", "Unknown target"))
    story.append(Paragraph("SWIFT Security Scan Report", title_style))
    story.append(Paragraph(f"Target: {target}", h2))
    ts = data.get("timestamp") or data.get("scan_time") or datetime.now().isoformat()
    story.append(Paragraph(f"Generated: {ts}", small))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.3*cm))

    # Summary table
    findings = data.get("findings") or data.get("vulnerabilities") or []
    if isinstance(findings, dict):
        findings = list(findings.values())

    counts = {}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1

    if counts:
        story.append(Paragraph("Summary", h2))
        table_data = [["Severity", "Count"]]
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in counts:
                table_data.append([sev.upper(), str(counts[sev])])
        tbl = Table(table_data, colWidths=[6*cm, 3*cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9f9f9")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 0.4*cm))

    # Findings
    if findings:
        story.append(Paragraph(f"Findings ({len(findings)})", h2))
        for i, vuln in enumerate(findings, 1):
            sev = str(vuln.get("severity", "info")).lower()
            sev_color = _sev_color(sev)
            name = vuln.get("name") or vuln.get("type") or vuln.get("title") or f"Finding {i}"

            # Finding header row
            header_tbl = Table([[
                Paragraph(f"<b>{i}. {name}</b>", normal),
                Paragraph(f"<b>{sev.upper()}</b>",
                          ParagraphStyle("sev", parent=normal, textColor=sev_color, fontSize=10))
            ]], colWidths=[13*cm, 3*cm])
            header_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f0f4ff")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LINEABOVE", (0, 0), (-1, 0), 2, sev_color),
            ]))
            story.append(header_tbl)

            desc = vuln.get("description") or vuln.get("details") or ""
            if desc:
                story.append(Paragraph(html.escape(str(desc)[:800]), normal))

            url = vuln.get("url") or vuln.get("endpoint") or ""
            if url:
                story.append(Paragraph(f"<b>URL:</b> {html.escape(str(url))}", small))

            evidence = vuln.get("evidence") or vuln.get("payload") or ""
            if evidence:
                story.append(Paragraph(f"Evidence: {html.escape(str(evidence)[:300])}", code_style))

            remediation = vuln.get("remediation") or vuln.get("fix") or vuln.get("recommendation") or ""
            if remediation:
                story.append(Paragraph(f"<b>Fix:</b> {html.escape(str(remediation)[:400])}", normal))

            story.append(Spacer(1, 0.25*cm))
    else:
        story.append(Paragraph("No findings recorded.", normal))

    # Raw metadata fallback
    if not findings and not counts:
        story.append(Paragraph("Raw output:", h2))
        raw = json.dumps(data, indent=2)[:3000]
        story.append(Paragraph(raw.replace("\n", "<br/>").replace(" ", "&nbsp;"), code_style))

    doc.build(story)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: generate_pdf_report.py <input.json> <output.pdf>")
        sys.exit(1)
    build_pdf(sys.argv[1], sys.argv[2])
    print(f"PDF saved: {sys.argv[2]}")
