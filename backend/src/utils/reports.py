import io
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from sqlmodel import Session

from src.core.models import (
    Scan,
    Finding,
    Severity,
    get_findings_for_scan,
    get_risk_label,
)

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, KeepTogether
    from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


def _count_by_severity(findings: List[Finding]) -> Dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def _severity_color(level: str):
    return {
        "critical": colors.HexColor("#dc2626"),
        "high": colors.HexColor("#ea580c"),
        "medium": colors.HexColor("#f59e0b"),
        "low": colors.HexColor("#16a34a"),
        "info": colors.HexColor("#2563eb"),
    }.get(level, colors.grey)


def _risk_color(score: Optional[int]):
    if score is None:
        return colors.grey
    if score > 80:
        return colors.HexColor("#dc2626")
    if score > 60:
        return colors.HexColor("#ea580c")
    if score > 30:
        return colors.HexColor("#f59e0b")
    return colors.HexColor("#16a34a")


def generate_pdf_report(scan: Scan, findings: List[Finding]) -> bytes:
    if not REPORTLAB_AVAILABLE:
        raise ImportError("Install reportlab to generate PDF reports")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        topMargin=0.4 * inch,
        bottomMargin=0.4 * inch,
        leftMargin=0.4 * inch,
        rightMargin=0.4 * inch,
    )

    styles = getSampleStyleSheet()
    
    style_title = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=24,
        textColor=colors.HexColor("#0f172a"),
        alignment=TA_CENTER,
        spaceAfter=12,
    )
    
    style_subtitle = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#64748b"),
        alignment=TA_CENTER,
    )
    
    style_finding_title = ParagraphStyle(
        "FindingTitle",
        parent=styles["Normal"],
        fontSize=12,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#0f172a"),
        leading=14,
    )
    
    style_finding_sev = ParagraphStyle(
        "FindingSev",
        parent=styles["Normal"],
        fontSize=10,
        fontName="Helvetica-Bold",
        textColor=colors.white,
        alignment=TA_CENTER,
    )
    
    style_meta = ParagraphStyle(
        "Meta",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.HexColor("#475569"),
        fontName="Helvetica",
    )
    
    style_remediation = ParagraphStyle(
        "Remediation",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#334155"),
        leading=13,
    )

    story = []

    story.append(Paragraph("Security Scan Report", style_title))
    story.append(Paragraph(scan.url, style_subtitle))
    story.append(Spacer(1, 0.4 * inch))

    info_data = [
        ["Scan ID", f"{scan.id}"],
        ["Target URL", Paragraph(scan.url, styles["Normal"])],
        ["Status", scan.status.value.upper()],
        ["Scan Date", scan.created_at.strftime("%Y-%m-%d %H:%M UTC") if scan.created_at else "N/A"],
        ["Risk Score", f"{scan.risk_score or 'N/A'} / 100"],
        ["Total Findings", str(len(findings))],
    ]

    info_table = Table(info_data, colWidths=[1.5 * inch, 6.2 * inch])
    info_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")), 
                ("BACKGROUND", (1, 0), (-1, -1), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#334155")),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )

    story.append(info_table)
    story.append(Spacer(1, 0.4 * inch))

    counts = _count_by_severity(findings)

    col_w = 7.7 * inch / 5.0
    
    summary_data = [
        [
            str(counts["critical"]),
            str(counts["high"]),
            str(counts["medium"]),
            str(counts["low"]),
            str(counts["info"]),
        ],
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
    ]

    summary_table = Table(summary_data, colWidths=[col_w] * 5, rowHeights=[0.8 * inch, 0.4 * inch])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("GRID", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
                # Numbers Row (Row 0)
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#0f172a")), 
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 24),
                ("ALIGN", (0, 0), (-1, 0), "CENTER"),
                ("VALIGN", (0, 0), (-1, 0), "MIDDLE"),
                # Adjusted padding for Numbers to prevent touching lines
                ("TOPPADDING", (0, 0), (-1, 0), 10),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
                
                # Labels Row (Row 1)
                ("TEXTCOLOR", (0, 1), (-1, 1), colors.HexColor("#64748b")), 
                ("FONTNAME", (0, 1), (-1, 1), "Helvetica"),
                ("FONTSIZE", (0, 1), (-1, 1), 10),
                ("ALIGN", (0, 1), (-1, 1), "CENTER"),
                ("VALIGN", (0, 1), (-1, 1), "TOP"),
                ("TOPPADDING", (0, 1), (-1, 1), 8),
                ("BOTTOMPADDING", (0, 1), (-1, 1), 12),
            ]
        )
    )

    story.append(summary_table)
    story.append(Spacer(1, 0.4 * inch))

    if findings:
        story.append(Paragraph("Detailed Findings", styles["Heading2"]))
        story.append(Spacer(1, 0.2 * inch))
        
        severity_order = ["critical", "high", "medium", "low", "info"]
        findings_sorted = sorted(
            findings,
            key=lambda f: severity_order.index(f.severity.value),
        )

        for f in findings_sorted:
            title_p = Paragraph(f.title, style_finding_title)
            sev_p = Paragraph(f.severity.value.upper(), style_finding_sev)
            
            path_safe = (f.path or 'N/A').replace('&', '&amp;').replace('<', '&lt;')
            meta_str = f"<b>Confidence:</b> {f.confidence}% &nbsp;&nbsp;&nbsp; <b>Path:</b> {path_safe}"
            meta_p = Paragraph(meta_str, style_meta)
            
            remediation_safe = (f.remediation or 'No specific remediation steps provided.').replace('&', '&amp;').replace('<', '&lt;').replace('\n', '<br/>')
            rem_str = f"<b>Remediation:</b><br/>{remediation_safe}"
            rem_p = Paragraph(rem_str, style_remediation)
            
            item_data = [
                [title_p, sev_p],
                [meta_p, ""],
                [rem_p, ""],
            ]
            
            t = Table(item_data, colWidths=[6.5 * inch, 1.2 * inch])
            
            sev_bg = _severity_color(f.severity.value)
            
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#f8fafc")),
                        ("BACKGROUND", (1, 0), (1, 0), sev_bg),                    
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("TOPPADDING", (0, 0), (-1, -1), 8),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                        ("SPAN", (0, 1), (1, 1)),
                        ("SPAN", (0, 2), (1, 2)),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#FFFFFA")),
                    ]
                )
            )
            
            story.append(KeepTogether(t))
            story.append(Spacer(1, 0.25 * inch))

    footer_text = f"Generated by VibeSecure on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph(footer_text, ParagraphStyle("Footer", parent=styles["Normal"], alignment=TA_CENTER, textColor=colors.grey, fontSize=8)))

    doc.build(story)
    pdf = buffer.getvalue()
    buffer.close()
    return pdf


def generate_json_report(scan: Scan, findings: List[Finding]) -> Dict[str, Any]:
    return {
        "scan": {
            "id": scan.id,
            "url": scan.url,
            "status": scan.status.value,
            "risk_score": scan.risk_score,
            "risk_label": get_risk_label(scan.risk_score),
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
        },
        "summary": {
            "total": len(findings),
            "by_severity": _count_by_severity(findings),
        },
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "path": f.path,
                "remediation": f.remediation,
            }
            for f in findings
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def export_report(scan_id: str, session: Session, output_format: str = "json") -> Dict[str, Any]:
    scan = session.get(Scan, scan_id)
    if not scan:
        return {"status": "error", "error": "Scan not found"}

    findings = get_findings_for_scan(session, scan_id)

    if output_format == "pdf":
        if not REPORTLAB_AVAILABLE:
            return {"status": "error", "error": "reportlab is required for PDF export"}

        return {
            "status": "success",
            "format": "pdf",
            "scan_id": scan_id,
            "pdf_bytes": generate_pdf_report(scan, findings),
        }

    return {
        "status": "success",
        "format": "json",
        "scan_id": scan_id,
        "data": generate_json_report(scan, findings),
    }


__all__ = ["export_report", "generate_pdf_report", "generate_json_report"]