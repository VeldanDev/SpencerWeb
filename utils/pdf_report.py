"""
Spencer v3.0 — PDF Report Generator
Generate laporan audit keamanan profesional dalam format PDF.
Cocok untuk diserahkan ke mitra UMKM sebagai deliverable.

Menggunakan reportlab — library Python untuk PDF generation.
"""

import os
import datetime
from urllib.parse import urlparse

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm, inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, KeepTogether
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


# Color palette untuk severity
SEVERITY_COLORS_PDF = {
    "CRITICAL": colors.HexColor("#8B0000") if REPORTLAB_AVAILABLE else None,
    "HIGH":     colors.HexColor("#DC2626") if REPORTLAB_AVAILABLE else None,
    "MEDIUM":   colors.HexColor("#EA580C") if REPORTLAB_AVAILABLE else None,
    "LOW":      colors.HexColor("#0891B2") if REPORTLAB_AVAILABLE else None,
    "INFO":     colors.HexColor("#16A34A") if REPORTLAB_AVAILABLE else None,
}

GRADE_COLORS = {
    "A": colors.HexColor("#16A34A") if REPORTLAB_AVAILABLE else None,
    "B": colors.HexColor("#65A30D") if REPORTLAB_AVAILABLE else None,
    "C": colors.HexColor("#CA8A04") if REPORTLAB_AVAILABLE else None,
    "D": colors.HexColor("#EA580C") if REPORTLAB_AVAILABLE else None,
    "F": colors.HexColor("#DC2626") if REPORTLAB_AVAILABLE else None,
    "?": colors.HexColor("#6B7280") if REPORTLAB_AVAILABLE else None,
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def generate_pdf_report(json_report: dict, output_path: str = None) -> str:
    """
    Generate PDF report dari hasil scan Spencer.
    
    Args:
        json_report: Dict hasil scan (loaded dari report JSON)
        output_path: Path output PDF. Default: reports/spencer_{domain}_{ts}.pdf
    
    Returns:
        Path file PDF yang berhasil di-generate
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError("reportlab tidak terinstall. Run: pip install reportlab")
    
    # Determine output path
    if not output_path:
        target = json_report["scan_info"]["target"]
        domain = urlparse(target).netloc.replace(".", "_")
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        rdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reports")
        os.makedirs(rdir, exist_ok=True)
        output_path = os.path.join(rdir, f"spencer_{domain}_{ts}.pdf")
    
    # Setup document
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
        title=f"Spencer Security Audit Report — {urlparse(json_report['scan_info']['target']).netloc}",
        author="Spencer Web Security Audit Tool"
    )
    
    # Styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=24,
        textColor=colors.HexColor("#1E40AF"),
        spaceAfter=20,
        alignment=TA_CENTER
    )
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor("#475569"),
        alignment=TA_CENTER,
        spaceAfter=12
    )
    h1_style = ParagraphStyle(
        'CustomH1',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=12,
        spaceBefore=20
    )
    h2_style = ParagraphStyle(
        'CustomH2',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=8,
        spaceBefore=14
    )
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['BodyText'],
        fontSize=10,
        leading=14,
        spaceAfter=6,
        alignment=TA_JUSTIFY
    )
    
    # Story (content list)
    story = []
    
    # ═══ COVER PAGE ═══
    story.append(Spacer(1, 4*cm))
    story.append(Paragraph("LAPORAN AUDIT KEAMANAN WEBSITE", title_style))
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph("Spencer Web Security Audit Tool", subtitle_style))
    story.append(Spacer(1, 2*cm))
    
    # Info box
    scan_info = json_report["scan_info"]
    target = scan_info["target"]
    domain = urlparse(target).netloc
    timestamp = scan_info.get("timestamp", "")
    try:
        scan_date = datetime.datetime.fromisoformat(timestamp).strftime("%d %B %Y, %H:%M:%S WIB")
    except Exception:
        scan_date = timestamp
    
    info_data = [
        ["Target Website", domain],
        ["URL Lengkap", target],
        ["Tanggal Audit", scan_date],
        ["Metode", scan_info.get("method", "OWASP Top 10 + CVSS")],
        ["Tool", scan_info.get("tool", "Spencer")],
        ["Durasi Scan", f"{scan_info.get('scan_duration_seconds', '?')} detik"],
    ]
    info_table = Table(info_data, colWidths=[5*cm, 11*cm])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#F1F5F9")),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor("#0F172A")),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('PADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 3*cm))
    
    # Grade box
    grade_info = json_report.get("grade", {})
    grade = grade_info.get("grade", "?")
    score = grade_info.get("score", 0)
    grade_color = GRADE_COLORS.get(grade, colors.gray)
    
    grade_table = Table(
        [[f"SECURITY GRADE: {grade}", f"SKOR: {score}/100"]],
        colWidths=[8*cm, 8*cm]
    )
    grade_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), grade_color),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 18),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 20),
    ]))
    story.append(grade_table)
    
    story.append(PageBreak())
    
    # ═══ EXECUTIVE SUMMARY ═══
    story.append(Paragraph("1. RINGKASAN EKSEKUTIF", h1_style))
    
    all_findings = json_report.get("all_findings", [])
    fails = [f for f in all_findings if f.get("status") == "FAIL"]
    
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in fails:
        sev = f.get("severity", "INFO")
        severity_count[sev] = severity_count.get(sev, 0) + 1
    
    stats = json_report.get("statistics", {})
    
    summary_text = f"""
    Audit keamanan website <b>{domain}</b> telah dilakukan pada tanggal <b>{scan_date}</b>
    menggunakan Spencer Web Security Audit Tool. Audit ini menggunakan metodologi OWASP Top 10
    dengan sistem penilaian risiko CVSS yang disederhanakan menjadi grade A-F.
    <br/><br/>
    
    Berdasarkan {stats.get('total_checks', 0)} pengecekan keamanan yang dilakukan, sistem mendapat
    grade <b>{grade}</b> dengan skor <b>{score}/100</b>. Ditemukan total
    <b>{len(fails)} kerentanan</b> yang terdiri dari:
    """
    story.append(Paragraph(summary_text, body_style))
    
    # Severity breakdown table
    sev_data = [
        ["Severity", "Jumlah", "Dampak"],
        ["CRITICAL", str(severity_count["CRITICAL"]), "Risiko tertinggi, harus segera diperbaiki"],
        ["HIGH", str(severity_count["HIGH"]), "Risiko tinggi, perbaiki dalam waktu dekat"],
        ["MEDIUM", str(severity_count["MEDIUM"]), "Risiko sedang, jadwalkan perbaikan"],
        ["LOW", str(severity_count["LOW"]), "Risiko rendah, perbaikan opsional"],
    ]
    sev_table = Table(sev_data, colWidths=[3*cm, 2*cm, 11*cm])
    sev_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E40AF")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('TEXTCOLOR', (0, 1), (0, 1), SEVERITY_COLORS_PDF["CRITICAL"]),
        ('TEXTCOLOR', (0, 2), (0, 2), SEVERITY_COLORS_PDF["HIGH"]),
        ('TEXTCOLOR', (0, 3), (0, 3), SEVERITY_COLORS_PDF["MEDIUM"]),
        ('TEXTCOLOR', (0, 4), (0, 4), SEVERITY_COLORS_PDF["LOW"]),
        ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 0.5*cm))
    
    # ═══ METODOLOGI ═══
    story.append(Paragraph("2. METODOLOGI AUDIT", h1_style))
    methodology_text = """
    Audit ini dilakukan menggunakan pendekatan <b>Black-box Testing</b> — auditor tidak memiliki
    akses ke source code maupun infrastruktur internal, dan hanya berinteraksi dengan target
    sebagaimana attacker dari luar.
    <br/><br/>
    
    <b>Framework yang digunakan:</b>
    <br/>• <b>OWASP Top 10</b> — standar industri untuk web application security testing
    <br/>• <b>OWASP Testing Guide v4</b> — panduan teknis pengujian per kategori
    <br/>• <b>CVSS v3.1</b> — Common Vulnerability Scoring System untuk penilaian risiko
    <br/><br/>
    
    <b>Module yang dijalankan:</b>
    <br/>1. HTTP Security Headers Audit (Passive)
    <br/>2. SSL/TLS Certificate Audit (Passive)
    <br/>3. Sensitive File Exposure Scan (Passive)
    <br/>4. CMS Detection & Version Check (Passive)
    <br/>5. WordPress Plugin & Theme Scanner (Passive)
    <br/>6. SQL Injection Scanner — Error, Boolean, Time-based (Active)
    <br/>7. Reflected XSS Scanner (Active)
    <br/>8. Stored XSS Scanner (Active)
    <br/>9. CSRF Protection Checker (Active)
    <br/>10. Open Port Reconnaissance (Active)
    """
    story.append(Paragraph(methodology_text, body_style))
    story.append(PageBreak())
    
    # ═══ TEMUAN ═══
    story.append(Paragraph("3. TEMUAN KERENTANAN", h1_style))
    
    if not fails:
        story.append(Paragraph(
            "<b>Tidak ditemukan kerentanan signifikan.</b> Website Anda memiliki konfigurasi "
            "keamanan yang baik berdasarkan parameter yang diuji.",
            body_style
        ))
    else:
        # Sort findings by severity
        fails_sorted = sorted(fails, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 4))
        
        for i, f in enumerate(fails_sorted, 1):
            severity = f.get("severity", "INFO")
            sev_color = SEVERITY_COLORS_PDF.get(severity, colors.gray)
            
            # Finding header dengan severity badge
            header_data = [[
                Paragraph(f"<b>Temuan #{i}: {_escape(f.get('check', 'Unknown'))}</b>",
                         ParagraphStyle('h', fontSize=11, textColor=colors.white)),
                Paragraph(f"<b>{severity}</b>",
                         ParagraphStyle('s', fontSize=10, textColor=colors.white, alignment=TA_CENTER))
            ]]
            header_table = Table(header_data, colWidths=[13*cm, 3*cm])
            header_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), sev_color),
                ('PADDING', (0, 0), (-1, -1), 8),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            
            # Detail dan recommendation
            detail = f.get("detail", "-")
            recommendation = f.get("recommendation", "-")
            
            detail_table_data = [
                [Paragraph("<b>Deskripsi:</b>", body_style),
                 Paragraph(_escape(detail), body_style)],
                [Paragraph("<b>Rekomendasi:</b>", body_style),
                 Paragraph(_escape(recommendation), body_style)],
            ]
            detail_table = Table(detail_table_data, colWidths=[3.5*cm, 12.5*cm])
            detail_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('PADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ]))
            
            # Keep header+detail together
            story.append(KeepTogether([header_table, detail_table, Spacer(1, 0.4*cm)]))
    
    story.append(PageBreak())
    
    # ═══ DETAIL PER MODULE ═══
    story.append(Paragraph("4. DETAIL HASIL PER MODULE", h1_style))
    
    module_names = {
        "headers":         "Module 1 — HTTP Security Headers",
        "ssl":             "Module 2 — SSL/TLS Certificate",
        "sensitive_files": "Module 3 — Sensitive File Exposure",
        "cms":             "Module 4 — CMS Detection",
        "wordpress":       "Module 5 — WordPress Plugin Scanner",
        "sqli_advanced":   "Module 6 — Advanced SQL Injection",
        "sqli":            "Module 6 — SQL Injection (Basic)",
        "xss":             "Module 7 — Reflected XSS",
        "stored_xss":      "Module 8 — Stored XSS",
        "csrf":            "Module 9 — CSRF Protection",
        "ports":           "Module 10 — Port Reconnaissance",
    }
    
    modules = json_report.get("modules", {})
    for key, name in module_names.items():
        if key not in modules:
            continue
        m = modules[key]
        story.append(Paragraph(name, h2_style))
        
        m_passed = m.get("passed", 0)
        m_failed = m.get("failed", 0)
        m_total = m_passed + m_failed
        
        if "error" in m:
            story.append(Paragraph(
                f"<i>Module error: {_escape(m['error'])}</i>",
                body_style
            ))
        else:
            stats_text = f"Passed: <b>{m_passed}</b> | Failed: <b>{m_failed}</b> | Total: <b>{m_total}</b>"
            story.append(Paragraph(stats_text, body_style))
            
            # Tampilkan FAIL findings dari module ini
            module_fails = [f for f in m.get("findings", []) if f.get("status") == "FAIL"]
            if module_fails:
                fail_data = [["Check", "Severity"]]
                for f in module_fails[:15]:
                    fail_data.append([
                        f.get("check", "")[:50],
                        f.get("severity", "")
                    ])
                fail_table = Table(fail_data, colWidths=[12*cm, 4*cm])
                fail_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E40AF")),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.3, colors.HexColor("#CBD5E1")),
                    ('PADDING', (0, 0), (-1, -1), 4),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ]))
                story.append(fail_table)
        story.append(Spacer(1, 0.3*cm))
    
    story.append(PageBreak())
    
    # ═══ KESIMPULAN & SARAN ═══
    story.append(Paragraph("5. KESIMPULAN DAN SARAN PRIORITAS", h1_style))
    
    priority_critical = severity_count["CRITICAL"]
    priority_high = severity_count["HIGH"]
    
    if priority_critical + priority_high > 0:
        conclusion_text = f"""
        Berdasarkan hasil audit, website <b>{domain}</b> memiliki <b>{priority_critical} kerentanan
        CRITICAL</b> dan <b>{priority_high} kerentanan HIGH</b> yang memerlukan perhatian segera.
        <br/><br/>
        
        <b>Saran prioritas perbaikan:</b>
        """
    else:
        conclusion_text = f"""
        Berdasarkan hasil audit, website <b>{domain}</b> tidak memiliki kerentanan kritis,
        namun masih ada beberapa item yang dapat diperbaiki untuk meningkatkan postur keamanan.
        <br/><br/>
        
        <b>Saran perbaikan:</b>
        """
    story.append(Paragraph(conclusion_text, body_style))
    
    # Top 5 prioritized recommendations
    top_fails = sorted(fails, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 4))[:5]
    for i, f in enumerate(top_fails, 1):
        rec_text = f"<b>{i}. [{f.get('severity')}] {_escape(f.get('check', ''))}</b><br/>{_escape(f.get('recommendation', ''))}"
        story.append(Paragraph(rec_text, body_style))
        story.append(Spacer(1, 0.2*cm))
    
    # Disclaimer
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("DISCLAIMER", h2_style))
    disclaimer = """
    Laporan ini dihasilkan secara otomatis oleh Spencer Web Security Audit Tool.
    Audit dilakukan pada waktu dan kondisi tertentu;
    kondisi keamanan website dapat berubah seiring waktu. Hasil audit ini hanya mencakup
    parameter yang diuji oleh tool dan tidak menggantikan audit keamanan manual oleh
    professional security expert. Beberapa temuan automated scanner dapat berupa false
    positive dan harus diverifikasi secara manual sebelum tindakan perbaikan diambil.
    """
    story.append(Paragraph(disclaimer, body_style))
    
    # Footer line
    story.append(Spacer(1, 0.5*cm))
    footer_text = f"""
    <para alignment="center"><i>Generated by Spencer v2.0 — {datetime.datetime.now().strftime('%d %B %Y')}</i></para>
    """
    story.append(Paragraph(footer_text, body_style))
    
    # Build PDF
    doc.build(story)
    
    return output_path


def _escape(text: str) -> str:
    """Escape special characters untuk reportlab Paragraph."""
    if not isinstance(text, str):
        text = str(text)
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))
