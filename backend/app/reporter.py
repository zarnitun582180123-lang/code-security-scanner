import io
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors


def generate_pdf_report(scan_id: int, repo_name: str, total_issues: int, vulnerabilities: list):
    buffer = io.BytesIO()
    # Margins လေးတွေကို နည်းနည်းကျဉ်းပြီး နေရာပိုကျယ်အောင် ယူထားပါတယ်
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    elements = []

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'TitleStyle', parent=styles['Heading1'], fontSize=20,
        textColor=colors.HexColor('#1E293B'), leading=24
    )
    subtitle_style = ParagraphStyle(
        'SubTitleStyle', parent=styles['Normal'], fontSize=11,
        textColor=colors.HexColor('#64748B'), leading=16
    )

    # Table Cell မူလ Style များ (Auto Word Wrap ရအောင် Paragraph သုံးမည်)
    cell_header_style = ParagraphStyle(
        'HeaderStyle', parent=styles['Normal'], fontSize=10,
        fontName='Helvetica-Bold', textColor=colors.whitesmoke
    )
    cell_body_style = ParagraphStyle(
        'BodyStyle', parent=styles['Normal'], fontSize=9,
        fontName='Helvetica', textColor=colors.HexColor('#1E293B'), leading=12
    )

    # Title & Metadata
    elements.append(Paragraph("<b>Code Security Audit Report</b>", title_style))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(f"<b>Repository:</b> {repo_name} | <b>Scan ID:</b> #{scan_id}", subtitle_style))
    elements.append(Paragraph(f"<b>Total Vulnerabilities Detected:</b> {total_issues}", subtitle_style))
    elements.append(Spacer(1, 15))

    # Table Header (Paragraph ဖြင့် ပတ်ပေးခြင်း)
    data = [[
        Paragraph("Severity", cell_header_style),
        Paragraph("Type", cell_header_style),
        Paragraph("File Path", cell_header_style),
        Paragraph("Line", cell_header_style)
    ]]

    # Table Data Body (Paragraph ဖြင့် ပတ်ပေးထား၍ စာလုံးရှည်လျှင် အလိုလို အောက်ကြောင်းဆင်းပါမည်)
    for item in vulnerabilities:
        data.append([
            Paragraph(str(item.severity), cell_body_style),
            Paragraph(str(item.vulnerability_type), cell_body_style),
            Paragraph(str(item.file_path), cell_body_style),
            Paragraph(str(item.line_number), cell_body_style)
        ])

    # Width များကို ချိန်ညှိထားခြင်း [Severity, Type, File Path, Line] Total = 540 (Letter Page Width)
    col_widths = [75, 185, 230, 50]

    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
    ]))

    elements.append(t)
    doc.build(elements)
    buffer.seek(0)
    return buffer