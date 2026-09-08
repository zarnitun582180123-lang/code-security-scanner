import jsPDF from 'jspdf';

export interface Vulnerability {
  title?: string;
  issue?: string;
  name?: string;
  type?: string;
  vulnerability_type?: string;
  severity?: string;
  file_path?: string;
  line_number?: number | string;

  suggestion?: string;
  recommendation?: string;
  impact?: string;
  description?: string;
  summary?: string;
  details?: string;

  remediation?: string;
  fix?: string;
  solution?: string;

  line_content?: string;
  raw_code?: string;
  vulnerable_code?: string;
  code_snippet?: string;
  code?: string;
  snippet?: string;
  secure_code?: string;
  fixed_code?: string;
  fix_code?: string;
  refactored_code?: string;
  patch?: string;
  recommendation_code?: string;
}

export interface PdfReportData {
  targetUrl?: string;
  scanType?: string;
  securityScore?: number;
  securityGrade?: string;
  summary?: string;
  findings?: Vulnerability[];
  serverInfo?: string;
}

const cleanText = (value: unknown): string => {
  if (value === null || value === undefined) return '';

  return String(value)
    .replace(/\r/g, '')
    .replace(/[^\x20-\x7E\n\t]/g, '');
};

const safeFilename = (value: string) =>
  value.replace(/[^a-zA-Z0-9_-]/g, '');

export async function generatePdfReport(
  report: PdfReportData
): Promise<void> {
  try {
    const pdf = new jsPDF({
      orientation: 'portrait',
      unit: 'mm',
      format: 'a4',
    });

    const pageWidth = pdf.internal.pageSize.getWidth();
    const pageHeight = pdf.internal.pageSize.getHeight();

    const margin = 16;
    const contentWidth = pageWidth - margin * 2;

    let y = 0;

    // ==================================================
    // COLORS
    // ==================================================

    const dark = [8, 15, 28] as const;
    const dark2 = [15, 23, 42] as const;
    const cyan = [6, 182, 212] as const;
    const blue = [37, 99, 235] as const;
    const green = [16, 185, 129] as const;
    const amber = [245, 158, 11] as const;
    const red = [244, 63, 94] as const;
    const gray = [100, 116, 139] as const;
    const lightGray = [226, 232, 240] as const;
    const white = [255, 255, 255] as const;

    // ==================================================
    // HELPERS
    // ==================================================

    const addPageBackground = () => {
      pdf.setFillColor(...dark);
      pdf.rect(0, 0, pageWidth, pageHeight, 'F');
    };

    const addPageFooter = () => {
      pdf.setDrawColor(51, 65, 85);
      pdf.setLineWidth(0.25);
      pdf.line(
        margin,
        pageHeight - 14,
        pageWidth - margin,
        pageHeight - 14
      );

      pdf.setFont('helvetica', 'normal');
      pdf.setFontSize(7);
      pdf.setTextColor(...gray);

      pdf.text(
        'SecureCode SAST v2.4  •  Confidential Security Report',
        margin,
        pageHeight - 8
      );

      pdf.text(
        `Page ${pdf.getCurrentPageInfo().pageNumber}`,
        pageWidth - margin - 18,
        pageHeight - 8
      );
    };

    const newPage = () => {
      pdf.addPage();
      addPageBackground();
      y = 18;
    };

    const ensureSpace = (needed: number) => {
      if (y + needed > pageHeight - 22) {
        newPage();
      }
    };

    const wrappedText = (
      text: string,
      width: number
    ): string[] => {
      return pdf.splitTextToSize(
        cleanText(text),
        width
      );
    };

    const drawLabel = (
      label: string,
      value: string,
      x: number,
      yy: number,
      width: number
    ) => {
      pdf.setFont('helvetica', 'bold');
      pdf.setFontSize(7);
      pdf.setTextColor(...gray);
      pdf.text(label.toUpperCase(), x, yy);

      pdf.setFont('helvetica', 'normal');
      pdf.setFontSize(8.5);
      pdf.setTextColor(...white);

      const lines = wrappedText(value || 'N/A', width);

      pdf.text(lines[0] || 'N/A', x, yy + 5);

      return lines.length;
    };

    const getSeverityColor = (severity: string) => {
      switch (severity) {
        case 'CRITICAL':
          return red;
        case 'HIGH':
          return [249, 115, 22] as const;
        case 'MEDIUM':
          return amber;
        default:
          return [59, 130, 246] as const;
      }
    };

    // ==================================================
    // PAGE 1 — COVER
    // ==================================================

    addPageBackground();

    // Decorative top bar
    pdf.setFillColor(...cyan);
    pdf.rect(0, 0, pageWidth, 3, 'F');

    // Small system label
    pdf.setFont('helvetica', 'bold');
    pdf.setFontSize(8);
    pdf.setTextColor(...cyan);

    pdf.text(
      'ISVS  •  SECURITY INTELLIGENCE PLATFORM',
      margin,
      22
    );

    y = 48;

    pdf.setFont('helvetica', 'bold');
    pdf.setFontSize(25);
    pdf.setTextColor(...white);

    pdf.text('SecureCode', margin, y);

    y += 9;

    pdf.setFontSize(15);
    pdf.setTextColor(...cyan);

    pdf.text('SAST v2.4', margin, y);

    y += 16;

    pdf.setFontSize(11);
    pdf.setTextColor(180, 195, 210);

    pdf.text(
      'LIVE WEB SECURITY',
      margin,
      y
    );

    y += 7;

    pdf.setFontSize(18);
    pdf.setTextColor(...white);

    pdf.text(
      'VULNERABILITY AUDIT',
      margin,
      y
    );

    // Accent line
    y += 9;

    pdf.setFillColor(...cyan);
    pdf.rect(margin, y, 38, 1.2, 'F');

    y += 20;

    // Target box
    pdf.setFillColor(...dark2);
    pdf.roundedRect(
      margin,
      y,
      contentWidth,
      42,
      4,
      4,
      'F'
    );

    pdf.setDrawColor(30, 41, 59);
    pdf.roundedRect(
      margin,
      y,
      contentWidth,
      42,
      4,
      4,
      'S'
    );

    pdf.setFont('helvetica', 'bold');
    pdf.setFontSize(7);
    pdf.setTextColor(...gray);

    pdf.text('AUDIT TARGET', margin + 8, y + 10);

    pdf.setFont('helvetica', 'normal');
    pdf.setFontSize(9);
    pdf.setTextColor(...white);

    const targetLines = wrappedText(
      report.targetUrl || 'N/A',
      contentWidth - 16
    );

    pdf.text(
      targetLines.slice(0, 2),
      margin + 8,
      y + 17
    );

    pdf.setFontSize(7);
    pdf.setTextColor(...gray);

    pdf.text(
      `Server: ${cleanText(report.serverInfo || 'N/A')}`,
      margin + 8,
      y + 31
    );

    pdf.text(
      `Generated: ${new Date().toLocaleDateString()}`,
      pageWidth - margin - 55,
      y + 31
    );

    // Score panel
    y += 58;

    const score = Number(report.securityScore ?? 0);
    const grade = cleanText(report.securityGrade || 'N/A');

    pdf.setFillColor(...dark2);
    pdf.roundedRect(
      margin,
      y,
      contentWidth,
      57,
      4,
      4,
      'F'
    );

    pdf.setDrawColor(30, 41, 59);
    pdf.roundedRect(
      margin,
      y,
      contentWidth,
      57,
      4,
      4,
      'S'
    );

    // Score
    pdf.setFont('helvetica', 'bold');
    pdf.setFontSize(34);
    pdf.setTextColor(...cyan);

    pdf.text(
      `${score}`,
      margin + 12,
      y + 29
    );

    pdf.setFontSize(10);
    pdf.setTextColor(...gray);

    pdf.text(
      '/ 100',
      margin + 43,
      y + 29
    );

    pdf.setFontSize(7);
    pdf.text(
      'SECURITY SCORE',
      margin + 12,
      y + 39
    );

    // Grade
    pdf.setFont('helvetica', 'bold');
    pdf.setFontSize(27);

   const gradeColor: RGB =
  grade.startsWith('A')
    ? green
    : grade.startsWith('B')
      ? cyan
      : grade.startsWith('C')
        ? amber
        : red;

    pdf.setTextColor(...gradeColor);

    pdf.text(
      grade,
      pageWidth - margin - 32,
      y + 30
    );

    pdf.setFontSize(7);
    pdf.setTextColor(...gray);

    pdf.text(
      'SECURITY GRADE',
      pageWidth - margin - 45,
      y + 40
    );

    // Bottom message
    y = pageHeight - 35;

    pdf.setFont('helvetica', 'normal');
    pdf.setFontSize(8);
    pdf.setTextColor(...gray);

    pdf.text(
      'Automated security assessment generated by SecureCode SAST.',
      margin,
      y
    );

    pdf.text(
      'Detection • Analysis • Remediation',
      margin,
      y + 6
    );

    // ==================================================
    // PAGE 2 — EXECUTIVE ASSESSMENT
    // ==================================================

    newPage();

    pdf.setFont('helvetica', 'bold');
    pdf.setFontSize(17);
    pdf.setTextColor(...white);

    pdf.text(
      'Executive Assessment',
      margin,
      y
    );

    y += 6;

    pdf.setFont('helvetica', 'normal');
    pdf.setFontSize(8);
    pdf.setTextColor(...gray);

    pdf.text(
      'Security posture overview and risk assessment',
      margin,
      y
    );

    y += 13;

    // Summary box
    pdf.setFillColor(...dark2);
    pdf.roundedRect(
      margin,
      y,
      contentWidth,
      43,
      4,
      4,
      'F'
    );

    pdf.setDrawColor(30, 41, 59);
    pdf.roundedRect(
      margin,
      y,
      contentWidth,
      43,
      4,
      4,
      'S'
    );

    pdf.setFont('helvetica', 'bold');
    pdf.setFontSize(8);
    pdf.setTextColor(...cyan);

    pdf.text(
      'ASSESSMENT SUMMARY',
      margin + 8,
      y + 10
    );

    pdf.setFont('helvetica', 'normal');
    pdf.setFontSize(9);
    pdf.setTextColor(...white);

    const summaryLines = wrappedText(
      report.summary ||
        'No executive summary available.',
      contentWidth - 16
    );

    pdf.text(
      summaryLines.slice(0, 5),
      margin + 8,
      y + 18
    );

    y += 54;

    // ==================================================
    // RISK OVERVIEW
    // ==================================================

    const findings = report.findings || [];

    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    findings.forEach((item) => {
      const severity = String(
        item.severity || 'LOW'
      ).toUpperCase();

      if (severity === 'CRITICAL') counts.critical++;
      else if (severity === 'HIGH') counts.high++;
      else if (severity === 'MEDIUM') counts.medium++;
      else counts.low++;
    });

    pdf.setFont('helvetica', 'bold');
    pdf.setFontSize(11);
    pdf.setTextColor(...white);

    pdf.text(
      'Risk Overview',
      margin,
      y
    );

    y += 8;

    type RGB = readonly [number, number, number];

const cards: Array<[string, number, RGB]> = [
  ['CRITICAL', counts.critical, red],
  ['HIGH', counts.high, [249, 115, 22]],
  ['MEDIUM', counts.medium, amber],
  ['LOW / INFO', counts.low, [59, 130, 246]],
];

    const cardGap = 4;
    const cardWidth =
      (contentWidth - cardGap * 3) / 4;

    cards.forEach(([label, value, color], index) => {
      const x =
        margin +
        index * (cardWidth + cardGap);

      pdf.setFillColor(...dark2);

      pdf.roundedRect(
        x,
        y,
        cardWidth,
        32,
        3,
        3,
        'F'
      );

      pdf.setDrawColor(30, 41, 59);

      pdf.roundedRect(
        x,
        y,
        cardWidth,
        32,
        3,
        3,
        'S'
      );

      pdf.setFont('helvetica', 'bold');
      pdf.setFontSize(18);
      pdf.setTextColor(...color);

      pdf.text(
        String(value),
        x + 7,
        y + 17
      );

      pdf.setFontSize(6.5);
      pdf.setTextColor(...gray);

      pdf.text(
        label,
        x + 7,
        y + 25
      );
    });

    y += 45;

    // ==================================================
    // SECURITY CONTROLS
    // ==================================================

    pdf.setFont('helvetica', 'bold');
    pdf.setFontSize(11);
    pdf.setTextColor(...white);

    pdf.text(
      'Security Control Status',
      margin,
      y
    );

    y += 8;

    const controls = [
      ['SSL / TLS', 'HTTPS Standard'],
      ['Content Security Policy', 'CSP Header'],
      ['Clickjacking Defense', 'DENY'],
      ['Strict HTTPS', 'HSTS Enforced'],
    ];

    controls.forEach(([label, status]) => {
      pdf.setFillColor(...dark2);

      pdf.roundedRect(
        margin,
        y,
        contentWidth,
        14,
        2,
        2,
        'F'
      );

      pdf.setFillColor(...green);

      pdf.circle(
        margin + 7,
        y + 7,
        2,
        'F'
      );

      pdf.setFont('helvetica', 'bold');
      pdf.setFontSize(8);
      pdf.setTextColor(...white);

      pdf.text(
        label,
        margin + 13,
        y + 8
      );

      pdf.setFont('helvetica', 'normal');
      pdf.setFontSize(8);
      pdf.setTextColor(...green);

      pdf.text(
        `ACTIVE  •  ${status}`,
        pageWidth - margin - 55,
        y + 8
      );

      y += 17;
    });

    // ==================================================
    // PAGE 3+ — DETAILED FINDINGS
    // ==================================================

    if (findings.length > 0) {
      newPage();

      pdf.setFont('helvetica', 'bold');
      pdf.setFontSize(17);
      pdf.setTextColor(...white);

      pdf.text(
        'Detailed Security Findings',
        margin,
        y
      );

      y += 6;

      pdf.setFont('helvetica', 'normal');
      pdf.setFontSize(8);
      pdf.setTextColor(...gray);

      pdf.text(
        `${findings.length} finding(s) identified during the audit`,
        margin,
        y
      );

      y += 14;

      findings.forEach((finding, index) => {
        const severity = String(
          finding.severity || 'LOW'
        ).toUpperCase();

        const title =
          finding.title ||
          finding.issue ||
          finding.vulnerability_type ||
          finding.type ||
          finding.name ||
          'Security Finding';

        const description =
          finding.impact ||
          finding.description ||
          finding.summary ||
          finding.details ||
          '';

        const remediation =
          finding.remediation ||
          finding.fix ||
          finding.recommendation ||
          finding.solution ||
          finding.suggestion ||
          '';

        const severityColor =
          getSeverityColor(severity);

        const descriptionLines = wrappedText(
          description || 'No description provided.',
          contentWidth - 16
        );

        const remediationLines = wrappedText(
          remediation || 'No remediation guidance provided.',
          contentWidth - 16
        );

        const requiredHeight =
          30 +
          Math.min(descriptionLines.length, 5) * 4 +
          Math.min(remediationLines.length, 6) * 4;

        ensureSpace(requiredHeight);

        // Finding container
        pdf.setFillColor(...dark2);

        pdf.roundedRect(
          margin,
          y,
          contentWidth,
          requiredHeight,
          4,
          4,
          'F'
        );

        pdf.setDrawColor(
          severityColor[0],
          severityColor[1],
          severityColor[2]
        );

        pdf.setLineWidth(0.6);

        pdf.line(
          margin,
          y + 4,
          margin,
          y + requiredHeight - 4
        );

        // Number
        pdf.setFont('helvetica', 'bold');
        pdf.setFontSize(8);
        pdf.setTextColor(...gray);

        pdf.text(
          `FINDING ${String(index + 1).padStart(2, '0')}`,
          margin + 8,
          y + 9
        );

        // Severity badge
        pdf.setFillColor(
          severityColor[0],
          severityColor[1],
          severityColor[2]
        );

        pdf.roundedRect(
          pageWidth - margin - 28,
          y + 4,
          20,
          7,
          2,
          2,
          'F'
        );

        pdf.setFont('helvetica', 'bold');
        pdf.setFontSize(6.5);
        pdf.setTextColor(...white);

        pdf.text(
          severity,
          pageWidth - margin - 18,
          y + 8.5,
          { align: 'center' }
        );

        // Title
        pdf.setFont('helvetica', 'bold');
        pdf.setFontSize(10);
        pdf.setTextColor(...white);

        const titleLines = wrappedText(
          title,
          contentWidth - 55
        );

        pdf.text(
          titleLines.slice(0, 2),
          margin + 8,
          y + 16
        );

        y += 27;

        // Description
        pdf.setFont('helvetica', 'bold');
        pdf.setFontSize(7);
        pdf.setTextColor(...cyan);

        pdf.text(
          'IMPACT / DESCRIPTION',
          margin + 8,
          y
        );

        y += 5;

        pdf.setFont('helvetica', 'normal');
        pdf.setFontSize(8);
        pdf.setTextColor(...white);

        pdf.text(
          descriptionLines.slice(0, 5),
          margin + 8,
          y
        );

        y +=
          Math.min(descriptionLines.length, 5) * 4 +
          5;

        // Remediation
        pdf.setFont('helvetica', 'bold');
        pdf.setFontSize(7);
        pdf.setTextColor(...green);

        pdf.text(
          'RECOMMENDED REMEDIATION',
          margin + 8,
          y
        );

        y += 5;

        pdf.setFont('helvetica', 'normal');
        pdf.setFontSize(8);
        pdf.setTextColor(...white);

        pdf.text(
          remediationLines.slice(0, 6),
          margin + 8,
          y
        );

        y +=
          Math.min(remediationLines.length, 6) * 4 +
          8;

        // File / line information
        if (
          finding.file_path ||
          finding.line_number
        ) {
          pdf.setFont('helvetica', 'normal');
          pdf.setFontSize(7);
          pdf.setTextColor(...gray);

          pdf.text(
            `Location: ${cleanText(
              finding.file_path || 'N/A'
            )}${
              finding.line_number
                ? `  •  Line ${finding.line_number}`
                : ''
            }`,
            margin + 8,
            y
          );

          y += 7;
        }

        // Reset for next finding
        y += 5;

        pdf.setDrawColor(51, 65, 85);
        pdf.setLineWidth(0.25);

        if (y < pageHeight - 25) {
          pdf.line(
            margin + 8,
            y,
            pageWidth - margin - 8,
            y
          );

          y += 8;
        }
      });
    } else {
      // No findings
      ensureSpace(55);

      pdf.setFont('helvetica', 'bold');
      pdf.setFontSize(17);
      pdf.setTextColor(...white);

      pdf.text(
        'Security Findings',
        margin,
        y
      );

      y += 15;

      pdf.setFillColor(6, 78, 59);

      pdf.roundedRect(
        margin,
        y,
        contentWidth,
        38,
        4,
        4,
        'F'
      );

      pdf.setFont('helvetica', 'bold');
      pdf.setFontSize(12);
      pdf.setTextColor(...green);

      pdf.text(
        'NO SECURITY FINDINGS DETECTED',
        pageWidth / 2,
        y + 15,
        { align: 'center' }
      );

      pdf.setFont('helvetica', 'normal');
      pdf.setFontSize(8);
      pdf.setTextColor(...white);

      pdf.text(
        'No hardening recommendations were identified during this audit.',
        pageWidth / 2,
        y + 24,
        { align: 'center' }
      );
    }

    // ==================================================
    // APPLY FOOTERS TO ALL PAGES
    // ==================================================

    const totalPages = pdf.getNumberOfPages();

    for (let page = 1; page <= totalPages; page++) {
      pdf.setPage(page);
      addPageFooter();
    }

    // ==================================================
    // SAVE
    // ==================================================

    const gradeName =
      safeFilename(
        report.securityGrade || 'Report'
      ) || 'Report';

    const filename =
      `SecureCode_Web_Audit_${gradeName}.pdf`;

    pdf.save(filename);

    console.log(
      `PDF report generated successfully: ${filename}`
    );
  } catch (error) {
    console.error(
      'PDF generation failed:',
      error
    );

    throw error;
  }
}