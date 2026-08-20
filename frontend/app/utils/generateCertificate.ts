import jsPDF from 'jspdf';

export interface CertificateData {
  targetUrl: string;
  securityGrade: string;
  securityScore: number;
  issueDate?: string;
  certificateId?: string;
}

const sanitizeText = (text: any): string => {
  if (text === undefined || text === null) return '';
  return String(text)
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/[\x00-\x1F\x7F-\x9F]/g, '')
    .trim();
};

export const generateCertificate = (data: CertificateData) => {
  try {
    const doc = new jsPDF({
      orientation: 'l',
      unit: 'mm',
      format: 'a4',
    });

    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();

    const targetUrl = sanitizeText(data?.targetUrl || 'https://target-endpoint.com');
    const grade = sanitizeText(data?.securityGrade || 'A+');
    const score = data?.securityScore ?? 100;

    // ---------------------------------------------------------
    // 1. CLASSIC CREAM/GOLD BACKGROUND & BORDERS
    // ---------------------------------------------------------
    doc.setFillColor(253, 251, 247); // Warm Cream Parchment Background
    doc.rect(0, 0, pageWidth, pageHeight, 'F');

    // Royal Gold Frame
    doc.setDrawColor(212, 175, 55); // Metallic Gold
    doc.setLineWidth(1.8);
    doc.rect(10, 10, pageWidth - 20, pageHeight - 20, 'S');

    doc.setDrawColor(184, 134, 11); // Dark Gold Inner
    doc.setLineWidth(0.5);
    doc.rect(13, 13, pageWidth - 26, pageHeight - 26, 'S');

    // Corner Ornaments
    const cLen = 8;
    doc.setDrawColor(184, 134, 11);
    doc.setLineWidth(1.2);
    // Top Left
    doc.line(10, 10 + cLen, 10 + cLen, 10);
    // Top Right
    doc.line(pageWidth - 10 - cLen, 10, pageWidth - 10, 10 + cLen);
    // Bottom Left
    doc.line(10, pageHeight - 10 - cLen, 10 + cLen, pageHeight - 10);
    // Bottom Right
    doc.line(pageWidth - 10 - cLen, pageHeight - 10, pageWidth - 10, pageHeight - 10 - cLen);

    // Dynamic Crimson/Red Decorative Wave Accents (Top & Bottom Corners)
    doc.setFillColor(153, 27, 27); // Royal Crimson Red
    doc.path([
      { op: 'm', c: [13, 13] },
      { op: 'l', c: [55, 13] },
      { op: 'c', c: [35, 25, 20, 35, 13, 55] },
      { op: 'h' }
    ], 'F');

    doc.setFillColor(212, 175, 55); // Gold Accent Overlay
    doc.path([
      { op: 'm', c: [13, 13] },
      { op: 'l', c: [40, 13] },
      { op: 'c', c: [25, 20, 18, 25, 13, 40] },
      { op: 'h' }
    ], 'F');

    // ---------------------------------------------------------
    // 2. GOLD HUD TECH LOGO (Centered Top)
    // ---------------------------------------------------------
    const logoX = pageWidth / 2;
    const logoY = 28;

    doc.setDrawColor(184, 134, 11);
    doc.setLineWidth(0.8);
    doc.circle(logoX, logoY, 11, 'S');

    doc.setDrawColor(153, 27, 27);
    doc.setLineWidth(0.5);
    doc.circle(logoX, logoY, 8.5, 'S');

    doc.setDrawColor(30, 41, 59);
    doc.setLineWidth(0.5);
    doc.circle(logoX, logoY, 5, 'S');
    doc.line(logoX - 11, logoY, logoX + 11, logoY);

    doc.setFillColor(184, 134, 11);
    doc.rect(logoX - 1.8, logoY - 0.5, 3.6, 3, 'F');

    doc.setTextColor(120, 53, 15);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.text('I S V S   A U D I T   F R A M E W O R K', logoX, logoY + 16, { align: 'center' });

    // ---------------------------------------------------------
    // 3. ELEGANT HEADINGS & TITLES
    // ---------------------------------------------------------
    doc.setTextColor(184, 134, 11);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9);
    doc.text('IDENTIFYING SECURITY VULNERABILITIES IN SOURCE CODE', pageWidth / 2, 53, { align: 'center' });

    doc.setTextColor(30, 41, 59); // Deep Slate
    doc.setFont('times', 'bold');
    doc.setFontSize(22);
    doc.text('CERTIFICATE OF SECURITY HARDENING', pageWidth / 2, 63, { align: 'center' });

    doc.setDrawColor(212, 175, 55);
    doc.setLineWidth(0.8);
    doc.line(pageWidth / 2 - 50, 67, pageWidth / 2 + 50, 67);

    // ---------------------------------------------------------
    // 4. CERTIFICATE BODY & TARGET ENDPOINT
    // ---------------------------------------------------------
    doc.setTextColor(71, 85, 105);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.text('THIS IS TO OFFICIALLY CERTIFY THAT THE TARGET ENDPOINT SYSTEM', pageWidth / 2, 75, { align: 'center' });

    // Clean Golden URL Display
    doc.setTextColor(184, 134, 11);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(14);
    doc.text(targetUrl, pageWidth / 2, 84, { align: 'center' });

    doc.setTextColor(71, 85, 105);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    doc.text(
      'HAS BEEN FULLY AUDITED AND COMPLIES WITH ALL ISVS SAST SECURITY HARDENING STANDARDS.',
      pageWidth / 2,
      93,
      { align: 'center' }
    );

    // ---------------------------------------------------------
    // 5. GRADE & SCORE DISPLAY
    // ---------------------------------------------------------
    const gradeY = 112;

    doc.setTextColor(16, 185, 129); // Emerald Green Grade
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(24);
    doc.text(`GRADE  ${grade}`, pageWidth / 2, gradeY, { align: 'center' });

    doc.setFontSize(9.5);
    doc.setTextColor(120, 53, 15);
    doc.text(`VERIFIED OVERALL SCORE: ${score} / 100`, pageWidth / 2, gradeY + 8, { align: 'center' });

    // ---------------------------------------------------------
    // 6. THREE OFFICIAL SIGNATORIES (Mr. Zar Ni Tun, Mr. Hlaing Min Htet, Mr. Thant Zin)
    // ---------------------------------------------------------
    const sigY = 160;

    // Signatory 1 (Left): Mr. Hlaing Min Htet
    const sig1X = 55;
    doc.setDrawColor(184, 134, 11);
    doc.setLineWidth(0.5);
    doc.line(sig1X - 25, sigY, sig1X + 25, sigY);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9.5);
    doc.setTextColor(30, 41, 59);
    doc.text('Mr. Hlaing Min Htet', sig1X, sigY + 5, { align: 'center' });

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    doc.text('Co-Founder & Security Engineer', sig1X, sigY + 9, { align: 'center' });

    // Signatory 2 (Center): Mr. Zar Ni Tun
    const sig2X = pageWidth / 2;
    doc.line(sig2X - 28, sigY, sig2X + 28, sigY);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(30, 41, 59);
    doc.text('Mr. Zar Ni Tun', sig2X, sigY + 5, { align: 'center' });

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    doc.text('Founder & Lead Researcher', sig2X, sigY + 9, { align: 'center' });

    // Signatory 3 (Right): Mr. Thant Zin
    const sig3X = pageWidth - 55;
    doc.line(sig3X - 25, sigY, sig3X + 25, sigY);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9.5);
    doc.setTextColor(30, 41, 59);
    doc.text('Mr. Thant Zin', sig3X, sigY + 5, { align: 'center' });

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(100, 116, 139);
    doc.text('Co-Founder & Core Architect', sig3X, sigY + 9, { align: 'center' });

    // ---------------------------------------------------------
    // 7. FOOTER METADATA
    // ---------------------------------------------------------
    const rawId = data?.certificateId || `ISVS-${Math.random().toString(36).substring(2, 9).toUpperCase()}`;
    const certId = sanitizeText(rawId);
    const dateStr = sanitizeText(data?.issueDate || new Date().toLocaleDateString());

    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text(`Certificate ID: ${certId}`, 20, pageHeight - 15);
    doc.text(`Issued On: ${dateStr}`, pageWidth - 20, pageHeight - 15, { align: 'right' });

    doc.save(`ISVS_Gold_Certificate_${certId}.pdf`);
  } catch (error) {
    console.error('Certificate Generation Error:', error);
  }
};