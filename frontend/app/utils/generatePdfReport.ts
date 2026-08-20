import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

export interface ScanReportData {
  targetUrl: string;
  scanType: string;
  securityScore: number;
  securityGrade: string;
  summary: string;
  findings: Array<{
    title: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | string;
    description?: string;
    remediation?: string;
  }>;
  serverInfo?: string;
  scannedAt?: string;
}

// PDF Encoding Glitch ကာကွယ်ရန်နှင့် Code Symbols/Punctuation (:, =, ;, /, ', ") များကို မပျောက်စေရန် Safe Sanitizer
const sanitizePdfText = (text: any): string => {
  if (!text) return '';
  return String(text)
    // Curly / Smart quotes များကို Standard ASCII Quotes သို့ ပြောင်းခြင်း
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201C\u201D]/g, '"')
    // Unicode dashes များကို Hyphen ပြောင်းခြင်း
    .replace(/[\u2013\u2014]/g, '-')
    // Non-printable Control Characters / Bad Unicode Glitch Characters များကိုသာ သီးသန့် ဖယ်ရှားခြင်း
    .replace(/[^\x20-\x7E\n\r\t]/g, '')
    .trim();
};

export const generatePdfReport = (data: ScanReportData) => {
  const doc = new jsPDF({
    orientation: 'p',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const timestamp = sanitizePdfText(data.scannedAt || new Date().toLocaleString());

  // ---------------------------------------------------------
  // 1. HEADER SECTION
  // ---------------------------------------------------------
  doc.setFillColor(10, 15, 28);
  doc.rect(0, 0, pageWidth, 40, 'F');

  doc.setTextColor(6, 182, 212);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.text('SECURECODE SAST & AUDIT', 14, 18);

  doc.setTextColor(148, 163, 184);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.text('EXECUTIVE CYBERSECURITY ASSESSMENT REPORT', 14, 25);
  doc.text(`Generated: ${timestamp}`, 14, 31);

  // Status Badge
  doc.setFillColor(15, 23, 42);
  doc.roundedRect(pageWidth - 55, 12, 41, 18, 3, 3, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(8);
  doc.setFont('helvetica', 'bold');
  doc.text('CONFIDENTIAL', pageWidth - 47, 22);

  // Accent Line
  doc.setDrawColor(6, 182, 212);
  doc.setLineWidth(0.8);
  doc.line(0, 40, pageWidth, 40);

  // ---------------------------------------------------------
  // 2. OVERVIEW & SCORE CARD
  // ---------------------------------------------------------
  let currentY = 48;

  // Target Box
  doc.setFillColor(248, 250, 252);
  doc.roundedRect(14, currentY, pageWidth - 28, 28, 3, 3, 'F');
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(14, currentY, pageWidth - 28, 28, 3, 3, 'S');

  doc.setTextColor(15, 23, 42);
  doc.setFontSize(9.5);
  doc.setFont('helvetica', 'bold');
  doc.text('Target Endpoint:', 18, currentY + 9);
  doc.setFont('helvetica', 'normal');
  doc.text(sanitizePdfText(data.targetUrl), 52, currentY + 9);

  doc.setFont('helvetica', 'bold');
  doc.text('Assessment Scope:', 18, currentY + 17);
  doc.setFont('helvetica', 'normal');
  doc.text(sanitizePdfText(data.scanType), 56, currentY + 17);

  doc.setFont('helvetica', 'bold');
  doc.text('Server Tech:', 18, currentY + 24);
  doc.setFont('helvetica', 'normal');
  doc.text(sanitizePdfText(data.serverInfo || 'N/A'), 45, currentY + 24);

  // Score Box
  const scoreX = pageWidth - 60;
  let gradeColor = [16, 185, 129];
  if (data.securityGrade.startsWith('C')) gradeColor = [245, 158, 11];
  if (data.securityGrade === 'F') gradeColor = [244, 63, 94];

  doc.setFillColor(gradeColor[0], gradeColor[1], gradeColor[2]);
  doc.roundedRect(scoreX, currentY + 3, 42, 22, 2, 2, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.text(`Grade: ${sanitizePdfText(data.securityGrade)}`, scoreX + 6, currentY + 12);
  doc.setFontSize(8.5);
  doc.text(`Score: ${data.securityScore}/100`, scoreX + 8, currentY + 18);

  currentY += 35;

  // Executive Summary
  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.text('Executive Assessment Summary', 14, currentY);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(51, 65, 85);
  const cleanSummaryText = sanitizePdfText(data.summary);
  const splitSummary = doc.splitTextToSize(cleanSummaryText, pageWidth - 28);
  doc.text(splitSummary, 14, currentY + 5);

  currentY += 8 + splitSummary.length * 4.5;

  // ---------------------------------------------------------
  // 3. SEVERITY BREAKDOWN STATS
  // ---------------------------------------------------------
  const criticals = data.findings.filter(f => String(f.severity).toUpperCase() === 'CRITICAL').length;
  const highs = data.findings.filter(f => String(f.severity).toUpperCase() === 'HIGH').length;
  const mediums = data.findings.filter(f => String(f.severity).toUpperCase() === 'MEDIUM').length;
  const lows = data.findings.filter(f => String(f.severity).toUpperCase() === 'LOW' || String(f.severity).toUpperCase() === 'INFO').length;

  doc.setFillColor(241, 245, 249);
  doc.rect(14, currentY, pageWidth - 28, 11, 'F');

  doc.setFontSize(8.5);
  doc.setFont('helvetica', 'bold');

  doc.setTextColor(225, 29, 72);
  doc.text(`Critical: ${criticals}`, 20, currentY + 7);

  doc.setTextColor(234, 88, 12);
  doc.text(`High: ${highs}`, 65, currentY + 7);

  doc.setTextColor(217, 119, 6);
  doc.text(`Medium: ${mediums}`, 115, currentY + 7);

  doc.setTextColor(37, 99, 235);
  doc.text(`Low / Info: ${lows}`, 160, currentY + 7);

  currentY += 16;

  // ---------------------------------------------------------
  // 4. FINDINGS TABLE
  // ---------------------------------------------------------
  doc.setTextColor(15, 23, 42);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.text(`Audit Findings & Remediation Plan (${data.findings.length})`, 14, currentY);

  const tableBody = data.findings.map(f => [
    sanitizePdfText(f.severity).toUpperCase(),
    sanitizePdfText(f.title),
    sanitizePdfText(f.description || 'No detailed description provided.'),
    sanitizePdfText(f.remediation || 'N/A')
  ]);

  autoTable(doc, {
    startY: currentY + 4,
    head: [['Severity', 'Finding Title', 'Impact / Description', 'Remediation Fix']],
    body: tableBody,
    theme: 'grid',
    margin: { left: 14, right: 14 },
    headStyles: {
      fillColor: [10, 15, 28],
      textColor: [6, 182, 212],
      fontSize: 8,
      fontStyle: 'bold',
      halign: 'left'
    },
    styles: {
      font: 'helvetica',
      fontSize: 7.5,
      cellPadding: 2.5,
      overflow: 'linebreak'
    },
    columnStyles: {
      0: { cellWidth: 20, fontStyle: 'bold' },
      1: { cellWidth: 38 },
      2: { cellWidth: 62 },
      3: { cellWidth: 62 }
    },
    didParseCell: function (data) {
      if (data.section === 'body' && data.column.index === 0) {
        const val = String(data.cell.raw);
        if (val === 'CRITICAL' || val === 'HIGH') {
          data.cell.styles.textColor = [225, 29, 72];
        } else if (val === 'MEDIUM') {
          data.cell.styles.textColor = [217, 119, 6];
        } else {
          data.cell.styles.textColor = [37, 99, 235];
        }
      }
    }
  });

  // Footer
  const pageCount = (doc as any).internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(148, 163, 184);
    doc.text(`SecureCode SAST Engine Assessment Report - Page ${i} of ${pageCount}`, pageWidth / 2, 288, { align: 'center' });
  }

  doc.save(`Security_Audit_Report_${Date.now()}.pdf`);
};