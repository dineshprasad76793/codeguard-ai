// Professional PDF report generator for CodeGuard AI.
// Builds a multi-page A4 PDF entirely in the browser (jsPDF) and
// triggers a direct file download — no print dialog, no extra steps.
import { jsPDF } from 'jspdf';
import { SEVERITY_ORDER } from './constants.js';

const PAGE_W = 595.28;
const PAGE_H = 841.89;
const MARGIN = 48;
const CONTENT_W = PAGE_W - MARGIN * 2;
const FOOT_ROOM = 40; // reserved at the bottom of every page

const INK = [15, 23, 42]; // near-black text
const MUTED = [100, 116, 139];
const ACCENT = [59, 130, 246];
const NAVY = [15, 23, 42];
const CARD_BG = [248, 250, 252];
const BORDER = [226, 232, 240];

// Color-coded severity (Critical=red, High=orange, Medium=yellow, Low=blue)
const SEV_STYLE = {
  Critical: { bg: [220, 38, 38], fg: [255, 255, 255] },
  High: { bg: [234, 88, 12], fg: [255, 255, 255] },
  Medium: { bg: [250, 204, 21], fg: [71, 32, 12] },
  Low: { bg: [37, 99, 235], fg: [255, 255, 255] },
  Info: { bg: [100, 116, 139], fg: [255, 255, 255] },
  Custom: { bg: [130, 120, 220], fg: [255, 255, 255] },
};

// jsPDF's built-in fonts only cover Windows-1252. Map the characters the
// AI report commonly uses, then drop anything else non-Latin so the PDF
// never renders broken glyphs.
const UNICODE_MAP = {
  '\u2014': '-', '\u2013': '-', '\u2018': "'", '\u2019': "'",
  '\u201c': '"', '\u201d': '"', '\u2022': '-', '\u2026': '...',
  '\u2192': '->', '\u21d2': '=>', '\u2713': '[ok]', '\u2717': '[x]',
  '\u00d7': 'x', '\u2264': '<=', '\u2265': '>=', '\u2260': '!=',
  '\u26a0': '[!]', '\u00a0': ' ', '\t': '  ',
};

function sanitize(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/[\u2014\u2013\u2018\u2019\u201c\u201d\u2022\u2026\u2192\u21d2\u2713\u2717\u00d7\u2264\u2265\u2260\u26a0\u00a0\t]/g, (c) => UNICODE_MAP[c])
    .replace(/[^\x20-\x7E\xA0-\xFF\n]/g, '');
}

function stamp() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
}

class Pdf {
  constructor() {
    this.doc = new jsPDF({ orientation: 'portrait', unit: 'pt', format: 'a4' });
    this.y = 0;
  }

  setFont(name, style, size, color) {
    this.doc.setFont(name, style);
    this.doc.setFontSize(size);
    this.doc.setTextColor(color[0], color[1], color[2]);
  }

  // Move to a new page if less than `need` points remain on this one.
  ensure(need) {
    if (this.y + need > PAGE_H - MARGIN - FOOT_ROOM) {
      this.doc.addPage();
      this.continuationHeader();
      return true;
    }
    return false;
  }

  continuationHeader() {
    this.setFont('helvetica', 'normal', 8, MUTED);
    this.doc.text('CodeGuard AI - Analysis Report (continued)', MARGIN, MARGIN);
    this.doc.setDrawColor(BORDER[0], BORDER[1], BORDER[2]);
    this.doc.line(MARGIN, MARGIN + 6, PAGE_W - MARGIN, MARGIN + 6);
    this.y = MARGIN + 24;
  }

  // Small filled label with centered text (severity chips, tags).
  chip(x, y, text, bg, fg, fontSize = 8) {
    this.setFont('helvetica', 'bold', fontSize, fg);
    const w = this.doc.getTextWidth(text) + 14;
    const h = fontSize + 8;
    this.doc.setFillColor(bg[0], bg[1], bg[2]);
    this.doc.roundedRect(x, y, w, h, 3, 3, 'F');
    this.doc.text(text, x + 7, y + h / 2 + fontSize * 0.35);
    return w;
  }

  sectionHeading(num, title) {
    this.ensure(60);
    const y = this.y;
    this.doc.setFillColor(ACCENT[0], ACCENT[1], ACCENT[2]);
    this.doc.rect(MARGIN, y + 2, 3, 14, 'F');
    this.setFont('helvetica', 'bold', 13, INK);
    this.doc.text(`${num}. ${title}`, MARGIN + 10, y + 14);
    this.y = y + 26;
  }

  // Wrapped paragraph. Returns the height used.
  paragraph(text, { size = 9, color = INK, style = 'normal', indent = 0, gap = 4, name = 'helvetica' } = {}) {
    const clean = sanitize(text);
    if (!clean.trim()) return 0;
    this.setFont(name, style, size, color);
    const lh = size * 1.4;
    const lines = this.doc.splitTextToSize(clean, CONTENT_W - indent);
    let drawn = 0;
    while (drawn < lines.length) {
      const room = PAGE_H - MARGIN - FOOT_ROOM - this.y;
      const fit = Math.floor(room / lh);
      if (fit <= 0) {
        this.ensure(lh);
        continue;
      }
      const take = lines.slice(drawn, drawn + fit);
      this.doc.text(take, MARGIN + indent, this.y + size);
      this.y += take.length * lh;
      drawn += take.length;
      if (drawn < lines.length) this.ensure(lh);
    }
    this.y += gap;
    return this.y;
  }

  codeBlock(label, code, borderColor) {
    const clean = sanitize(code).trim();
    if (!clean) return;
    const truncated = clean.length > 1400 ? clean.slice(0, 1400) + '\n... (truncated)' : clean;
    this.setFont('courier', 'normal', 8, INK);
    let lines = this.doc.splitTextToSize(truncated, CONTENT_W - 26);
    if (lines.length > 36) {
      lines = lines.slice(0, 36);
      lines.push('... (truncated)');
    }
    const lh = 10.5;
    const boxH = lines.length * lh + 20;
    // Keep the whole box on one page (skip if taller than a fresh page).
    if (boxH < PAGE_H - MARGIN * 2 - FOOT_ROOM) this.ensure(boxH + 14);
    const y = this.y;
    this.doc.setFillColor(CARD_BG[0], CARD_BG[1], CARD_BG[2]);
    this.doc.setDrawColor(BORDER[0], BORDER[1], BORDER[2]);
    this.doc.rect(MARGIN, y, CONTENT_W, boxH, 'FD');
    this.doc.setFillColor(borderColor[0], borderColor[1], borderColor[2]);
    this.doc.rect(MARGIN, y, 3, boxH, 'F');
    this.setFont('helvetica', 'bold', 7, borderColor);
    this.doc.text(label.toUpperCase(), MARGIN + 10, y + 11);
    this.setFont('courier', 'normal', 8, INK);
    this.doc.text(lines, MARGIN + 12, y + 24);
    this.y = y + boxH + 10;
  }
}

function scoreColor(score) {
  if (score === null || score === undefined) return MUTED;
  if (score >= 8) return [22, 163, 74];
  if (score >= 5) return [217, 119, 6];
  return [220, 38, 38];
}

function deriveCounts(report, findings) {
  if (findings.length) {
    const c = {};
    findings.forEach((f) => {
      c[f.severity] = (c[f.severity] || 0) + 1;
    });
    return c;
  }
  return report.counts || null;
}

function drawCoverBanner(pdf) {
  const doc = pdf.doc;
  doc.setFillColor(NAVY[0], NAVY[1], NAVY[2]);
  doc.rect(0, 0, PAGE_W, 92, 'F');
  doc.setFillColor(ACCENT[0], ACCENT[1], ACCENT[2]);
  doc.rect(0, 92, PAGE_W, 3, 'F');
  pdf.setFont('helvetica', 'bold', 24, [255, 255, 255]);
  doc.text('CodeGuard AI', MARGIN, 46);
  pdf.setFont('helvetica', 'normal', 10, [148, 163, 184]);
  doc.text('by Dinesh | dinesh.ai', MARGIN, 64);
  pdf.setFont('helvetica', 'bold', 10, [255, 255, 255]);
  const tag = 'ANALYSIS REPORT';
  doc.text(tag, PAGE_W - MARGIN - doc.getTextWidth(tag), 46);
  pdf.setFont('helvetica', 'normal', 8, [148, 163, 184]);
  const site = 'AI-powered code & security analysis';
  doc.text(site, PAGE_W - MARGIN - doc.getTextWidth(site), 64);
  pdf.y = 116;
}

function drawScanDetails(pdf, meta, findings) {
  const doc = pdf.doc;
  const rows = [
    ['Target', meta.target || 'N/A'],
    ['Mode', meta.mode || 'code'],
    ['Findings', String(findings.length)],
    ['Generated', new Date().toLocaleString()],
  ];
  const y0 = pdf.y;
  const rowH = 16;
  const labelW = 90;
  pdf.setFont('helvetica', 'normal', 9, MUTED);
  doc.text('SCAN DETAILS', MARGIN, y0);
  pdf.y = y0 + 12;
  rows.forEach(([k, v]) => {
    pdf.setFont('helvetica', 'bold', 9, MUTED);
    doc.text(k, MARGIN, pdf.y + 9);
    pdf.setFont('helvetica', 'normal', 9, INK);
    const lines = doc.splitTextToSize(sanitize(v), CONTENT_W - labelW);
    doc.text(lines.slice(0, 2), MARGIN + labelW, pdf.y + 9);
    pdf.y += Math.max(rowH, lines.slice(0, 2).length * 12);
  });
  doc.setDrawColor(BORDER[0], BORDER[1], BORDER[2]);
  doc.line(MARGIN, pdf.y + 6, PAGE_W - MARGIN, pdf.y + 6);
  pdf.y += 20;
}

function drawSummary(pdf, report) {
  const doc = pdf.doc;
  const boxW = (CONTENT_W - 12) / 2;
  const boxH = 62;
  const y = pdf.y;
  [MARGIN, MARGIN + boxW + 12].forEach((x) => {
    doc.setFillColor(CARD_BG[0], CARD_BG[1], CARD_BG[2]);
    doc.setDrawColor(BORDER[0], BORDER[1], BORDER[2]);
    doc.roundedRect(x, y, boxW, boxH, 6, 6, 'FD');
  });
  const q = report.quality;
  const s = report.security;
  pdf.setFont('helvetica', 'normal', 8, MUTED);
  doc.text('CODE QUALITY', MARGIN + 14, y + 18);
  doc.text('SECURITY', MARGIN + boxW + 26, y + 18);
  pdf.setFont('helvetica', 'bold', 22, scoreColor(q));
  doc.text(q === null || q === undefined ? 'N/A' : `${q}/10`, MARGIN + 14, y + 44);
  pdf.setFont('helvetica', 'bold', 22, scoreColor(s));
  doc.text(s === null || s === undefined ? 'N/A' : `${s}/10`, MARGIN + boxW + 26, y + 44);
  pdf.y = y + boxH + 16;
}

function drawSeverityBreakdown(pdf, counts) {
  const entries = Object.entries(counts || {}).filter(([, n]) => n > 0);
  if (!entries.length) return;
  const total = entries.reduce((a, [, n]) => a + n, 0);
  const max = Math.max(...entries.map(([, n]) => n));
  const rowH = 26;
  entries.forEach(([sev, n]) => {
    pdf.ensure(rowH + 4);
    const y = pdf.y;
    const style = SEV_STYLE[sev] || SEV_STYLE.Info;
    pdf.chip(MARGIN, y, sev, style.bg, style.fg, 8);
    // Count + share
    pdf.setFont('helvetica', 'bold', 10, INK);
    pdf.doc.text(`${n}`, MARGIN + 120, y + 12);
    pdf.setFont('helvetica', 'normal', 8, MUTED);
    const pct = Math.round((n / total) * 100);
    pdf.doc.text(`${pct}% of findings`, MARGIN + 136, y + 12);
    // Proportional bar
    const barW = 150;
    const w = Math.round((n / max) * barW);
    pdf.doc.setFillColor(BORDER[0], BORDER[1], BORDER[2]);
    pdf.doc.roundedRect(PAGE_W - MARGIN - barW, y + 6, barW, 7, 3, 3, 'F');
    pdf.doc.setFillColor(style.bg[0], style.bg[1], style.bg[2]);
    pdf.doc.roundedRect(PAGE_W - MARGIN - barW, y + 6, Math.max(w, 7), 7, 3, 3, 'F');
    pdf.y = y + rowH;
  });
  pdf.y += 6;
}

function drawFinding(pdf, f, index) {
  const doc = pdf.doc;
  // Keep the header + a bit of body together; skip to a new page if tight.
  pdf.ensure(110);
  const y = pdf.y;
  const style = SEV_STYLE[f.severity] || SEV_STYLE.Info;

  // Separator between findings
  doc.setDrawColor(BORDER[0], BORDER[1], BORDER[2]);
  doc.line(MARGIN, y, PAGE_W - MARGIN, y);

  const headY = y + 18;
  let x = MARGIN;
  x += pdf.chip(x, headY - 11, f.severity, style.bg, style.fg, 8) + 8;
  if (f.cvss !== null && f.cvss !== undefined) {
    x += pdf.chip(x, headY - 11, `CVSS ${f.cvss.toFixed(1)}`, style.bg, style.fg, 8) + 8;
  }
  pdf.setFont('helvetica', 'bold', 11, INK);
  const title = sanitize(f.title || `Finding ${index + 1}`);
  const titleLines = doc.splitTextToSize(title, CONTENT_W - (x - MARGIN) - 90);
  doc.text(titleLines.slice(0, 2), x, headY);
  pdf.y = headY + Math.max(6, titleLines.slice(0, 2).length * 14) - 4;

  // Meta line: finding number, line, location, OWASP
  const metaBits = [`#${index + 1}`];
  if (f.line) metaBits.push(`Line: ${f.line}`);
  else if (f.lineLabel) metaBits.push(`Line: ${f.lineLabel}`);
  if (f.location) metaBits.push(`Location: ${f.location}`);
  if (f.owasp) metaBits.push(`OWASP: ${f.owasp}`);
  if (f.vector) metaBits.push(f.vector);
  pdf.setFont('helvetica', 'normal', 8, MUTED);
  doc.text(sanitize(metaBits.join('   |   ')), MARGIN, pdf.y + 10);
  pdf.y += 20;

  if (f.explanation) pdf.paragraph(f.explanation, { size: 9 });
  if (f.why) {
    pdf.setFont('helvetica', 'bold', 9, INK);
    pdf.ensure(30);
    pdf.doc.text('Why it matters', MARGIN, pdf.y + 9);
    pdf.y += 16;
    pdf.paragraph(f.why, { size: 9 });
  }
  if (f.recommendation) {
    pdf.ensure(30);
    pdf.setFont('helvetica', 'bold', 9, [22, 163, 74]);
    pdf.doc.text('Fix suggestion', MARGIN, pdf.y + 9);
    pdf.y += 16;
    pdf.paragraph(f.recommendation, { size: 9 });
  }
  if (f.vulnCode) pdf.codeBlock('Vulnerable code', f.vulnCode, [220, 38, 38]);
  if (f.fixedCode) pdf.codeBlock('Fixed code', f.fixedCode, [22, 163, 74]);
  pdf.y += 8;
}

function drawRawFallback(pdf, report) {
  pdf.paragraph(
    'The report below is shown as produced by the AI (no individual findings were detected in the response format).',
    { size: 9, color: MUTED }
  );
  pdf.paragraph(report.raw, { size: 9, name: 'courier' });
}

function drawRecommendations(pdf, findings) {
  const fixes = findings.filter((f) => f.recommendation);
  if (!fixes.length) return;
  fixes.forEach((f, i) => {
    pdf.ensure(40);
    const y = pdf.y;
    pdf.setFont('helvetica', 'bold', 9, ACCENT);
    pdf.doc.text(`${i + 1}.`, MARGIN, y + 9);
    pdf.setFont('helvetica', 'bold', 9, INK);
    const title = sanitize(f.title);
    const lines = pdf.doc.splitTextToSize(title, CONTENT_W - 16);
    pdf.doc.text(lines.slice(0, 1), MARGIN + 16, y + 9);
    pdf.y = y + 14;
    pdf.paragraph(f.recommendation, { size: 9, indent: 16, gap: 8 });
  });
}

function stampFooters(pdf, meta) {
  const doc = pdf.doc;
  const pages = doc.getNumberOfPages();
  for (let p = 1; p <= pages; p++) {
    doc.setPage(p);
    doc.setDrawColor(BORDER[0], BORDER[1], BORDER[2]);
    doc.line(MARGIN, PAGE_H - 34, PAGE_W - MARGIN, PAGE_H - 34);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(MUTED[0], MUTED[1], MUTED[2]);
    doc.text(
      `CodeGuard AI - ${sanitize(meta.target || 'analysis').slice(0, 70)}`,
      MARGIN,
      PAGE_H - 22
    );
    const right = `Page ${p} of ${pages}  |  (c) 2026 Dinesh | dinesh.ai`;
    doc.text(right, PAGE_W - MARGIN - doc.getTextWidth(right), PAGE_H - 22);
  }
}

/**
 * Build the professional PDF report and return the jsPDF document.
 * @param {object} report  parsed report from lib/parse (quality, security, counts, issues, raw)
 * @param {object} meta    { mode, target }
 * @param {Array}  findings findings to include (already FP-filtered + sorted)
 */
export function buildPdfReport(report, meta, findings = []) {
  const pdf = new Pdf();
  pdf.doc.setProperties({
    title: `CodeGuard AI Report - ${meta.target || 'analysis'}`,
    subject: 'AI-assisted code and security analysis',
    author: 'Dinesh (dinesh.ai)',
    creator: 'CodeGuard AI',
  });

  drawCoverBanner(pdf);
  drawScanDetails(pdf, meta, findings);

  const counts = deriveCounts(report, findings);

  pdf.sectionHeading(1, 'Summary');
  drawSummary(pdf, report);
  if (report.raw && report.counts === null && !findings.length) {
    // no counts anywhere — skip severity section noise
  } else {
    pdf.paragraph(
      findings.length
        ? `${findings.length} finding(s) were identified in this scan. Higher severity items should be fixed first.`
        : 'No individual findings were identified in this scan.',
      { size: 9, color: MUTED }
    );
  }

  pdf.sectionHeading(2, 'Severity Breakdown');
  drawSeverityBreakdown(pdf, counts);

  pdf.sectionHeading(3, 'Findings');
  if (findings.length) {
    findings.forEach((f, i) => drawFinding(pdf, f, i));
  } else {
    drawRawFallback(pdf, report);
  }

  if (findings.length) {
    pdf.sectionHeading(4, 'Recommendations / Fixes');
    drawRecommendations(pdf, findings);
  }

  // Closing disclaimer
  pdf.ensure(40);
  pdf.setFont('helvetica', 'normal', 8, MUTED);
  const disc = 'AI-assisted analysis - verify all findings manually. Authorized testing only. Copyright (c) 2026 Dinesh. All rights reserved. | dinesh.ai';
  const discLines = pdf.doc.splitTextToSize(disc, CONTENT_W);
  pdf.doc.text(discLines, MARGIN, pdf.y + 10);

  stampFooters(pdf, meta);
  return pdf.doc;
}

/**
 * Build the report and trigger an immediate browser download.
 */
export function downloadPdfReport(report, meta, findings = []) {
  buildPdfReport(report, meta, findings).save(`codeguard-report-${stamp()}.pdf`);
}

export function sortFindings(findings) {
  return [...findings].sort(
    (a, b) =>
      (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) ||
      (b.cvss ?? -1) - (a.cvss ?? -1)
  );
}
