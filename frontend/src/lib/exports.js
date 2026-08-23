import { parseReport } from './parse';

export function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function stamp() {
  return new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-');
}

export function downloadFile(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(link.href);
}

export function buildMarkdown(analysisText, meta) {
  const r = parseReport(analysisText);
  const lines = [];
  lines.push('# CodeGuard AI — Analysis Report');
  lines.push('');
  lines.push(`**Target:** ${meta.target || 'N/A'}  `);
  lines.push(`**Mode:** ${meta.mode || 'code'}  `);
  lines.push(`**Generated:** ${new Date().toLocaleString()}  `);
  lines.push('');
  if (r.quality !== null) lines.push(`- Code Quality: **${r.quality}/10**`);
  if (r.security !== null) lines.push(`- Security: **${r.security}/10**`);
  if (r.counts)
    lines.push(
      `- Issues — Critical: ${r.counts.Critical}, High: ${r.counts.High}, Medium: ${r.counts.Medium}, Low: ${r.counts.Low}`
    );
  lines.push('');
  if (r.issues.length === 0) {
    lines.push('```');
    lines.push(analysisText);
    lines.push('```');
  } else {
    r.issues.forEach((issue, i) => {
      lines.push(`## ${i + 1}. ${issue.title}`);
      lines.push('');
      lines.push(
        `**Severity:** ${issue.severity}  ` +
          (issue.cvss !== null ? `**CVSS:** ${issue.cvss}${issue.vector ? ` (${issue.vector})` : ''}  ` : '') +
          (issue.line ? `**Line:** ${issue.line}  ` : '') +
          (issue.owasp ? `**OWASP:** ${issue.owasp}` : '')
      );
      lines.push('');
      if (issue.explanation) lines.push(`**Explanation:** ${issue.explanation}`, '');
      if (issue.why) lines.push(`**Why it is a problem:** ${issue.why}`, '');
      if (issue.recommendation)
        lines.push(`**Recommendation:** ${issue.recommendation}`, '');
      if (issue.vulnCode) lines.push('**Vulnerable code:**', '```', issue.vulnCode, '```', '');
      if (issue.fixedCode) lines.push('**Fixed code:**', '```', issue.fixedCode, '```', '');
    });
  }
  lines.push('---');
  lines.push('Copyright (c) 2026 Dinesh. All rights reserved. | dinesh.ai');
  lines.push('AI-assisted analysis — verify all findings manually.');
  return lines.join('\n');
}

export function buildJSON(analysisText, meta) {
  return JSON.stringify(
    {
      tool: 'CodeGuard AI',
      author: 'Dinesh (dinesh.ai)',
      generated: new Date().toISOString(),
      mode: meta.mode,
      target: meta.target,
      report: parseReport(analysisText),
    },
    null,
    2
  );
}

export function buildHtmlReport(analysisText, meta) {
  const now = new Date().toLocaleString();
  return (
    '<!DOCTYPE html>\n<html>\n<head>\n<meta charset="UTF-8" />\n' +
    '<title>CodeGuard AI Report</title>\n<style>\n' +
    'body { font-family: Segoe UI, Arial, sans-serif; background: #f1f5f9; color: #0f172a; padding: 40px; }\n' +
    '.card { max-width: 900px; margin: 0 auto; background: #fff; border-radius: 12px; padding: 32px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }\n' +
    'h1 { color: #2563eb; margin-bottom: 4px; }\n' +
    '.meta { color: #64748b; font-size: 0.85rem; margin-bottom: 24px; }\n' +
    'pre { white-space: pre-wrap; background: #0f172a; color: #e2e8f0; padding: 20px; border-radius: 8px; font-size: 0.85rem; line-height: 1.6; }\n' +
    '.footer { margin-top: 24px; color: #64748b; font-size: 0.75rem; text-align: center; }\n' +
    '@media print { body { background: #fff; padding: 0; } .card { box-shadow: none; } pre { background: #f8fafc; color: #0f172a; } }\n' +
    '</style>\n</head>\n<body>\n<div class="card">\n' +
    '<h1>CodeGuard AI — Analysis Report</h1>\n' +
    `<div class="meta">Target: ${escapeHtml(meta.target || 'N/A')} — Generated: ${now}</div>\n` +
    `<pre>${escapeHtml(analysisText)}</pre>\n` +
    '<div class="footer">Copyright (c) 2026 Dinesh. All rights reserved. | dinesh.ai<br />AI-assisted analysis — verify all findings manually.</div>\n' +
    '</div>\n<script>window.onload = function(){ window.print(); }<\/script>\n</body>\n</html>'
  );
}

export function printReport(analysisText, meta) {
  const win = window.open('', '_blank');
  if (!win) return false;
  win.document.write(buildHtmlReport(analysisText, meta));
  win.document.close();
  return true;
}

export async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (e) {
    // Fallback for non-secure contexts
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try {
      ok = document.execCommand('copy');
    } catch (err) {
      ok = false;
    }
    document.body.removeChild(ta);
    return ok;
  }
}

export function badgeUrl(label, value, color) {
  return `https://img.shields.io/badge/${encodeURIComponent(
    label
  )}-${encodeURIComponent(value)}-${color}`;
}

export { stamp };
