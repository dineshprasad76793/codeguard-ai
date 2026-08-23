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
