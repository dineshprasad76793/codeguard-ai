// Parses the AI report text into a structured object.
// Supports BOTH the v2 accuracy-focused format (Category / Confidence /
// Data Flow / Manual Verification) and the legacy format (Issue / CVSS).
// Anything unparseable falls back to raw text.

function normalizeSeverity(s) {
  const v = (s || '').trim().toLowerCase();
  if (v.startsWith('crit')) return 'Critical';
  if (v.startsWith('high')) return 'High';
  if (v.startsWith('med')) return 'Medium';
  if (v.startsWith('low')) return 'Low';
  if (v.startsWith('info')) return 'Info';
  return 'Info';
}

const CATEGORY_ORDER = [
  'Confirmed Vulnerability',
  'Potential Vulnerability',
  'Security Hardening',
  'Code Quality',
  'Informational',
];

function normalizeCategory(s) {
  const v = (s || '').trim().toLowerCase();
  if (!v) return null;
  if (v.startsWith('confirmed')) return 'Confirmed Vulnerability';
  if (v.startsWith('potential')) return 'Potential Vulnerability';
  if (v.includes('harden')) return 'Security Hardening';
  if (v.includes('quality')) return 'Code Quality';
  if (v.startsWith('info')) return 'Informational';
  return 'Potential Vulnerability';
}

function normalizeConfidence(s) {
  const v = (s || '').trim().toLowerCase();
  if (v.startsWith('high')) return 'High';
  if (v.startsWith('med')) return 'Medium';
  if (v.startsWith('low')) return 'Low';
  return null;
}

function stripFences(text) {
  if (!text) return '';
  let t = text.trim();
  t = t.replace(/^```[a-zA-Z0-9+#-]*\s*\n?/, '');
  t = t.replace(/\n?```\s*$/, '');
  return t.trim();
}

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Field labels that can terminate a multi-line field value.
const FIELD_LABELS = [
  'Category', 'Severity', 'Confidence', 'File', 'Line', 'Evidence', 'Data Flow',
  'Why It Matters', 'Why it is a problem', 'Why It Was Detected',
  'Recommended Fix', 'Recommendation', 'Manual Verification Required',
  'Why this is not necessarily a vulnerability',
  'Vulnerable Code', 'Fixed Code', 'Explanation', 'Location', 'OWASP',
  'CVSS Estimate',
];
const ANY_LABEL_RE = new RegExp(
  '^\\s*(?:' + FIELD_LABELS.map(esc).join('|') + ')\\s*:',
  'im'
);

function grabField(block, name) {
  const start = block.match(new RegExp('^\\s*' + esc(name) + '\\s*:\\s*\\n?', 'im'));
  if (!start) return '';
  const rest = block.slice(start.index + start[0].length);
  const end = rest.match(ANY_LABEL_RE);
  const value = (end ? rest.slice(0, end.index) : rest).trim();
  return value;
}

export function parseReport(text) {
  const report = {
    quality: null,
    security: null,
    counts: null,
    categoryCounts: null,
    totalFindings: null,
    issues: [],
    raw: text,
  };

  // Scores: new format first, legacy fallback
  const s =
    text.match(/SECURITY SCORE:\s*(\d+(?:\.\d+)?)\s*\/\s*10/i) ||
    text.match(/Security:\s*(\d+(?:\.\d+)?)\s*\/\s*10/i);
  const q =
    text.match(/CODE QUALITY SCORE:\s*(\d+(?:\.\d+)?)\s*\/\s*10/i) ||
    text.match(/Code Quality:\s*(\d+(?:\.\d+)?)\s*\/\s*10/i);
  report.security = s ? Number(s[1]) : null;
  report.quality = q ? Number(q[1]) : null;

  // Category summary (new format)
  const cat = (label) => {
    const m = text.match(new RegExp(label + '\\s*:\\s*(\\d+)', 'i'));
    return m ? Number(m[1]) : null;
  };
  const confirmed = cat('Confirmed Vulnerabilities');
  if (confirmed !== null) {
    report.categoryCounts = {
      'Confirmed Vulnerability': confirmed,
      'Potential Vulnerability': cat('Potential Vulnerabilities') || 0,
      'Security Hardening': cat('Hardening Recommendations') || 0,
      'Code Quality': cat('Code Quality Issues') || 0,
      Informational: cat('Informational Findings') || 0,
    };
    report.totalFindings = cat('Total Findings');
  }

  // Severity summary (legacy fallback)
  const c = text.match(
    /Critical:\s*(\d+)\s*\|\s*High:\s*(\d+)\s*\|\s*Medium:\s*(\d+)\s*\|\s*Low:\s*(\d+)/i
  );
  if (c) {
    report.counts = {
      Critical: Number(c[1]),
      High: Number(c[2]),
      Medium: Number(c[3]),
      Low: Number(c[4]),
    };
  }

  // Findings: new format starts "N. Title:", legacy starts "N. Issue:"
  const blocks = text
    .split(/^\s*(?=\d+\.\s*(?:Title|Issue):)/m)
    .filter((b) => /^\s*\d+\.\s*(?:Title|Issue):/m.test(b));

  blocks.forEach((block, i) => {
    const titleM = block.match(/^\s*\d+\.\s*(?:Title|Issue):\s*(.+)/m);
    const severityRaw =
      grabField(block, 'Severity') || block.match(/Severity:\s*(.+)/)?.[1] || '';
    const cvss = block.match(/CVSS Estimate:\s*(\d+(?:\.\d+)?)/i);
    const vector = block.match(/(CVSS:3\.1\/[A-Za-z:\/]+)/);
    const line = grabField(block, 'Line') || block.match(/Line:\s*(\d+|N\/A)/i)?.[1];
    const owasp = block.match(/OWASP:\s*(A\d+:\d+[^:\n]*)/i);
    const locationM = grabField(block, 'Location') || block.match(/Location:\s*(.+)/)?.[1];

    report.issues.push({
      id: `ai-${i}`,
      title: titleM ? titleM[1].trim() : `Finding ${i + 1}`,
      category: normalizeCategory(grabField(block, 'Category')),
      severity: normalizeSeverity(severityRaw),
      confidence: normalizeConfidence(grabField(block, 'Confidence')),
      file: grabField(block, 'File') || null,
      line: line && /^\d+$/.test(line.trim()) ? Number(line.trim()) : null,
      lineLabel: line ? line.trim() : null,
      location: locationM ? locationM.trim() : null,
      owasp: owasp ? owasp[1].trim() : null,
      cvss: cvss ? Number(cvss[1]) : null,
      vector: vector ? vector[1] : null,
      evidence: grabField(block, 'Evidence') ||
        sectionLegacy(block, /Explanation:\s*\n?/, [/Why it is a problem:/, /Why It Matters:/]),
      dataFlow: grabField(block, 'Data Flow') || null,
      why:
        grabField(block, 'Why It Matters') ||
        grabField(block, 'Why it is a problem'),
      whyDetected: grabField(block, 'Why It Was Detected') || null,
      manualVerification: grabField(block, 'Manual Verification Required') || null,
      whyNotVuln: grabField(block, 'Why this is not necessarily a vulnerability') || null,
      recommendation:
        grabField(block, 'Recommended Fix') || grabField(block, 'Recommendation'),
      vulnCode: stripFences(grabField(block, 'Vulnerable Code')),
      fixedCode: stripFences(grabField(block, 'Fixed Code')),
      source: 'ai',
    });
  });

  return report;
}

function sectionLegacy(block, startRe, endRes) {
  const m = block.match(startRe);
  if (!m) return '';
  const rest = block.slice(m.index + m[0].length);
  for (const endRe of endRes) {
    const e = rest.match(endRe);
    if (e) return rest.slice(0, e.index).trim();
  }
  return rest.trim();
}

export function cvssClass(score) {
  if (score === null || score === undefined) return '';
  if (score >= 9) return 'cvss-critical';
  if (score >= 7) return 'cvss-high';
  if (score >= 4) return 'cvss-medium';
  if (score > 0) return 'cvss-low';
  return 'cvss-none';
}

export function scoreClass(score) {
  if (score === null || score === undefined) return '';
  if (score >= 8) return 'score-green';
  if (score >= 5) return 'score-yellow';
  return 'score-red';
}

export { CATEGORY_ORDER };
