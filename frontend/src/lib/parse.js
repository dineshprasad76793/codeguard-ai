// Parses the AI report text into a structured object.
// Tolerates format drift: anything unparseable falls back to raw text.

function normalizeSeverity(s) {
  const v = (s || '').trim().toLowerCase();
  if (v.startsWith('crit')) return 'Critical';
  if (v.startsWith('high')) return 'High';
  if (v.startsWith('med')) return 'Medium';
  if (v.startsWith('low')) return 'Low';
  if (v.startsWith('info')) return 'Info';
  return 'Info';
}

function stripFences(text) {
  if (!text) return '';
  let t = text.trim();
  t = t.replace(/^```[a-zA-Z0-9+#-]*\s*\n?/, '');
  t = t.replace(/\n?```\s*$/, '');
  return t.trim();
}

function section(block, startRe, endRe) {
  const m = block.match(startRe);
  if (!m) return '';
  const rest = block.slice(m.index + m[0].length);
  const e = rest.match(endRe);
  return (e ? rest.slice(0, e.index) : rest).trim();
}

export function parseReport(text) {
  const report = {
    quality: null,
    security: null,
    counts: null,
    issues: [],
    raw: text,
  };

  const q = text.match(/Code Quality:\s*(\d+(?:\.\d+)?)\s*\/\s*10/i);
  const s = text.match(/Security:\s*(\d+(?:\.\d+)?)\s*\/\s*10/i);
  report.quality = q ? Number(q[1]) : null;
  report.security = s ? Number(s[1]) : null;

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

  const blocks = text
    .split(/^\s*(?=\d+\.\s*Issue:)/m)
    .filter((b) => /^\s*\d+\.\s*Issue:/m.test(b));

  blocks.forEach((block, i) => {
    const title = block.match(/Issue:\s*(.+)/);
    const sev = block.match(/Severity:\s*(.+)/);
    const cvss = block.match(/CVSS Estimate:\s*(\d+(?:\.\d+)?)/i);
    const vector = block.match(/(CVSS:3\.1\/[A-Za-z:\/]+)/);
    const line = block.match(/Line:\s*(\d+|N\/A)/i);
    const owasp = block.match(/OWASP:\s*(A\d+:\d+[^:\n]*)/i);
    const location = block.match(/Location:\s*(.+)/);

    const explanation = section(
      block,
      /Explanation:\s*\n?/,
      /Why it is a problem:/
    );
    const why = section(
      block,
      /Why it is a problem:\s*\n?/,
      /Recommendation:|Vulnerable Code:|Fixed Code:/
    );
    const recommendation = section(
      block,
      /Recommendation:\s*\n?/,
      /Vulnerable Code:|Fixed Code:/
    );
    const vulnCode = stripFences(
      section(block, /Vulnerable Code:\s*\n?/, /Fixed Code:|DISCLAIMER:/)
    );
    const fixedCode = stripFences(
      section(block, /Fixed Code:\s*\n?/, /DISCLAIMER:|\d+\.\s*Issue:|$/)
    );

    report.issues.push({
      id: `ai-${i}`,
      title: title ? title[1].trim() : `Issue ${i + 1}`,
      severity: sev ? normalizeSeverity(sev[1]) : 'Info',
      cvss: cvss ? Number(cvss[1]) : null,
      vector: vector ? vector[1] : null,
      line: line && /^\d+$/.test(line[1].trim()) ? Number(line[1]) : null,
      lineLabel: line ? line[1].trim() : null,
      location: location ? location[1].trim() : null,
      owasp: owasp ? owasp[1].trim() : null,
      explanation,
      why,
      recommendation,
      vulnCode,
      fixedCode,
      source: 'ai',
    });
  });

  return report;
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
