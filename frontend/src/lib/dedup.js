// Final finding normalization + semantic deduplication layer.
//
// The AI report and the custom-rule engine can describe the SAME underlying
// vulnerability with different titles ("Hardcoded production API key" vs
// "Hardcoded production credential (custom rule match)"). This module maps
// findings to normalized vulnerability IDs, merges semantically identical
// ones (same type + same line/value), and drops placeholder noise.
//
// Different vulnerabilities on the same line stay separate: dedup only ever
// merges findings that normalize to the same type.

// Obvious sample values that must never surface as real credentials.
const PLACEHOLDER_VALUE_RE =
  /YOUR[_\s-]?API[_\s-]?KEY|YOUR[_\s-]?TOKEN|CHANGE[_-]?ME|REPLACE[_-]?ME|INSERT[_-]?(API[_-]?KEY|TOKEN)|EXAMPLE[-_]?(TOKEN|SECRET|KEY)|TEST[-_]?(TOKEN|SECRET|KEY)|DUMMY[-_]?(TOKEN|SECRET|KEY)|SAMPLE[-_]?(TOKEN|SECRET|KEY)|<API_KEY>|<TOKEN>|placeholder|example[-_]?(secret|key)|test[-_]?(secret|key)|xxxxxx|\*\*\*\*/i;

/**
 * Map a finding to a normalized vulnerability ID.
 * Returns null for types we don't deduplicate (they pass through as-is).
 */
export function normalizeType(f) {
  const t = `${f.title || ''} ${f.category || ''}`;
  if (/placeholder/i.test(t)) return 'PLACEHOLDER_SECRET';
  // Logging must be checked before credential matching: "sensitive password
  // logged" titles must not be absorbed by hardcoded-credential rules.
  // Tolerates spelling drift ("Sensititive", "sensetive") and phrasing like
  // "authorization header logging".
  if (
    f.cwe === 'CWE-532' ||
    /(sensitive|sensitive|sensetive|sensitiive)[^.]*(log|expos)|log(s|ged|ging)[^.\n]{0,40}(password|credential|secret|token|authorization|api[_-]?key)|data exposure in logs|logged to (console|logs)|password logging|logging (of )?(password|credential|secret|header)/i.test(t)
  ) {
    return 'SENSITIVE_DATA_LOGGING';
  }
  if (
    f.cwe === 'CWE-798' ||
    /hardcoded (production |secret |api |credential|password|token)|hardcoded (api|auth)[_ ]?key|provider (api )?key|production credential/i.test(t)
  ) {
    return 'HARDCODED_PRODUCTION_CREDENTIAL';
  }
  if (/sql injection/i.test(t)) return 'SQL_INJECTION';
  if (/command injection/i.test(t)) return 'COMMAND_INJECTION';
  if (/remote code execution|\brce\b|unsafe eval|code execution via eval/i.test(t)) return 'RCE_EVAL';
  if (/cross-site scripting|\bxss\b/i.test(t)) return 'XSS';
  if (/(path|directory) traversal/i.test(t)) return 'PATH_TRAVERSAL';
  if (/ssrf|server-side request forgery/i.test(t)) return 'SSRF';
  if (/(weak|unsalted|broken).*(password )?hash|md5|sha-?1/i.test(t)) return 'WEAK_PASSWORD_HASHING';
  if (/open redirect/i.test(t)) return 'OPEN_REDIRECT';
  if (/\bidor\b|insecure direct object/i.test(t)) return 'IDOR';
  if (/(insecure|disabled|no |missing)[^.]*(tls|certificate)|certificate validation/i.test(t)) return 'INSECURE_TLS';
  if (/weak (randomness|random)|predictable random/i.test(t)) return 'WEAK_RANDOMNESS';
  if (/insecure (de)?serialization|unsafe (de)?serialization|pickle/i.test(t)) return 'UNSAFE_DESERIALIZATION';
  return null;
}

function severityRank(s) {
  return { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 }[s] ?? -1;
}

function mentionsPlaceholder(f) {
  const hay = `${f.title || ''} ${f.vulnCode || ''} ${f.evidence || ''} ${f.explanation || ''}`;
  return PLACEHOLDER_VALUE_RE.test(hay);
}

/**
 * Merge duplicate findings, keeping the strongest evidence.
 * Primary = the finding with the highest severity; on ties the earlier one
 * wins (AI findings are listed before custom-rule findings), so the AI's
 * title is preserved when it is at least as severe.
 */
function mergeInto(primary, dup) {
  if (severityRank(dup.severity) > severityRank(primary.severity)) {
    primary.severity = dup.severity;
    primary.title = dup.title;
    primary.category = dup.category;
  }
  // Strongest confidence wins.
  const confRank = { High: 3, Medium: 2, Low: 1 };
  if ((confRank[dup.confidence] || 0) > (confRank[primary.confidence] || 0)) {
    primary.confidence = dup.confidence;
  }
  if (!primary.cwe && dup.cwe) primary.cwe = dup.cwe;
  if (!primary.owasp && dup.owasp) primary.owasp = dup.owasp;
  if (!primary.cvss && dup.cvss) { primary.cvss = dup.cvss; primary.vector = dup.vector; }
  if (!primary.vulnCode && dup.vulnCode) primary.vulnCode = dup.vulnCode;
  if (!primary.line && dup.line) { primary.line = dup.line; primary.lineLabel = dup.lineLabel; }
  // Record that both engines independently flagged the same issue.
  const fromCustom = dup.source === 'custom';
  const note = fromCustom
    ? 'Also detected independently by the custom rule engine.'
    : 'Also detected independently by AI analysis.';
  if (!/custom rule engine|AI analysis\.$/.test(primary.whyDetected || '')) {
    primary.whyDetected = `${primary.whyDetected ? primary.whyDetected + ' ' : ''}${note}`;
  }
  primary.mergedSources = Array.from(
    new Set([...(primary.mergedSources || [primary.source]), dup.source])
  );
  return primary;
}

// Logging statements within this many lines of each other are treated as
// one logging root cause (a logging block).
const LOG_PROXIMITY_LINES = 30;

/**
 * Cluster same-type logging findings that are close together (e.g. a
 * password log line and an authorization-header log line in one block) and
 * merge each cluster into ONE finding whose evidence contains every
 * statement. Different vulnerability types are never merged here.
 */
function mergeProximityLogging(kept) {
  const logs = kept.filter((f) => f._norm === 'SENSITIVE_DATA_LOGGING');
  if (logs.length <= 1) return kept;
  const sorted = [...logs].sort((a, b) => (a.line ?? 0) - (b.line ?? 0));
  const clusters = [[sorted[0]]];
  for (let i = 1; i < sorted.length; i++) {
    const prev = clusters[clusters.length - 1];
    const lastLine = Math.max(...prev.map((f) => f.line ?? 0));
    if ((sorted[i].line ?? 0) - lastLine <= LOG_PROXIMITY_LINES) {
      prev.push(sorted[i]);
    } else {
      clusters.push([sorted[i]]);
    }
  }
  // Remove all log findings from kept, then re-insert one merged finding
  // per cluster at the position of its earliest-line member.
  const mergedIds = new Set(clusters.flat().map((f) => f.id));
  const out = kept.filter((f) => !mergedIds.has(f.id));
  const rank = { High: 3, Medium: 2, Low: 1 };
  for (const cluster of clusters) {
    const primary = cluster.find((f) => f.source !== 'custom') || cluster[0];
    const merged = Object.assign({}, primary);
    merged.title = 'Sensitive Data Exposure in Logs';
    merged.severity = cluster.reduce(
      (best, f) => (rank[f.severity] > rank[best] ? f.severity : best),
      'Medium'
    );
    merged.line = Math.min(...cluster.map((f) => f.line ?? 999999));
    merged.lineLabel = String(merged.line);
    merged.confidence = cluster.reduce(
      (best, f) => (rank[f.confidence] > rank[best] ? f.confidence : best),
      'Medium'
    );
    if (!merged.cwe) merged.cwe = (cluster.find((f) => f.cwe) || {}).cwe || 'CWE-532';
    if (!merged.owasp) merged.owasp = (cluster.find((f) => f.owasp) || {}).owasp || null;
    // Combine every logged statement into the evidence.
    const unique = [...new Set(cluster.map((f) => (f.vulnCode || '').trim()).filter(Boolean))];
    if (unique.length > 1) merged.vulnCode = unique.join('\n');
    merged.category = cluster.some((f) => f.category === 'Confirmed Vulnerability')
      ? 'Confirmed Vulnerability'
      : 'Potential Vulnerability';
    merged.mergedCount = cluster.length;
    merged.whyDetected = `${merged.whyDetected ? merged.whyDetected + ' ' : ''}${
      cluster.length > 1 ? cluster.length + ' related logging statements were consolidated into this finding.' : ''
    }`.trim();
    const insertAt = out.findIndex((f) => (f.line ?? 999999) > merged.line);
    if (insertAt === -1) out.push(merged);
    else out.splice(insertAt, 0, merged);
  }
  return out;
}

/**
 * Normalize + deduplicate a merged findings list.
 * - Placeholder "secrets" are dropped entirely (hygiene mode off).
 * - Findings that normalize to the same type on the same line (or the same
 *   embedded credential value) merge into one finding.
 * - Findings with no normalized type pass through untouched.
 */
export function dedupeFindings(issues) {
  const kept = [];
  const byKey = new Map();
  const credentialValues = new Set(); // real credential values already reported

  for (const f of issues || []) {
    const norm = normalizeType(f);

    // Placeholders: never security findings (hygiene reporting is off).
    if (norm === 'PLACEHOLDER_SECRET') continue;
    if (
      norm === 'HARDCODED_PRODUCTION_CREDENTIAL' &&
      mentionsPlaceholder(f)
    ) {
      continue; // an AI finding about an obvious sample value
    }

    const key = `${norm}:${f.line ?? 'na'}`;
    const existing = byKey.get(key);
    if (existing) {
      // Same normalized type on the same line: merge evidence into one.
      mergeInto(existing, f);
      continue;
    }

    // Cross-line check: the same credential value reported elsewhere is the
    // same vulnerability — skip it (only reached when no same-line match).
    let valueKey = '';
    if (norm === 'HARDCODED_PRODUCTION_CREDENTIAL') {
      const m = (f.vulnCode || '').match(/["']([A-Za-z0-9+/_\-]{16,})["']/);
      if (m) {
        valueKey = m[1];
        if (credentialValues.has(valueKey)) continue;
        credentialValues.add(valueKey);
      }
    }

    const rec = Object.assign({}, f, { _norm: norm });
    byKey.set(key, rec);
    kept.push(rec);
  }
  // Second pass: consolidate logging statements that are part of the same
  // logging block into a single root-cause finding.
  return mergeProximityLogging(kept);
}

// Report category chips must match the findings actually listed. The AI
// writes its summary block before dedup runs, so its counts overcount once
// merges happen (5 raw findings, 4 listed).
const REPORT_CATEGORIES = [
  'Confirmed Vulnerability',
  'Potential Vulnerability',
  'Security Hardening',
  'Code Quality',
  'Informational',
];

export function recountCategories(issues) {
  const counts = {};
  for (const c of REPORT_CATEGORIES) counts[c] = 0;
  for (const f of issues || []) {
    if (!f) continue;
    if (counts[f.category] !== undefined) counts[f.category] += 1;
  }
  return counts;
}
