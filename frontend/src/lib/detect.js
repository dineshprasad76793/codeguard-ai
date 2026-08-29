import { DEFAULT_RULES } from './constants';

// Heuristic language detection from pasted code. Order matters:
// the most distinctive markers are checked first.
export function detectLanguage(code) {
  if (!code || !code.trim()) return null;
  const t = code;

  if (/^\s*<\?php/.test(t) || /\bfunction\s+\w+\s*\([^)]*\)\s*{?\s*$/m.test(t) && /<\?php|\$\w+\s*=/.test(t)) {
    if (/\<\?php/.test(t)) return 'PHP';
  }
  if (/-----BEGIN/.test(t) && /CERTIFICATE/.test(t)) return null;
  if (/^\s*package\s+main/m.test(t) && /\bfunc\s+\w+\(/.test(t)) return 'Go';
  if (/\bfn\s+main\s*\(/.test(t) || /^\s*use\s+\w+::/m.test(t)) return 'Rust';
  if (/^\s*def\s+\w+.*:\s*$/m.test(t) || /^\s*import\s+\w+(\s+as\s+\w+)?\s*$/m.test(t) && /def\s|class\s+\w+.*:/.test(t)) {
    if (/^\s*(def|class)\s/m.test(t) || /self\./.test(t) || /print\(/.test(t) && !/console\./.test(t)) return 'Python';
  }
  if (/^\s*#!.*\b(ruby|python|perl|bash|sh)\b/.test(t)) {
    const m = t.match(/^#!.*\b(ruby|python)\b/);
    if (m) return m[1][0].toUpperCase() + m[1].slice(1);
  }
  if (/puts\s+|^\s*end\s*$/m.test(t) && /\bdef\s+\w+/m.test(t) && !/function/.test(t)) return 'Ruby';
  if (/console\.(log|error)\s*\(|\b(const|let|var)\s+\w+\s*=|=>\s*{/.test(t)) {
    if (/\binterface\s+\w+|:\s*(string|number|boolean)\b/.test(t)) return 'TypeScript';
    return 'JavaScript';
  }
  if (/public\s+static\s+void\s+main|System\.out\.print/.test(t)) return 'Java';
  if (/\bfun\s+main\s*\(/.test(t)) return 'Kotlin';
  if (/\bimport\s+(UIKit|Foundation|SwiftUI)/.test(t) || /\bfunc\s+\w+\([^)]*\)\s*->\s*\w+/.test(t)) return 'Swift';
  if (/using\s+System|Console\.Write/.test(t)) return 'C#';
  if (/#include\s*<[\w.]+>/.test(t)) return /\b(cout|cin|std::)\b/.test(t) ? 'C++' : 'C';
  if (/<!DOCTYPE html|<html[\s>]/i.test(t)) return 'HTML';
  if (/^[.#\w\s:,()\-\n]*\{[^}]*:[^}]*;[^}]*\}/m.test(t) && /\{[^}]*:[^}]*;/.test(t) && !/function|=>/.test(t)) return 'CSS';
  if (/^\s*#include/.test(t)) return 'C';
  return null;
}

// ── Custom-rule classification helpers ─────────────────────────────
// Rules only LOCATE a pattern; the classifier decides what (if anything)
// the match means using the full line's context.

const LOG_LINE_RE = /console\.(log|debug|info|warn|error|trace|dir)\s*\(|\bprint\s*\(|\bprintf\s*\(|\blogger?\.\w+\s*\(|\blogging\.\w+\s*\(|System\.out\.print|\becho\s+/;

// Values that are obviously samples — never real credentials.
const PLACEHOLDER_RE = /your[_\s-]?(api[_-]?key|token|secret|password)|change[_-]?me|replace[_-]?me|insert[_-]?(api[_-]?key|token)|example[-_]?(token|secret|key)|test[-_]?(token|secret|key)|dummy[-_]?(token|secret|key)|sample[-_]?(token|secret|key)|<[^>]*>|^xxx+$|^-+$|^null$|^undefined$|placeholder/i;

// Password hashes are stored digests, not plaintext credentials.
const HASH_PREFIX_RE = /^\$(2[aby]|argon2(id|d|i)|scrypt)\$|^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i;

// Provider formats strong enough to confirm a real credential.
const PROVIDER_PREFIX_RE = /^sk_live_|^AKIA[0-9A-Z]{16}$|^AIza[0-9A-Za-z\-_]{35}$|^ghp_[A-Za-z0-9]{30,}|^xox[bp]-|^-----BEGIN/;

// Values that came from user input rather than source code literals.
const USER_INPUT_RE = /req(uest)?\.(body|query|params|headers|cookies)|\$\_(GET|POST|REQUEST)|request\.form|request\.args|process\.env\.\w*password/i;

const HIGH_ENTROPY_RE = /^[A-Za-z0-9+/_\-]{20,}$/;

function extractLiteral(matchText) {
  const m = matchText.match(/["']([^"']{3,})["']/);
  return m ? m[1] : null;
}

/**
 * Classify a rule match using full-line context.
 * Returns null when the match should be suppressed entirely.
 */
function classifyMatch(rule, matchText, lineText) {
  const isDefaultRule = /^rule-/.test(rule.id || '');
  const isLog = LOG_LINE_RE.test(lineText);
  const literal = extractLiteral(matchText);
  const secretish = /password|passwd|pwd|secret|token|api[_-]?key/i.test(rule.name + ' ' + matchText);

  // 1) Logging statements: a logged password/token variable is sensitive-
  //    data logging (Medium), NEVER a "hardcoded password".
  if (isLog && secretish) {
    const loggedLiteral = literal && !PLACEHOLDER_RE.test(literal) && PROVIDER_PREFIX_RE.test(literal);
    return {
      title: 'Sensitive data exposure in logs (custom rule match)',
      severity: loggedLiteral ? 'High' : 'Medium',
      confidence: 'Medium',
      category: loggedLiteral ? 'Confirmed Vulnerability' : 'Potential Vulnerability',
      cwe: 'CWE-532',
      owasp: 'A09:2021-Security Logging and Monitoring Failures',
      explanation:
        'A password/secret-looking value is written to logs. Logs are frequently ' +
        'shipped to aggregators, support tooling, and long-term storage, so credentials ' +
        'there outlive code rotations.',
      why: 'Anyone with read access to logs (ops, support, third-party shippers) obtains the value.',
      recommendation: 'Redact or omit credential values from log output; log identifiers instead of secrets.',
      dedupeClass: 'log-secret',
    };
  }

  // 2) Placeholder values are never real credentials.
  if (literal && PLACEHOLDER_RE.test(literal)) {
    return {
      title: 'Placeholder secret value (custom rule match)',
      severity: 'Info',
      confidence: 'High',
      category: 'Informational',
      cwe: 'CWE-798',
      owasp: null,
      explanation:
        'The value is an obvious placeholder/sample (YOUR_API_KEY, CHANGE_ME, example…). ' +
        'It is not a real credential, but remember to replace it before deploying.',
      why: 'Placeholder values deployed to production are a deployment-hygiene risk, not an exposed secret.',
      recommendation: 'No action needed for correctness; load real credentials from the environment or a secret manager.',
      dedupeClass: 'placeholder',
    };
  }

  // 3) Password HASHES (bcrypt/argon2/scrypt/hex digests) are not plaintext.
  if (literal && HASH_PREFIX_RE.test(literal)) {
    return {
      title: 'Stored password hash — not plaintext (custom rule match)',
      severity: 'Info',
      confidence: 'High',
      category: 'Informational',
      cwe: null,
      owasp: null,
      explanation:
        'The matched value is a password hash/digest (bcrypt/argon2/scrypt/hex digest), ' +
        'not a plaintext credential. Storing hashes is correct practice.',
      why: 'Hash literals in code are still configuration data — prefer environment/secrets — but this is not credential exposure.',
      recommendation: 'Optionally move the hash out of source control; no security bug here.',
      dedupeClass: 'hash-literal',
    };
  }

  // 4) Provider-format tokens are confirmable even without quotes in the
  //    match (e.g. the bare AWS/private-key rules).
  if (PROVIDER_PREFIX_RE.test(matchText) || (literal && PROVIDER_PREFIX_RE.test(literal))) {
    return {
      title: 'Hardcoded production credential (custom rule match)',
      severity: 'High',
      confidence: 'High',
      category: 'Confirmed Vulnerability',
      cwe: 'CWE-798',
      owasp: 'A07:2021-Identification and Authentication Failures',
      explanation:
        'The value matches a known live provider credential format embedded directly in source. ' +
        'Anyone with repository or bundle access can use it immediately.',
      why: 'Provider-format keys are immediately usable and individually billable/abusable.',
      recommendation: 'Remove the literal, rotate the credential, and load it from environment/secret storage.',
      dedupeClass: 'real-cred',
    };
  }

  // 5) Literal credential-like values: real concern, honest confidence.
  if (literal) {
    const entropy = HIGH_ENTROPY_RE.test(literal) && literal.length >= 20;
    return {
      title: `Potential hardcoded ${/password|passwd|pwd/i.test(matchText) ? 'password' : 'credential'} (custom rule match)`,
      severity: 'High',
      confidence: entropy ? 'Medium' : 'Low',
      category: 'Potential Vulnerability',
      cwe: 'CWE-798',
      owasp: 'A07:2021-Identification and Authentication Failures',
      explanation:
        'A credential-like name is assigned a string literal. Static analysis cannot prove the value is a real ' +
        'secret (it may be sample data), so verify before treating it as exposed.',
      why: 'If the value is a real credential, repository access equals credential access.',
      recommendation: 'Verify the value; if real, rotate it and move it to environment/secret storage.',
      manualVerification: 'Yes — confirm whether this literal is a real credential',
      dedupeClass: 'maybe-cred',
    };
  }

  // 6) No literal value in the match.
  if (!isDefaultRule) {
    // User-defined rule: the user explicitly asked for this pattern, so
    // report it as a potential issue with honest, low confidence.
    return {
      title: `Potential issue: ${rule.name} (custom rule match)`,
      severity: 'Medium',
      confidence: 'Low',
      category: 'Potential Vulnerability',
      cwe: null,
      owasp: null,
      explanation:
        `Your custom rule "${rule.name}" matched here. The match is not a literal value, ` +
        'so automated context analysis could not classify it — review manually.',
      why: `Matched pattern: ${matchText.slice(0, 120)}`,
      recommendation: 'Review the match; remove the rule or fix the code as appropriate.',
      manualVerification: 'Yes — review the matched pattern in context',
      dedupeClass: 'user-rule',
    };
  }
  // Built-in rule matching a bare non-provider token: suppress.
  return null;
}

// Proactive sensitive-logging detection: a log statement outputting a
// password/secret/token variable is a Medium finding even when no secret
// rule matches it (there is no literal to match).
function scanSensitiveLogging(code, seen, findings) {
  const lines = code.split('\n');
  const re = /\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b/i;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!LOG_LINE_RE.test(line) || !re.test(line)) continue;
    const dedupeKey = `${i + 1}:log-secret`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    // Skip lines that only log obviously-safe things (e.g. a token's length).
    if (/\.length\b|redact|\*\*\*|\[REDACTED\]/i.test(line)) continue;
    findings.push({
      id: `log-secret-${i}`,
      title: 'Sensitive data exposure in logs (custom rule match)',
      severity: 'Medium',
      confidence: 'Medium',
      category: 'Potential Vulnerability',
      cvss: null,
      vector: null,
      cwe: 'CWE-532',
      line: i + 1,
      lineLabel: String(i + 1),
      location: null,
      owasp: 'A09:2021-Security Logging and Monitoring Failures',
      explanation:
        'A log statement references a password/secret/token value. Logs are frequently ' +
        'shipped to aggregators and long-term storage, so secrets there outlive code rotations.',
      why: 'Anyone with read access to logs obtains the value.',
      recommendation: 'Redact or omit credential values from log output; log identifiers instead of secrets.',
      manualVerification: 'Yes — confirm the logged value is actually sensitive',
      vulnCode: line.trim().slice(0, 200),
      fixedCode: '',
      source: 'custom',
    });
  }
}

// Runs the enabled local rules against the code and returns classified
// findings with line numbers. Overlapping matches on the same line for the
// same issue class are deduplicated.
export function runCustomRules(code, rules) {
  const findings = [];
  const seen = new Set(); // `${line}:${dedupeClass}` dedupe keys
  scanSensitiveLogging(code, seen, findings);
  const all = [...DEFAULT_RULES, ...(rules || [])];
  for (const rule of all) {
    if (rule.enabled === false) continue;
    let re;
    try {
      re = new RegExp(rule.pattern, 'gi');
    } catch (e) {
      continue; // invalid user regex — skip silently
    }
    let match;
    let count = 0;
    while ((match = re.exec(code)) !== null && count < 20) {
      count++;
      if (match.index === re.lastIndex) re.lastIndex++;
      const line = code.slice(0, match.index).split('\n').length;
      const lineStart = code.lastIndexOf('\n', match.index) + 1;
      const lineEnd = code.indexOf('\n', match.index);
      const lineText = code.slice(lineStart, lineEnd === -1 ? code.length : lineEnd);

      const verdict = classifyMatch(rule, match[0], lineText);
      if (!verdict) continue;
      const dedupeKey = `${line}:${verdict.dedupeClass}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      findings.push({
        id: `${rule.id}-${match.index}`,
        title: verdict.title,
        severity: verdict.severity,
        confidence: verdict.confidence,
        category: verdict.category,
        cvss: null,
        vector: null,
        cwe: verdict.cwe || null,
        line,
        lineLabel: String(line),
        location: null,
        owasp: verdict.owasp,
        explanation: verdict.explanation,
        why: verdict.why,
        recommendation: verdict.recommendation,
        manualVerification: verdict.manualVerification || null,
        vulnCode: lineText.trim().slice(0, 200),
        fixedCode: '',
        source: 'custom',
      });
    }
  }
  return findings;
}
