// Zero-dependency regression tests for the finding normalization +
// deduplication layer. Run with:  node tests/dedup.test.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
function strip(src) {
  return src
    .replace(/^import .*$/gm, '')
    .replace(/^export const /gm, 'const ')
    .replace(/^export function /gm, 'function ');
}
const { dedupeFindings, normalizeType, recountCategories } = new Function(
  strip(readFileSync(join(here, '..', 'src/lib/dedup.js'), 'utf8')) +
    '; return { dedupeFindings, normalizeType, recountCategories };'
)();

let passed = 0;
let failed = 0;
function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ok  ${name}`);
  } catch (e) {
    failed++;
    console.log(`FAIL  ${name}\n      ${e.message.split('\n')[0]}`);
  }
}

// ── Normalization ──────────────────────────────────────────────────
test('AI + custom credential titles normalize to the same type', () => {
  assert.equal(
    normalizeType({ title: 'Hardcoded production API key' }),
    'HARDCODED_PRODUCTION_CREDENTIAL'
  );
  assert.equal(
    normalizeType({ title: 'Hardcoded production credential (custom rule match)', cwe: 'CWE-798' }),
    'HARDCODED_PRODUCTION_CREDENTIAL'
  );
});

test('logging titles normalize before credential matching', () => {
  assert.equal(
    normalizeType({ title: 'Sensitive data exposure in logs (custom rule match)', cwe: 'CWE-532' }),
    'SENSITIVE_DATA_LOGGING'
  );
  assert.equal(
    normalizeType({ title: 'Sensitive data logged to console' }),
    'SENSITIVE_DATA_LOGGING'
  );
  assert.equal(
    normalizeType({ title: 'Sensitive Password Logged' }),
    'SENSITIVE_DATA_LOGGING'
  );
});

test('distinct vulnerability types normalize distinctly', () => {
  assert.equal(normalizeType({ title: 'SQL Injection in login query' }), 'SQL_INJECTION');
  assert.equal(normalizeType({ title: 'Remote Code Execution via eval' }), 'RCE_EVAL');
  assert.equal(normalizeType({ title: 'Cross-site scripting in profile' }), 'XSS');
  assert.equal(normalizeType({ title: 'Path traversal in download handler' }), 'PATH_TRAVERSAL');
  assert.equal(normalizeType({ title: 'SSRF via url parameter' }), 'SSRF');
  assert.equal(normalizeType({ title: 'MD5 used for password hashing' }), 'WEAK_PASSWORD_HASHING');
  assert.equal(normalizeType({ title: 'Open redirect in login return url' }), 'OPEN_REDIRECT');
  assert.equal(normalizeType({ title: 'IDOR on invoice endpoint' }), 'IDOR');
});

// ── The headline dedup scenarios ───────────────────────────────────
test('AI + custom hardcoded API key on the same line merge into ONE', () => {
  const ai = {
    id: 'ai-0', title: 'Hardcoded production API key', severity: 'High',
    confidence: 'High', category: 'Confirmed Vulnerability', line: 5,
    cwe: 'CWE-798', vulnCode: 'const productionApiKey = "sk_live_a1b2c3d4e5f6g7h8i9j0";',
    source: 'ai',
  };
  const custom = {
    id: 'rule-provider-40', title: 'Hardcoded production credential (custom rule match)',
    severity: 'High', confidence: 'High', category: 'Confirmed Vulnerability', line: 5,
    cwe: 'CWE-798', vulnCode: 'const productionApiKey = "sk_live_a1b2c3d4e5f6g7h8i9j0";',
    source: 'custom',
  };
  const out = dedupeFindings([ai, custom]);
  assert.equal(out.length, 1, 'should merge to one finding');
  assert.match(out[0].title, /Hardcoded production API key/); // AI title kept
  assert.match(out[0].whyDetected, /custom rule engine/); // merge noted
});

test('AI + custom sensitive-logging on the same line merge into ONE', () => {
  const ai = {
    id: 'ai-1', title: 'Sensitive data logged to console', severity: 'Medium',
    confidence: 'Medium', category: 'Potential Vulnerability', line: 1,
    cwe: 'CWE-532', source: 'ai',
  };
  const custom = {
    id: 'log-secret-0', title: 'Sensitive data exposure in logs (custom rule match)',
    severity: 'Medium', confidence: 'Medium', category: 'Potential Vulnerability',
    line: 1, cwe: 'CWE-532', source: 'custom',
  };
  const out = dedupeFindings([ai, custom]);
  assert.equal(out.length, 1);
  assert.match(out[0].title, /Sensitive Data Exposure in Logs|Sensitive data/i);
});

// ── Different vulnerabilities on the same line stay separate ───────
test('SQL injection + hardcoded key on the same line remain two findings', () => {
  const sqli = {
    id: 'ai-0', title: 'SQL Injection via concatenated query', severity: 'High',
    confidence: 'High', category: 'Confirmed Vulnerability', line: 3, source: 'ai',
  };
  const cred = {
    id: 'ai-1', title: 'Hardcoded production API key', severity: 'High',
    confidence: 'High', category: 'Confirmed Vulnerability', line: 3, source: 'ai',
  };
  const out = dedupeFindings([sqli, cred]);
  assert.equal(out.length, 2);
});

// ── Placeholders ───────────────────────────────────────────────────
test('placeholder secret findings are dropped entirely', () => {
  const info = {
    id: 'rule-apikey-9', title: 'Placeholder secret value (custom rule match)',
    severity: 'Info', confidence: 'High', category: 'Informational', line: 2,
    source: 'custom',
  };
  assert.equal(dedupeFindings([info]).length, 0);
});

test('AI credential finding about a placeholder value is suppressed', () => {
  const ai = {
    id: 'ai-0', title: 'Hardcoded API key', severity: 'High', confidence: 'Medium',
    category: 'Potential Vulnerability', line: 2,
    vulnCode: 'const API_KEY = "YOUR_API_KEY_HERE";',
    explanation: 'An API key is assigned a literal value.',
    source: 'ai',
  };
  const out = dedupeFindings([ai]);
  assert.equal(out.length, 0, 'placeholder-valued credential must not surface');
});

test('real production credential is NOT suppressed as a placeholder', () => {
  const ai = {
    id: 'ai-0', title: 'Hardcoded production API key', severity: 'High', confidence: 'High',
    category: 'Confirmed Vulnerability', line: 5,
    vulnCode: 'const productionApiKey = "sk_live_a1b2c3d4e5f6g7h8i9j0";',
    source: 'ai',
  };
  assert.equal(dedupeFindings([ai]).length, 1);
});

// ── The exact duplicates from the latest regression report ─────────
test('AI + two custom log findings on nearby lines collapse to ONE', () => {
  const ai = {
    id: 'ai-9', title: 'Sensitive credential and authorization header logging',
    severity: 'Medium', confidence: 'Medium', category: 'Potential Vulnerability',
    line: 51, cwe: 'CWE-532', source: 'ai',
  };
  const c1 = {
    id: 'log-secret-48', title: 'Sensitive data exposure in logs (custom rule match)',
    severity: 'Medium', confidence: 'Medium', category: 'Potential Vulnerability',
    line: 49, cwe: 'CWE-532', vulnCode: 'console.log("Password:", req.body.password);',
    source: 'custom',
  };
  const c2 = {
    id: 'log-secret-51', title: 'Sensitive data exposure in logs (custom rule match)',
    severity: 'Medium', confidence: 'Medium', category: 'Potential Vulnerability',
    line: 52, cwe: 'CWE-532', vulnCode: 'console.log("Authorization:", req.headers.authorization);',
    source: 'custom',
  };
  const out = dedupeFindings([ai, c1, c2]);
  const logs = out.filter((f) => f._norm === 'SENSITIVE_DATA_LOGGING' || /logs/i.test(f.title));
  assert.equal(logs.length, 1, `expected 1 merged log finding, got ${logs.length}`);
  assert.match(logs[0].title, /Sensitive Data Exposure in Logs/);
  assert.ok((logs[0].vulnCode || '').includes('req.body.password'), 'evidence must include the password statement');
  assert.ok((logs[0].vulnCode || '').includes('req.headers.authorization'), 'evidence must include the authorization statement');
});

test('typo\u0027d AI title (Sensititive) still normalizes to SENSITIVE_DATA_LOGGING', () => {
  assert.equal(
    normalizeType({ title: 'Sensititive data exposure in logs (custom rule match)' }),
    'SENSITIVE_DATA_LOGGING'
  );
  assert.equal(
    normalizeType({ title: 'Sensetive credential logging' }),
    'SENSITIVE_DATA_LOGGING'
  );
});

test('authorization-header logging normalizes to SENSITIVE_DATA_LOGGING', () => {
  assert.equal(
    normalizeType({ title: 'Sensitive credential and authorization header logging' }),
    'SENSITIVE_DATA_LOGGING'
  );
});

test('log findings far apart (>30 lines) stay separate root causes', () => {
  const a = {
    id: 'log-1', title: 'Sensitive data exposure in logs (custom rule match)',
    severity: 'Medium', confidence: 'Medium', category: 'Potential Vulnerability',
    line: 10, cwe: 'CWE-532', source: 'custom',
  };
  const b = {
    id: 'log-2', title: 'Sensitive data exposure in logs (custom rule match)',
    severity: 'Medium', confidence: 'Medium', category: 'Potential Vulnerability',
    line: 90, cwe: 'CWE-532', source: 'custom',
  };
  const out = dedupeFindings([a, b]);
  assert.equal(out.length, 2, 'distant log findings are separate root causes');
});

test('different vulnerability types near each other stay separate', () => {
  const sqli = {
    id: 'ai-0', title: 'SQL Injection in search', severity: 'High', confidence: 'High',
    category: 'Confirmed Vulnerability', line: 20, source: 'ai',
  };
  const idor = {
    id: 'ai-1', title: 'IDOR on invoice endpoint', severity: 'Medium', confidence: 'Medium',
    category: 'Potential Vulnerability', line: 25, source: 'ai',
  };
  const out = dedupeFindings([sqli, idor]);
  assert.equal(out.length, 2);
});

// ── Non-normalized findings pass through ───────────────────────────
test('findings with no normalized type pass through untouched', () => {
  const odd = {
    id: 'ai-9', title: 'Unusual naming convention reduces readability',
    severity: 'Info', confidence: 'High', category: 'Code Quality', line: 8,
    source: 'ai',
  };
  const out = dedupeFindings([odd]);
  assert.equal(out.length, 1);
  assert.equal(out[0].title, 'Unusual naming convention reduces readability');
});

// ── Same credential on different lines merges ──────────────────────
test('same secret value on different lines merges (value fingerprint)', () => {
  const a = {
    id: 'ai-0', title: 'Hardcoded production API key', severity: 'High', confidence: 'High',
    category: 'Confirmed Vulnerability', line: 2,
    vulnCode: 'const k1 = "sk_live_a1b2c3d4e5f6g7h8i9j0";', source: 'ai',
  };
  const b = {
    id: 'rule-provider-77', title: 'Hardcoded production credential (custom rule match)',
    severity: 'High', confidence: 'High', category: 'Confirmed Vulnerability', line: 9,
    cwe: 'CWE-798', vulnCode: 'use_key("sk_live_a1b2c3d4e5f6g7h8i9j0");', source: 'custom',
  };
  const out = dedupeFindings([a, b]);
  assert.equal(out.length, 1, 'same credential value must merge across lines');
});

// ── Summary count recomputation ────────────────────────────────────
test('recountCategories matches the deduplicated finding list', () => {
  const issues = [
    { id: 'a', category: 'Confirmed Vulnerability' },
    { id: 'b', category: 'Confirmed Vulnerability' },
    { id: 'c', category: 'Security Hardening' },
    { id: 'd', category: 'Code Quality' },
  ];
  const counts = recountCategories(issues);
  assert.equal(counts['Confirmed Vulnerability'], 2);
  assert.equal(counts['Potential Vulnerability'], 0);
  assert.equal(counts['Security Hardening'], 1);
  assert.equal(counts['Code Quality'], 1);
  assert.equal(counts['Informational'], 0);
});

test('recountCategories skips unknown/missing categories and null entries', () => {
  const counts = recountCategories([
    { id: 'x' },
    { id: 'y', category: 'Weird Category' },
    null,
  ]);
  assert.equal(counts['Confirmed Vulnerability'], 0);
  assert.equal(counts['Code Quality'], 0);
  assert.equal(recountCategories(null)['Informational'], 0);
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
