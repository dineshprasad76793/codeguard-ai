// Zero-dependency regression tests for the custom-rule classification engine.
// Run with:  node tests/rules.test.mjs   (from the frontend/ directory)
//
// The source files use ESM `export` while the CRA package is CommonJS, so we
// load them by rewriting the export keywords and evaluating in a module scope.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
function strip(src) {
  return src
    .replace(/^import .*$/gm, '')
    .replace(/^export const /gm, 'const ')
    .replace(/^export function /gm, 'function ')
    .replace(/^export \{[^}]*\};?/gm, '');
}
function loadEngine() {
  const constants = strip(readFileSync(join(here, '..', 'src/lib/constants.js'), 'utf8'));
  const detect = strip(readFileSync(join(here, '..', 'src/lib/detect.js'), 'utf8'));
  return new Function(`${constants}\n${detect}; return { detectLanguage, runCustomRules, DEFAULT_RULES };`)();
}

const { runCustomRules, DEFAULT_RULES } = loadEngine();

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

const titles = (f) => (f || []).map((x) => x.title);

// ── The two reported false positives ───────────────────────────────
test('console.log("Password:", req.body.password) is NOT a hardcoded password', () => {
  const f = runCustomRules('console.log("Password:", req.body.password);', []);
  for (const x of f) assert.ok(!/hardcoded password/i.test(x.title), `wrong title: ${x.title}`);
});

test('console.log of a secret variable is classified as sensitive-data logging', () => {
  const code = 'logger.info("user password:", user.password);';
  const f = runCustomRules(code, []);
  assert.ok(f.length >= 1, 'expected a logging finding');
  assert.match(titles(f)[0], /logs/i);
  assert.equal(f[0].severity, 'Medium');
  assert.equal(f[0].cwe, 'CWE-532');
});

test('YOUR_API_KEY_HERE is Info placeholder, never a hardcoded credential', () => {
  const f = runCustomRules('const API_KEY = "YOUR_API_KEY_HERE";', []);
  assert.ok(f.length >= 1);
  assert.match(titles(f)[0], /placeholder/i);
  assert.equal(f[0].severity, 'Info');
  assert.equal(f[0].category, 'Informational');
});

test('CHANGE_ME placeholder suppressed as real secret', () => {
  const f = runCustomRules('const TOKEN = "CHANGE_ME";', []);
  for (const x of f) assert.ok(!/hardcoded/i.test(x.title));
});

test('example-token suppressed', () => {
  const f = runCustomRules('const EXAMPLE_TOKEN = "example-token";', []);
  for (const x of f) assert.ok(!/hardcoded/i.test(x.title));
});

// ── Real secrets stay detected ─────────────────────────────────────
test('sk_live_ production key → Confirmed/High/High-confidence', () => {
  const f = runCustomRules('const productionToken = "sk_live_a1b2c3d4e5f6g7h8i9j0";', []);
  assert.ok(f.length >= 1);
  assert.match(titles(f)[0], /Hardcoded production credential/i);
  assert.equal(f[0].severity, 'High');
  assert.equal(f[0].confidence, 'High');
  assert.equal(f[0].category, 'Confirmed Vulnerability');
  assert.equal(f[0].cwe, 'CWE-798');
});

test('generic literal password → Potential with honest confidence', () => {
  const f = runCustomRules('const password = "RealSecretValue123";', []);
  assert.ok(f.length >= 1);
  assert.match(titles(f)[0], /Potential hardcoded/i);
  assert.equal(f[0].category, 'Potential Vulnerability');
  assert.ok(['Medium', 'Low', 'High'].includes(f[0].confidence));
});

test('AWS access key still detected', () => {
  const f = runCustomRules('const k = "AKIAIOSFODNN7EXAMPLE";', []);
  assert.ok(f.length >= 1);
});

test('private key block still detected', () => {
  const f = runCustomRules('const PEM = `-----BEGIN RSA PRIVATE KEY-----`;', []);
  assert.ok(f.length >= 1);
});

// ── Safe-code non-detections ───────────────────────────────────────
test('variable-to-variable assignment (const userPassword = password) → nothing', () => {
  const f = runCustomRules('const userPassword = password;', []);
  assert.equal(f.length, 0);
});

test('admin username literal → nothing', () => {
  const f = runCustomRules('const adminUsername = "admin";', []);
  for (const x of f) assert.ok(!/hardcoded/i.test(x.title));
});

test('bcrypt hash is Informational, not a plaintext credential', () => {
  const f = runCustomRules('const password_hash = "$2b$12$KIXQvIqpGhAeOqOd1sT4eOy0Vv1ZqZqZqZqZqZqZqZqZqZqZqZqZq";', []);
  const hashes = f.filter((x) => /hash/i.test(x.title));
  assert.ok(hashes.length >= 1);
  assert.equal(hashes[0].severity, 'Info');
});

test('crypto.randomBytes never flagged', () => {
  const f = runCustomRules('const iv = crypto.randomBytes(32).toString("hex");', []);
  assert.equal(f.length, 0);
});

test('parameterized SQL never flagged by custom rules', () => {
  const f = runCustomRules('db.query("SELECT * FROM users WHERE id = ?", [id]);', []);
  assert.equal(f.length, 0);
});

// ── Dedup ──────────────────────────────────────────────────────────
test('overlapping matches on one line deduplicate', () => {
  const code = 'console.log("password:", "sk_live_a1b2c3d4e5f6g7h8i9j0");';
  const f = runCustomRules(code, []);
  const keys = f.map((x) => `${x.line}:${x.title}`);
  assert.equal(new Set(keys).size, keys.length, 'duplicate findings on same line');
});

// ── Custom (user) rules still work ─────────────────────────────────
test('user-defined rules are honored', () => {
  const f = runCustomRules('const cfg = "magic-marker-value";', [
    { id: 'user-1', name: 'Magic marker', pattern: 'magic-marker-value', enabled: true },
  ]);
  assert.ok(f.length >= 1);
});

test('invalid user regex is skipped silently', () => {
  const f = runCustomRules('const x = "(";', [
    { id: 'bad', name: 'Bad', pattern: '([', enabled: true },
  ]);
  assert.ok(Array.isArray(f));
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
