// Offline test harness: builds a real PDF via lib/pdf.js in Node and
// writes it to a temp file so we can verify the output is valid.
import { writeFileSync } from 'fs';
import { buildPdfReport, sortFindings } from './src/lib/pdf.js';

const issues = [
  {
    id: 'ai-0',
    title: 'SQL injection in login query — very long title that must wrap across lines to test the wrapping behaviour of the PDF renderer with lots of text',
    severity: 'Critical',
    cvss: 9.8,
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    line: 42,
    lineLabel: null,
    location: 'app.py — login()',
    owasp: 'A03:2021 Injection',
    explanation:
      'The query is built with string formatting, so attacker-controlled input changes the SQL. A quote character breaks out of the string literal — unicode test: \u201cquotes\u201d, dash \u2014, arrow \u2192, bullet \u2022.',
    why: 'An attacker can log in as any user or dump the whole users table without knowing a password.',
    recommendation:
      'Use parameterised queries, e.g. cursor.execute("SELECT * FROM users WHERE name = %s", (name,)).',
    vulnCode: 'q = f"SELECT * FROM users WHERE name = \'{name}\'"\ncursor.execute(q)',
    fixedCode: 'cursor.execute(\n  "SELECT * FROM users WHERE name = %s", (name,)\n)',
    source: 'ai',
  },
  {
    id: 'ai-1',
    title: 'Hardcoded API key',
    severity: 'High',
    cvss: 7.5,
    vector: null,
    line: 7,
    lineLabel: null,
    location: null,
    owasp: 'A02:2021 Cryptographic Failures',
    explanation: 'A secret token is committed in source control.',
    why: 'Anyone with repository access can use the key.',
    recommendation: 'Move the key to an environment variable and rotate it.',
    vulnCode: 'API_KEY = "sk-live-abcdefghijklmnop"',
    fixedCode: 'API_KEY = os.environ["API_KEY"]',
    source: 'ai',
  },
  {
    id: 'ai-2',
    title: 'Missing input validation',
    severity: 'Medium',
    cvss: 5.3,
    vector: null,
    line: null,
    lineLabel: 'N/A',
    location: null,
    owasp: null,
    explanation: 'User input is used without length checks.',
    why: 'Very large inputs can slow the endpoint down.',
    recommendation: 'Validate and cap input length before processing.',
    vulnCode: '',
    fixedCode: '',
    source: 'ai',
  },
  {
    id: 'ai-3',
    title: 'Outdated dependency',
    severity: 'Low',
    cvss: 3.1,
    vector: null,
    line: null,
    lineLabel: null,
    location: 'requirements.txt',
    owasp: 'A06:2021 Vulnerable Components',
    explanation: 'An old library version is pinned.',
    why: 'Known bugs are fixed in newer releases.',
    recommendation: 'Upgrade to the latest patch version.',
    vulnCode: '',
    fixedCode: '',
    source: 'ai',
  },
];

// Force pagination: duplicate the critical finding several times.
const many = [];
for (let i = 0; i < 6; i++) many.push(...issues.map((f, j) => ({ ...f, id: `ai-${i}-${j}` })));

const report = {
  quality: 6,
  security: 4,
  counts: { Critical: 6, High: 6, Medium: 6, Low: 6 },
  issues: many,
  raw: 'raw text fallback',
};

const doc = buildPdfReport(report, { mode: 'code', target: 'Python code (120 lines)' }, sortFindings(many));
const buf = Buffer.from(doc.output('arraybuffer'));
writeFileSync('test-report.pdf', buf);

const pages = doc.getNumberOfPages();
console.log(`OK: wrote test-report.pdf (${buf.length} bytes), pages=${pages}`);
