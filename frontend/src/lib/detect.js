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

// Runs the enabled local regex rules against the code and returns
// findings with line numbers.
export function runCustomRules(code, rules) {
  const findings = [];
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
      const line = code.slice(0, match.index).split('\n').length;
      findings.push({
        id: `${rule.id}-${match.index}`,
        title: `${rule.name} (custom rule match)`,
        severity: 'Custom',
        cvss: null,
        vector: null,
        line,
        lineLabel: String(line),
        location: null,
        owasp: null,
        explanation:
          'A local pattern rule matched here. Review this line and confirm whether it is a real issue.',
        why: `Matched pattern: ${match[0].slice(0, 120)}`,
        recommendation: 'If this is a real secret, remove it and rotate the credential.',
        vulnCode: match[0].slice(0, 200),
        fixedCode: '',
        source: 'custom',
      });
      count++;
      if (match.index === re.lastIndex) re.lastIndex++;
    }
  }
  return findings;
}
