export const LANGUAGES = [
  'Python', 'JavaScript', 'TypeScript', 'Java', 'Go', 'PHP',
  'C', 'C++', 'C#', 'Rust', 'Ruby', 'Kotlin', 'Swift', 'HTML', 'CSS',
];

export const EXT_TO_LANG = {
  py: 'Python',
  js: 'JavaScript', mjs: 'JavaScript', jsx: 'JavaScript',
  ts: 'TypeScript', tsx: 'TypeScript',
  java: 'Java',
  go: 'Go',
  php: 'PHP',
  c: 'C', h: 'C',
  cpp: 'C++', cc: 'C++', cxx: 'C++', hpp: 'C++',
  cs: 'C#',
  rs: 'Rust',
  rb: 'Ruby',
  kt: 'Kotlin', kts: 'Kotlin',
  swift: 'Swift',
  html: 'HTML', htm: 'HTML',
  css: 'CSS',
};

export const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'];

export const SEVERITY_ORDER = {
  Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4, Custom: 5,
};

// Built-in local secret-detection rules (JavaScript regex, case-insensitive
// via the 'gi' flag applied at match time).
export const DEFAULT_RULES = [
  {
    id: 'rule-password',
    name: 'Hardcoded password',
    pattern: '\\b(password|passwd|pwd|secret)\\b\\s*[:=]\\s*["\'][^"\']{3,}["\']',
    enabled: true,
  },
  {
    id: 'rule-apikey',
    name: 'Hardcoded API key or token',
    pattern: '\\b(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key)\\b\\s*[:=]\\s*["\'][A-Za-z0-9_\\-.+/]{12,}["\']',
    enabled: true,
  },
  {
    id: 'rule-aws',
    name: 'AWS access key ID',
    pattern: 'AKIA[0-9A-Z]{16}',
    enabled: true,
  },
  {
    id: 'rule-privkey',
    name: 'Private key material',
    pattern: '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    enabled: true,
  },
  {
    id: 'rule-connstr',
    name: 'Connection string with credentials',
    pattern: '(postgres|mysql|mongodb(\\+srv)?|redis|amqp)://[^\\s/:]+:[^\\s/@]+@',
    enabled: true,
  },
];

export const MAX_HISTORY = 15;
