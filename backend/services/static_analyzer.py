"""Deterministic static-analysis evidence gatherer for CodeGuard AI.

This module NEVER declares vulnerabilities on its own (that judgment
belongs to the AI under strict classification rules). It produces
structured, line-referenced *evidence hints* that the AI must weigh:

- SQL construction vs prepared-statement usage
- HTML injection sinks and whether sanitization is visible
- Command-execution sinks with fixed vs constructed commands
- Hardcoded secrets with placeholder filtering and masking
- Path construction / traversal patterns
- Deserialization and dynamic-evaluation calls
- Inline event handlers and broad error handling (quality hints)
- Network egress candidates for SSRF reasoning
- Auth markers where detectable

Design constraints:
- Language-agnostic (regex over lines; works for Python/JS/TS/Java/Go/PHP)
- Cheap: linear in file size, no AST dependency
- Safe: secret values are always masked in emitted snippets
"""
import re
from dataclasses import dataclass, field

# ── Placeholder / noise values never reported as secrets ──────────
PLACEHOLDER_RE = re.compile(
    r"^(?://|/\*|<!--|#)?\s*$"
    r"|your[\s_-]?(api[\s_-]?key|token|secret|password)"
    r"|\b(example|sample|placeholder|dummy|test|dummyvalue|changeme|change-me"
    r"|xxx+|abc+|123+|abcdef|password|secret|token|apikey|api_key|not[a-z]*real"
    r"|todo|fixme|none|null|nil|undefined|true|false|redacted|masked)\b"
    r"|^[a-z0-9]*$"
    r"|\.\.\.|…|\{.+\}|<[^>]+>|\$\{.+\}",
    re.IGNORECASE,
)

SECRET_PATTERNS = [
    # name-based (assignment of a literal to a secret-looking variable)
    (re.compile(
        r"""(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|
            private[_-]?key|client[_-]?secret|password|passwd|pwd|token)\s*
            [=:]\s*["'][^"']{6,}["']""", re.IGNORECASE | re.VERBOSE), "credential-assignment"),
    # AWS access key id
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws-access-key"),
    # AWS secret / long base64ish keys assigned to key-like names
    (re.compile(r"""\b(?i:aws)?_?(?i:secret)?_?(?i:access)?_?(?i:key)\b\s*[=:]\s*["'][A-Za-z0-9/+=]{32,}["']"""), "long-key"),
    # Google API keys
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "google-api-key"),
    # Private key blocks
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), "private-key-block"),
    # JWTs
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"), "jwt"),
    # Generic high-entropy hex/base64 assigned to secret-ish names
    (re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9]{20,}\b"), "prefixed-api-key"),
]

ENTROPYISH_RE = re.compile(r"^[A-Za-z0-9+/_\-]{16,}$")

SQL_EXEC_RE = re.compile(
    r"""\.execute(?:Query|Update|Many|Scalar)?\s*\(|\bexecute\s*\(|\bquery\s*\(
        |\bdb\.query\b|\bcursor\.\w+\s*\(""", re.VERBOSE)
SQL_TEXT_RE = re.compile(
    r"""(?i)\b(?:SELECT\b.+\bFROM\b|INSERT\b.+INTO|UPDATE\b.+\bSET\b
        |DELETE\b.+FROM|DROP\s+TABLE|CREATE\s+TABLE|ALTER\s+TABLE|UNION\s+SELECT)""")
SQL_DYNAMIC_RE = re.compile(
    r"""\+\s*["'`]|["'`]\s*\+|\bf["']|\$\{|\.format\s*\(|%\s*\(|["'`][^"'
]*["'`]\s*\+""",
    re.VERBOSE)

SQL_PREPARED_RE = re.compile(
    r"""["'`][^"'`]*(?:\?|\:\w+|\%s|\$\d+)[^"'`]*["'`]\s*,\s*
        (?:\(|\[|\{|\w)""", re.VERBOSE)
PARAM_STYLE_RE = re.compile(r"""["'`][^"'`]*(?:\?|%s|:\w+|\$\d+)[^"'`]*["'`]""")
ORM_RE = re.compile(
    r"""\b(?:sequelize|prisma|sqlalchemy|django|hibernate|typeorm|knex|gorm|
        active_?record|peewee|mongoose|sqlite3?\.connect)\b""", re.IGNORECASE | re.VERBOSE)

HTML_SINK_RE = re.compile(
    r"""\.innerHTML\s*=|\.outerHTML\s*=|document\.write(?:ln)?\s*\(|\bv-html\s*=|
        dangerouslySetInnerHTML|insertAdjacentHTML\s*\(|\$\([^)]*\)\.html\s*\(|\.html\(""",
    re.VERBOSE)
SANITIZER_RE = re.compile(
    r"""\bescapeHtml\b|\bhtml\.escape\b|\bescape\(|\bDOMPurify(?:\.sanitize)?\b|
        \bsanitize(?:Html|HTML)?\b|\bencodeURI(?:Component)?\b|\btextContent\s*=|
        \bcreateTextNode\b|\binnerText\s*=|\bxss\(|\bescapeJs\b|\bjsesc\b""",
    re.IGNORECASE | re.VERBOSE)

CMD_SINK_RE = re.compile(
    r"""\bos\.(?:system|popen)\s*\(|subprocess\.(?:call|run|check_output|Popen)\s*\(|
        \bexec(?:Sync|SyncFile|File)?\s*\(|\bexecvp\w*\s*\(|\bspawn(?:Sync)?\s*\(|
        child_process|\bRuntime\.getRuntime\(\)\.exec\s*\(|\bshell_exec\b|\bsystem\s*\(""",
    re.VERBOSE)
CMD_SHELL_TRUE_RE = re.compile(r"shell\s*=\s*True")
STRING_LITERAL_RE = re.compile(r"""^["'][^"'\\\n]*["']$""")

NET_CALL_RE = re.compile(
    r"""\bfetch\s*\(|\baxios(?:\.\w+)?\s*\(|\brequests\.(?:get|post|put|delete|head|request)\s*\(|
        \burg?lib\.(?:request|urlopen)\s*\(|\bhttp\.(?:Get|Post)\s*\(|\bcurl_init\s*\(|\bHttpClient\b""",
    re.VERBOSE)
URL_INPUT_RE = re.compile(
    r"""request\.(?:GET|POST|body|query|params)|req\.(?:query|body|params)|
        request\.form|request\.args|input\s*\(|\$request|params\[|req\.url|request\.url|
        window\.location|document\.location|localStorage|sessionStorage""", re.VERBOSE)
ALLOWLIST_RE = re.compile(
    r"""\b(?:allowlist|whitelist|allowed_hosts|ALLOWED_HOSTS|is_valid_url|validate_url|
        urlparse|permitted_hosts|trusted_hosts|HOSTS\s*=)\b""", re.VERBOSE)

PATH_OP_RE = re.compile(
    r"""\bopen\s*\(|\breadFile(?:Sync)?\s*\(|\bwriteFile(?:Sync)?\s*\(|\bos\.path\.join\s*\(|
        \bPath\s*\(|\bpath\.join\s*\(|\bfopen\s*\(|\bos\.remove\b|\bshutil\.\w+\s*\(|\bFiles\.\w+\s*\(""",
    re.VERBOSE)
TRAVERSAL_RE = re.compile(r"""\.\./|\.\.\\|\.\.%2f|%2e%2e""", re.IGNORECASE)
NORM_RE = re.compile(r"""\b(?:realpath|abspath|normalize|canonical|resolve)\s*\(|\bbasename\s*\(""", re.VERBOSE)

DESER_RE = re.compile(
    r"""\bpickle\.loads?\s*\(|\bcPickle\.loads?\s*\(|\bmarshal\.loads?\s*\(|\byaml\.load\s*\((?!.*Safe)|
        \byaml\.unsafe_load\b|\bObjectInputStream\b|\breadsObject\b|\bunserialize\s*\(|\bMarshal\.load\b""",
    re.VERBOSE)
SAFE_PARSE_RE = re.compile(
    r"""\byaml\.safe_load\b|\bJSON\.parse\b|\bjson\.loads?\b|\bjson_decode\b|\bpickle\.load\b[^#\n]*file""",
    re.VERBOSE)
EVAL_RE = re.compile(
    r"""\bnew\s+Function\s*\(|\bFunction\s*\(\s*['"]|\bsetTimeout\s*\(\s*['"]|
        \bsetInterval\s*\(\s*['"]|\bwindow\s*\[\s*['"]|\beval\s*\(|\bexec\s*\(""",
    re.VERBOSE)

EVENT_ATTR_RE = re.compile(
    r"""\bon(?:click|load|error|mouseover|mouseout|focus|blur|change|submit|input)\s*=""", re.IGNORECASE)
BROAD_CATCH_RE = re.compile(
    r"""\bexcept\s*:|\bexcept\s+Exception\s*:\s*(?:pass|\.\.\.)?\s*$|catch\s*\([^)]*\)\s*\{\s*\}""")

AUTH_MARKER_RE = re.compile(
    r"""\b@login_required\b|\@RequiresAuthentication\b|isAuthenticated|requireLogin|authMiddleware|
        requireAuth|ensureLoggedIn|checkPermission|hasRole|@PreAuthorize|is_admin|isAdmin|requireAdmin""",
    re.VERBOSE)


def mask_secret(value: str) -> str:
    """Never emit a full secret; keep first 3 and last 2 chars at most."""
    v = value.strip()
    if len(v) <= 5:
        return "*" * len(v)
    return f"{v[:3]}{'*' * (len(v) - 5)}{v[-2:]}"


@dataclass
class Hint:
    type: str
    line: int
    snippet: str
    note: str = ""
    confidence: str = "Medium"

    def as_dict(self):
        return {"type": self.type, "line": self.line,
                "snippet": self.snippet.strip()[:200], "note": self.note,
                "confidence": self.confidence}


@dataclass
class Analysis:
    hints: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def add(self, *args, **kwargs):
        self.hints.append(Hint(*args, **kwargs))


def _secret_is_placeholder(value: str, var_name: str) -> bool:
    if PLACEHOLDER_RE.search(value):
        return True
    # value equals/derives from the variable name itself (secret = SECRET)
    if value.strip().lower().replace("_", "") == var_name.strip().lower().replace("_", ""):
        return True
    if not ENTROPYISH_RE.match(value):
        # long values must at least look keyed; short human words are placeholders
        if len(value) < 8 or value.lower() == value and value.isalpha():
            return True
    return False


def analyze_code(code: str, language: str = "") -> Analysis:
    res = Analysis()
    lines = code.splitlines()
    joined = "\n".join(lines)
    lang = (language or "").lower()

    uses_prepared = bool(SQL_PREPARED_RE.search(joined) or PARAM_STYLE_RE.search(joined))
    uses_orm = bool(ORM_RE.search(joined))
    any_sanitizer = bool(SANITIZER_RE.search(joined))

    for i, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith(("#", "//", "/*", "*")):
            continue

        # ── secrets ────────────────────────────────────────────────
        for pat, kind in SECRET_PATTERNS:
            m = pat.search(line)
            if m:
                matched = m.group(0)
                inner = re.search(r"""["']([^"']{6,})["']""", matched)
                value = inner.group(1) if inner else matched
                var = re.search(r"""([A-Za-z_][A-Za-z0-9_]*)\s*[=:]""", line[:m.start()] + matched)
                var_name = var.group(1) if var else "secret"
                if _secret_is_placeholder(value, var_name):
                    res.add("secret-placeholder", i, mask_secret(value),
                            "looks like a placeholder/example value — not a real secret",
                            confidence="Low")
                else:
                    res.add("possible-secret", i, mask_secret(value),
                            f"{kind}; verify whether it is a real credential (masked in this report)",
                            confidence="High" if len(value) >= 20 else "Medium")
                break

        # ── SQL construction ───────────────────────────────────────
        if SQL_TEXT_RE.search(line) or SQL_EXEC_RE.search(line):
            if SQL_DYNAMIC_RE.search(line):
                res.add("sql-dynamic-construction", i, line,
                        "SQL built with concatenation/interpolation — check for user input "
                        "reaching it; parameterized queries are the fix",
                        confidence="High" if not uses_prepared else "Low")
            elif SQL_EXEC_RE.search(line) and not uses_prepared and not uses_orm:
                res.add("sql-execute-no-params", i, line,
                        "query execution without visible parameterization",
                        confidence="Low")

        # ── HTML sinks ─────────────────────────────────────────────
        if HTML_SINK_RE.search(line):
            escaped = bool(SANITIZER_RE.search(line)) or any(
                SANITIZER_RE.search(lines[j]) for j in range(max(0, i - 4), min(len(lines), i + 2)))
            if escaped:
                res.add("htmlSink-sanitized", i, line,
                        "HTML sink reached via visible escaping/sanitization — treat as code "
                        "quality/hardening, NOT automatic XSS", confidence="High")
            else:
                res.add("htmlSink-unsanitized", i, line,
                        "HTML sink without visible sanitization — check whether attacker data "
                        "can reach this assignment", confidence="Medium")

        # ── command execution ──────────────────────────────────────
        if CMD_SINK_RE.search(line):
            arg = re.search(r"\((.*)\)", line)
            argval = arg.group(1).strip() if arg else ""
            list_args = argval.startswith("[") and "shell" not in line
            fixed = (
                bool(STRING_LITERAL_RE.match(argval))
                or list_args
                or bool(re.match(r"""^["'][^"'${]+["']$""", argval))
            )
            if fixed:
                res.add("commandSink-fixed", i, line,
                        "command execution with a fixed string literal — not automatically "
                        "vulnerable; review only", confidence="High")
            elif CMD_SHELL_TRUE_RE.search(line):
                res.add("commandSink-shellTrue", i, line,
                        "subprocess with shell=True and dynamic argument — command-injection "
                        "candidate if input is external", confidence="High")
            else:
                res.add("commandSink-dynamic", i, line,
                        "command execution with non-literal argument — determine whether the "
                        "argument can contain external input", confidence="Medium")

        # ── network egress (SSRF reasoning) ────────────────────────
        if NET_CALL_RE.search(line):
            note = "outbound request — check whether the URL is external-input-controlled"
            conf = "Low"
            if URL_INPUT_RE.search(line) or any(
                    URL_INPUT_RE.search(lines[j]) for j in range(max(0, i - 5), i)):
                note += "; an input source appears near this call"
                conf = "Medium"
            if ALLOWLIST_RE.search(joined):
                note += "; an allowlist/validation symbol exists elsewhere in the file"
                conf = "Low"
            res.add("network-call", i, line, note, confidence=conf)

        # ── path construction ──────────────────────────────────────
        if PATH_OP_RE.search(line):
            if TRAVERSAL_RE.search(line):
                res.add("path-traversal-pattern", i, line,
                        "path construction contains traversal sequences", confidence="High")
            elif NORM_RE.search(joined):
                res.add("path-op", i, line,
                        "filesystem operation; normalization present elsewhere in file",
                        confidence="Low")
            else:
                res.add("path-op", i, line,
                        "filesystem operation — check the origin of the path components",
                        confidence="Medium")

        # ── deserialization ────────────────────────────────────────
        if DESER_RE.search(line):
            res.add("unsafe-deserialization", i, line,
                    "object deserialization API that can execute code if the input is "
                    "attacker-controlled", confidence="High")
        elif EVAL_RE.search(line) and not SAFE_PARSE_RE.search(line):
            res.add("dynamic-evaluation", i, line,
                    "eval/Function-style dynamic code execution — dangerous only if the "
                    "argument includes external input", confidence="Medium")

        # ── quality-only hints (never vulnerabilities on their own) ─
        if EVENT_ATTR_RE.search(line):
            res.add("inline-event-handler", i, line,
                    "inline event handler — code-quality/CSP-hardening concern unless it "
                    "processes untrusted data", confidence="High")
        if BROAD_CATCH_RE.search(line):
            res.add("broad-error-handling", i, line,
                    "broad/empty exception handler — code quality unless it hides failures "
                    "or leaks data in the message", confidence="High")
        if AUTH_MARKER_RE.search(line):
            res.add("auth-marker", i, line,
                    "authentication/authorization control present", confidence="Low")

    # ── file-level summary for the AI ─────────────────────────────
    res.summary = {
        "lines_scanned": len(lines),
        "language_hint": lang or "unspecified",
        "uses_prepared_statements_or_params": uses_prepared,
        "uses_orm": uses_orm,
        "any_html_sanitizer_visible": any_sanitizer,
        "has_auth_markers": bool(AUTH_MARKER_RE.search(joined)),
        "hint_counts": {},
    }
    for h in res.hints:
        res.summary["hint_counts"][h.type] = res.summary["hint_counts"].get(h.type, 0) + 1
    return res


def evidence_block(analysis: Analysis, max_hints: int = 80) -> str:
    """Render the analysis as a text block injected into the AI prompt."""
    if not analysis.hints and not analysis.summary:
        return "(no static evidence collected)"
    out = ["STATIC-ANALYSIS EVIDENCE (deterministic, line-referenced; use it, weigh it, "
           "and cite line numbers — but YOU decide the final classification under the rules):",
           f"- summary: {analysis.summary}"]
    for h in analysis.hints[:max_hints]:
        out.append(f"- [{h.type}] line {h.line} (confidence {h.confidence}): {h.snippet} — {h.note}")
    if len(analysis.hints) > max_hints:
        out.append(f"- … {len(analysis.hints) - max_hints} further hints truncated")
    return "\n".join(out)
