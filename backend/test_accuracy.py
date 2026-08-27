"""Accuracy regression tests for the CodeGuard AI detection engine.

Two layers:
1. static_analyzer unit tests — deterministic evidence rules (placeholder
   secrets filtered, sanitizers detected, prepared statements recognized…)
2. prompt-contract tests — the AI prompt actually contains the accuracy
   discipline it is supposed to enforce.

Run from the backend directory:
    python -m pytest test_accuracy.py -v
"""
import pytest

from services.static_analyzer import (
    analyze_code,
    evidence_block,
    mask_secret,
)
from services.glm_service import CODE_SYSTEM_PROMPT, build_user_prompt
from services.url_scanner import URL_SYSTEM_PROMPT


def hints_for(code, language=""):
    return {h.type for h in analyze_code(code, language).hints}


# ── Safe patterns must NOT produce dangerous-evidence hints ────────

SAFE_SAMPLES = {
    "escaped-innerHTML": """
function render(name) {
    el.innerHTML = escapeHtml(name);
}
""",
    "dompurify": """
app.get('/x', (req, res) => {
    el.innerHTML = DOMPurify.sanitize(req.query.x);
});
""",
    "prepared-statement": """
cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
""",
    "orm-query": """
user = User.query.filter_by(id=user_id).first()
""",
    "fixed-exec": """
import subprocess
subprocess.run(["systemctl", "restart", "nginx"])
""",
    "placeholder-secret": """
API_KEY = "YOUR_API_KEY"
PASSWORD = "example"
TOKEN = "test-token"
SECRET = ""
""",
    "safe-json-parse": """
data = JSON.parse(responseText);
cfg = yaml.safe_load(stream);
""",
    "placeholder-js-secret": """
const apiKey = "YOUR_API_KEY_HERE";
const password = 'dummy';
""",
}


@pytest.mark.parametrize("name", list(SAFE_SAMPLES))
def test_safe_samples_no_dangerous_hints(name):
    h = hints_for(SAFE_SAMPLES[name])
    if name in ("escaped-innerHTML", "dompurify"):
        assert "htmlSink-unsanitized" not in h
        assert "htmlSink-sanitized" in h
    if name in ("prepared-statement", "orm-query"):
        assert "sql-dynamic-construction" not in h
        assert "sql-execute-no-params" not in h
    if name == "fixed-exec":
        assert "commandSink-shellTrue" not in h
        assert "commandSink-dynamic" not in h
    if name.startswith("placeholder"):
        assert "possible-secret" not in h
    if name == "safe-json-parse":
        assert "unsafe-deserialization" not in h


# ── Vulnerable patterns MUST produce the right evidence ────────────

def test_sql_concat_detected():
    code = 'q = "SELECT * FROM users WHERE name = \'" + username + "\'"\ncur.execute(q)'
    h = hints_for(code, "python")
    assert "sql-dynamic-construction" in h


def test_fstring_sql_detected():
    code = 'cur.execute(f"SELECT * FROM t WHERE x = {x}")'
    assert "sql-dynamic-construction" in hints_for(code, "python")


def test_select_word_alone_not_sql_concat():
    # mere presence of SELECT with parameter markers must not be concat
    code = 'cur.execute("SELECT * FROM users WHERE id = %s", (uid,))'
    h = hints_for(code, "python")
    assert "sql-dynamic-construction" not in h


def test_unsanitized_innerhtml_flagged():
    code = "el.innerHTML = userInput;"
    assert "htmlSink-unsanitized" in hints_for(code, "javascript")


def test_shell_true_dynamic_flagged():
    code = 'subprocess.run("ls " + path, shell=True)'
    h = hints_for(code, "python")
    assert "commandSink-shellTrue" in h


def test_real_secret_detected_and_masked():
    code = 'AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY12"'
    h = hints_for(code, "python")
    assert "possible-secret" in h
    # the emitted snippet must never contain the full secret
    analysis = analyze_code(code, "python")
    for hint in analysis.hints:
        assert "wJalrXUtnFEMI" not in hint.snippet


def test_placeholder_password_not_secret():
    code = 'password = "example"'
    assert "possible-secret" not in hints_for(code, "python")


def test_mask_secret_shape():
    full = "wJalrXUtnFEMI"
    m = mask_secret(full)
    assert m == "wJa" + "*" * (len(full) - 5) + "MI"
    assert mask_secret("abc") == "***"
    long_secret = "AKIAIOSFODNN7EXAMPLE"
    m2 = mask_secret(long_secret)
    assert long_secret not in m2 and m2.startswith("AKI")


def test_pickle_deserialization_flagged():
    code = "obj = pickle.loads(request.data)"
    assert "unsafe-deserialization" in hints_for(code, "python")


def test_yaml_unsafe_load_flagged():
    code = "cfg = yaml.load(data)"
    assert "unsafe-deserialization" in hints_for(code, "python")


def test_eval_flagged_as_dynamic_evaluation():
    code = "result = eval(user_expr)"
    assert "dynamic-evaluation" in hints_for(code, "python")


def test_ssrf_input_url_medium_confidence():
    code = "fetch(request.query.url).then(r => r.json())"
    analysis = analyze_code(code, "javascript")
    nets = [h for h in analysis.hints if h.type == "network-call"]
    assert nets and nets[0].confidence == "Medium"


def test_ssrf_allowlist_lowers_confidence():
    code = """
const ALLOWED_HOSTS = ['api.example.com'];
function is_valid_url(u){ const h = new URL(u).hostname; return ALLOWED_HOSTS.includes(h); }
fetch(target).then(r => r.json())
"""
    analysis = analyze_code(code, "javascript")
    nets = [h for h in analysis.hints if h.type == "network-call"]
    assert nets and nets[0].confidence == "Low"
    assert "allowlist" in nets[0].note


def test_path_traversal_detected():
    code = 'fp = open("/data/" + req.query.name)'
    h = hints_for(code, "python")
    assert "path-op" in h  # traversal seq not literally present, but path op noted


def test_traversal_sequence_detected():
    code = 'content = fs.readFileSync(base + "../../../etc/passwd")'
    assert "path-traversal-pattern" in hints_for(code, "javascript")


def test_inline_onclick_is_quality_only():
    code = '<button onclick="doThing()">Go</button>'
    h = hints_for(code, "html")
    assert "inline-event-handler" in h
    # and nothing dangerous leaked in
    assert not h & {"htmlSink-unsanitized", "commandSink-dynamic"}


def test_broad_catch_is_quality_only():
    code = "try { work(); } catch (e) {}"
    h = hints_for(code, "javascript")
    assert "broad-error-handling" in h


def test_evidence_block_contains_summary_and_lines():
    code = 'el.innerHTML = user;\nos.system("ping " + host)'
    block = evidence_block(analyze_code(code, "javascript"))
    assert "STATIC-ANALYSIS EVIDENCE" in block
    assert "uses_prepared_statements_or_params" in block
    assert "line 1" in block and "line 2" in block


def test_evidence_block_masks_secrets():
    code = 'token = "wJalrXUtnFEMIsecretsecret1234"'
    block = evidence_block(analyze_code(code, "python"))
    assert "wJalrXUtnFEMIsecretsecret1234" not in block
    assert "wJa" in block  # masked form retained for evidence


# ── Prompt-contract tests (the discipline must be IN the prompt) ───

def test_code_prompt_has_categories_and_confidence():
    for needle in (
        "Confirmed Vulnerability",
        "Potential Vulnerability",
        "Security Hardening",
        "Code Quality",
        "Informational",
        "Confidence:",
        "Data Flow:",
        "Manual Verification Required",
        "Why this is not necessarily a vulnerability",
    ):
        assert needle in CODE_SYSTEM_PROMPT, f"missing in prompt: {needle}"


def test_code_prompt_has_false_positive_rules():
    for needle in (
        "NEVER automatic XSS",
        "NEVER flag code merely because it contains the word SELECT",
        "exec/system usage alone is NOT a finding",
        "X-Frame-Options is an HTTP RESPONSE header",
        "frame-ancestors belongs in a Content-Security-Policy",
        "NEVER invent CVEs",
        "NEVER print a full secret",
    ):
        assert needle in CODE_SYSTEM_PROMPT, f"missing rule in prompt: {needle}"


def test_url_prompt_header_semantics():
    for needle in (
        "X-Frame-Options is an HTTP RESPONSE header",
        "CANNOT be set via an HTML <meta> tag",
        "not fully equivalent",
        "Security Hardening",
    ):
        assert needle in URL_SYSTEM_PROMPT, f"missing rule in URL prompt: {needle}"


def test_user_prompt_masks_real_secrets_end_to_end():
    from services.glm_service import build_user_prompt as bup
    secret = "sk-live-9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"
    up = bup("python", f'ADMIN_TOKEN = "{secret}"\nx = 1')
    assert secret not in up, "full secret reached the AI prompt"
    assert "sk-" in up and "4c" in up  # masked form retained
    assert "<user_code>" in up


def test_user_prompt_masks_real_secrets_end_to_end():
    from services.glm_service import build_user_prompt as bup
    secret = "sk-live-9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c"
    up = bup("python", f'ADMIN_TOKEN = "{secret}"\nx = 1')
    assert secret not in up, "full secret reached the AI prompt"
    assert "sk-" in up and "4c" in up  # masked form retained


# ── v2.5 detector additions ────────────────────────────────────────

def test_console_log_variable_not_hardcoded_secret():
    code = 'console.log("API token:", apiKey)'
    h = hints_for(code, "javascript")
    assert "possible-secret" not in h


def test_log_statement_with_literal_is_logging_concern():
    code = 'logger.info("token=" + "9f8e7d6c5b4a3f2e1d0c9b8a")'
    h = hints_for(code, "python")
    assert "possible-secret" not in h
    assert "secret-in-log-statement" in h


def test_weak_hash_password_context():
    code = 'pwd_hash = md5(password)'
    h = hints_for(code, "python")
    wh = [x for x in analyze_code(code, "python").hints if x.type == "weak-hash"]
    assert "weak-hash" in h and wh[0].confidence == "High"


def test_weak_hash_non_security_context_low():
    code = 'etag = md5(content)'
    wh = [x for x in analyze_code(code, "python").hints if x.type == "weak-hash"]
    assert wh and wh[0].confidence == "Medium"


def test_math_random_with_token_context_flagged():
    code = "const resetToken = Math.random().toString(36)"
    h = hints_for(code, "javascript")
    assert "weak-randomness-security-use" in h
    assert "weak-randomness-general" not in h


def test_math_random_general_not_security():
    code = "const dice = Math.floor(Math.random() * 6) + 1"
    h = hints_for(code, "javascript")
    assert "weak-randomness-security-use" not in h


def test_cors_wildcard_with_credentials():
    code = """
app.use(cors({ origin: '*', credentials: true }));
"""
    assert "cors-wildcard-with-credentials" in hints_for(code, "javascript")


def test_cors_wildcard_alone_is_hardening():
    code = 'res.set("Access-Control-Allow-Origin", "*")'
    h = hints_for(code, "javascript")
    assert "cors-wildcard" in h
    assert "cors-wildcard-with-credentials" not in h


# ── prompt-contract additions (v2.5) ───────────────────────────────

def test_prompt_cvss_and_no_findings_wording():
    for needle in (
        "Not enough information",
        "No high-confidence vulnerabilities were detected by this static analysis",
        "False Positive Analysis:",
        "DEDUPLICATION",
        "never merely a variable name containing password",
    ):
        assert needle in CODE_SYSTEM_PROMPT, f"missing rule: {needle}"


def test_user_prompt_includes_evidence():
    up = build_user_prompt("python", "x = pickle.loads(data)")
    assert "STATIC-ANALYSIS EVIDENCE" in up
    assert "unsafe-deserialization" in up
    assert "<user_code>" in up
