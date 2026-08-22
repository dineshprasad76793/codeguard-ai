import re
import httpx
from services.glm_service import call_glm

MAX_HTML_CHARS = 15000

URL_SYSTEM_PROMPT = """You are an educational web-security assessment assistant for security learners and bug bounty researchers. You receive observations from ONE passive GET request to a URL: final URL, status code, response headers, and a truncated HTML excerpt. Based ONLY on these observations, produce an educational security assessment.

Your job:
- Identify missing security headers (Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) and explain what each one protects against
- Assess cookie flags (HttpOnly, Secure, SameSite) from Set-Cookie headers and explain the risks
- Note form handling, inline scripts, external script sources, mixed content, and information disclosure visible in the HTML
- Explain which attack CLASSES are relevant to the observed characteristics (e.g., clickjacking, cross-site scripting, session hijacking, MIME-type sniffing) as educational explanations only

Strict rules:
- NEVER provide working exploit payloads or step-by-step exploitation instructions against the target
- NEVER confirm a vulnerability. Describe every finding as a hypothesis that requires authorized verification
- Explain defensively: what the weakness is, why it matters, and exactly how to fix it
- Remind the user that security testing must only be performed on systems they own or have written authorization to test

Severity levels:
- Critical / High / Medium / Low / Informational

CVSS scoring rule:
- For every issue, provide an estimated CVSS v3.1 base score (0.0-10.0) and a full vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
- These are educational estimates of potential impact IF the weakness is confirmed — not confirmed vulnerability scores
- Derive the Severity label from the CVSS band: 9.0-10.0 Critical, 7.0-8.9 High, 4.0-6.9 Medium, 0.1-3.9 Low, 0.0 Informational

Scoring rule:
- Security score (0-10): rate the observed header and content hygiene only. This score never implies the site is secure or fully tested.

Return your analysis in this exact format:

SCORES
Security: X/10

SUMMARY
Total Issues: X
Critical: X | High: X | Medium: X | Low: X

ISSUES

1. Issue: [short title]
   Severity: [Critical/High/Medium/Low/Informational]
   CVSS Estimate: X.X (CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...)
   Location: [header name / HTML section / N/A]

   Explanation:
   [simple educational explanation]

   Why it is a problem:
   [what attack class this relates to and why]

   Recommendation:
   [how to fix it]

   Fix Example:
   [config or code example, or N/A]

[repeat for each issue]

DISCLAIMER: This is an AI-assisted assessment based on a single passive request. It is not a penetration test. All findings must be verified manually, and only on systems you own or are authorized to test."""


def _is_private_host(hostname: str) -> bool:
    host = hostname.lower().strip()
    if host in ("localhost", "::1", "0.0.0.0"):
        return True
    if host.startswith(("127.", "10.", "192.168.", "169.254.")):
        return True
    m = re.match(r"^172\.(\d+)\.", host)
    if m and 16 <= int(m.group(1)) <= 31:
        return True
    return False


def validate_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^https?://[^\s]+$", url, re.IGNORECASE):
        raise ValueError("URL must start with http:// or https:// and contain no spaces.")
    host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    host = host.split("/")[0].split(":")[0]
    if _is_private_host(host):
        raise ValueError("Scanning internal or localhost addresses is not allowed.")
    return url


async def collect_observations(url: str) -> dict:
    headers = {
        "User-Agent": "CodeGuardAI/1.0 (Educational security analysis)"
    }
    async with httpx.AsyncClient(
        timeout=15.0, follow_redirects=True, max_redirects=3
    ) as client:
        response = await client.get(url, headers=headers)

    html = response.text[:MAX_HTML_CHARS]
    form_tags = re.findall(r"<form[^>]*>", html, re.IGNORECASE)
    external_scripts = re.findall(
        r"<script[^>]*src=[\"']([^\"']+)[\"']", html, re.IGNORECASE
    )
    total_scripts = html.lower().count("<script")
    inline_scripts = max(0, total_scripts - len(external_scripts))

    return {
        "final_url": str(response.url),
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "html_excerpt": html,
        "form_tags": form_tags,
        "external_scripts": external_scripts,
        "inline_scripts": inline_scripts,
    }


def build_user_prompt(obs: dict) -> str:
    header_lines = "\n".join(
        f"{k}: {v}" for k, v in obs["headers"].items()
    )
    forms = "\n".join(obs["form_tags"]) if obs["form_tags"] else "None found"
    scripts = (
        "\n".join(obs["external_scripts"])
        if obs["external_scripts"]
        else "None found"
    )

    return (
        "Passive GET observations for the target URL:\n\n"
        f"Final URL after redirects: {obs['final_url']}\n"
        f"Status code: {obs['status_code']}\n\n"
        "Response headers:\n"
        f"{header_lines}\n\n"
        f"Forms found in HTML ({len(obs['form_tags'])}):\n{forms}\n\n"
        f"External scripts ({len(obs['external_scripts'])}):\n{scripts}\n\n"
        f"Inline scripts (approximate): {obs['inline_scripts']}\n\n"
        f"Truncated HTML excerpt ({len(obs['html_excerpt'])} chars):\n"
        f"{obs['html_excerpt']}"
    )


async def analyze_url(url: str) -> str:
    obs = await collect_observations(url)
    return await call_glm(URL_SYSTEM_PROMPT, build_user_prompt(obs))
