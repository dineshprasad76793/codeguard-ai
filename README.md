# CodeGuard AI v2

**Copyright (c) 2026 Dinesh (dinesh.ai). All rights reserved.**

Unauthorized use, distribution, or modification of this software is strictly prohibited.

---

An AI-powered security workbench: analyze code, assess websites, and scan public GitHub repositories for vulnerabilities, bugs, and code-quality issues — with CVSS scoring, OWASP mapping, and exportable reports.

## What's new in v2

- **12 languages + auto-detect**: Python, JavaScript, TypeScript, Java, Go, PHP, C, C++, C#, Rust, Ruby, Kotlin, Swift (+ HTML/CSS). The language is detected automatically from pasted code or file extensions.
- **Structured findings**: every finding has severity, estimated CVSS v3.1 score + vector, line number, and OWASP Top 10 mapping. Filter by severity, jump straight to the code line, mark false positives.
- **Exports & sharing**: PDF (print), Markdown, JSON, copy-to-clipboard, temporary shareable links (24h expiry), and shields.io badge generator.
- **GitHub repo scanning**: paste any public repo URL — up to 8 code files are fetched and analyzed together.
- **Advanced options**: OWASP Top 10 mapping, secrets detection (API keys, passwords, tokens — local regex + AI), dependency vulnerability check.
- **Custom security rules**: add your own regex patterns; matches appear as findings instantly (client-side, no AI needed).
- **History**: last 15 scans saved locally, reopen any time.
- **Editor**: syntax highlighting, line numbers, multi-file upload.
- **Dark/light theme** (dark default), fully responsive for phones and desktops.
- **CI/CD-friendly API** with optional token authentication.

## Security hardening (v2)

- Security headers on every response: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Per-IP rate limiting: 10 AI requests/minute (protects the API budget), 60/min for other endpoints
- SSRF protection in URL scanning: DNS resolution checks (blocks DNS-rebinding bypasses), redirect-safe fetching, metadata IP blocking, NAT64-aware validation
- Request size caps (1 MB body, 150k chars of code) — DoS protection
- Prompt-injection hardening: user code is framed as untrusted data that must never alter AI instructions
- Generic error messages (no internal/upstream detail leakage)
- Optional API token auth (`CG_API_TOKEN`) for all sensitive endpoints
- No source maps in production builds
- CORS disabled by default (same-origin only)

## Tech stack

| Layer | Technology |
|---|---|
| Frontend | React 18 |
| Backend | Python 3.12 + FastAPI |
| AI | GLM via OpenRouter |

## Local development

```bash
# Backend
cd backend
pip install -r requirements.txt
copy ..\env.example .env   # then edit .env
python main.py             # http://localhost:8000

# Frontend (dev server with proxy to :8000)
cd frontend
npm install
npm start                  # http://localhost:3000
```

The backend also serves the production frontend build at `http://localhost:8000`.

## API reference

All endpoints accept/return JSON. Optional auth: set `CG_API_TOKEN`, then send `X-API-Token: <value>`.

| Endpoint | Purpose |
|---|---|
| `POST /api/analyze` | `{language, code, options?, custom_rules?}` → AI code analysis |
| `POST /api/scan-url` | `{url}` → passive website security assessment |
| `POST /api/scan-github` | `{url, options?}` → public GitHub repo scan |
| `POST /api/share` | `{analysis, title?}` → temporary share token |
| `GET /api/share/{token}` | Fetch a shared report |
| `GET /api/health` | Health check |

### CI/CD example

```bash
curl -s -X POST https://your-app.onrender.com/api/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-Token: $CG_API_TOKEN" \
  -d '{"language":"python","code":"...","options":{"secrets":true}}' \
  | jq -e '.analysis | contains("Critical") | not' || exit 1
```

## Deployment

The service is a single unit (FastAPI serves the built frontend). `render.yaml` is included:

1. Push to GitHub
2. [render.com](https://render.com) → New Web Service → connect the repo
3. Set `GLM_API_KEY` (and optionally `CG_API_TOKEN`) in the dashboard
4. Deploy — everything else is pre-configured

## Safety & legal

- URL scanning performs **one passive GET request** and an educational assessment — no payloads, no exploitation
- Only test systems you own or are authorized to test (e.g., a bug bounty program's scope)
- The AI never executes your code; analysis is text-only
- All findings are hypotheses requiring manual verification

---

Developed by **Dinesh** — dinesh.ai
