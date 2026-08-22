# CodeGuard AI

**Copyright (c) 2026 Dinesh (dinesh.ai). All rights reserved.**

Unauthorized use, distribution, or modification of this software is strictly prohibited.

---

An AI-powered web application that analyzes source code and helps developers find bugs, errors, code-quality problems, and basic security issues. Built for students, developers, testers, and beginners.

## Features

### Code Analysis mode
- Paste code → click **Analyze Code** → get a clear AI report
- **Upload code files** (.py, .java, .c, .cpp, .js, .html, .css) — language is auto-detected from the file extension
- **Code Quality and Security scores** (0–10) shown as color-coded score cards (green / yellow / red)
- Detects syntax errors, logical bugs, code-quality issues, and common security weaknesses
- Every issue includes: title, severity, line number (when possible), explanation, impact, recommended fix, and corrected code

### URL Security Check mode
- Enter a URL → confirm authorization → click **Scan URL**
- Performs **one passive GET request** (like a normal browser visit) and an AI educational assessment
- Identifies missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy), cookie flag weaknesses, form/inline-script risks, and information disclosure
- Explains which attack classes relate to each finding (XSS, clickjacking, session hijacking, MIME sniffing, MITM) — educationally, with fixes
- **Estimated CVSS v3.1 scores** — every finding gets a base score (0.0–10.0) with a full vector string, shown as color-coded badges sorted highest-first (Critical ≥9 red · High ≥7 orange · Medium ≥4 yellow · Low >0 blue)
- **Never sends exploit payloads and never exploits anything** — findings are hypotheses requiring authorized verification
- Internal/localhost addresses are blocked; an authorization checkbox is required before scanning

### Both modes
- **Issue counter chips** — 🔴 Critical, 🟠 High, 🟡 Medium, 🔵 Low at a glance
- **Download Report** — saves a standalone styled HTML report (open it and press Ctrl+P to save as PDF)
- Severity-rated findings: Critical / High / Medium / Low / Informational
- Responsive dark-themed UI that works on desktop and mobile
- Never executes user code — analysis is text-only by design

### ⚠️ Legal & ethics
Only scan websites you own or have written permission to test (for example, a bug bounty program's defined scope). Unauthorized scanning is illegal in many countries.

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 18 |
| Backend | Python 3.12 + FastAPI |
| AI Model | GLM (via OpenRouter) |

## Project Structure

```
codeguard-ai/
├── frontend/                  # React app
│   ├── public/index.html
│   └── src/
│       ├── index.js           # Entry point
│       ├── App.js             # Main UI (code analysis + URL check modes)
│       └── App.css            # Styling (dark theme, responsive)
├── backend/
│   ├── main.py                # FastAPI server + CORS
│   ├── requirements.txt       # Python dependencies
│   ├── routes/analyze.py      # POST /api/analyze + POST /api/scan-url
│   ├── services/glm_service.py# Shared GLM AI client + code-analysis prompt
│   ├── services/url_scanner.py# Passive URL fetch + security-assessment prompt
│   └── models/schema.py       # Request/response models
├── .env.example               # Environment variable template
├── .gitignore
├── LICENSE
└── README.md
```

## Deployment (free hosting — works on mobile & desktop)

The app is a **single service**: the FastAPI backend also serves the built React frontend, so one free host runs everything and gives you a public URL usable from any phone, tablet, or computer. The UI is responsive and auto-adjusts to any screen size.

### Option A: Render (recommended, free)

1. Push this project to GitHub (see below)
2. Go to [render.com](https://render.com) → sign up free (you can log in with GitHub)
3. Dashboard → **New +** → **Web Service** → connect your `codeguard-ai` repository
4. Render reads `render.yaml` automatically — just add your secret:
   - Environment → Add Environment Variable → `GLM_API_KEY` = your OpenRouter key
5. Click **Create Web Service** and wait for the build (~3–5 minutes)
6. You get a public URL like `https://codeguard-ai.onrender.com` — open it on any device

> Note: Render's free tier sleeps after 15 minutes of inactivity; the first request after sleep takes ~30 seconds to wake up.

### Push to GitHub

```bash
cd codeguard-ai
gh auth login                 # choose GitHub.com → HTTPS → login with browser
gh repo create codeguard-ai --public --source=. --push
```

(Or create the repo manually on github.com and push with `git remote add origin ...` + `git push -u origin main`.)

The `.env` file with your API key is git-ignored and never leaves your computer — on Render you paste the key into their dashboard instead.

## Prerequisites

- Python 3.10+ — [python.org/downloads](https://www.python.org/downloads/)
- Node.js 18+ — [nodejs.org](https://nodejs.org)
- An OpenRouter API key — [openrouter.ai/keys](https://openrouter.ai/keys) (free signup)
  - Or a Zhipu AI key from [open.bigmodel.cn](https://open.bigmodel.cn) if you prefer direct access

## Setup

### 1. Backend

```bash
cd backend
pip install -r requirements.txt
```

Create your `.env` file (copy from `.env.example` and fill in your key):

```
GLM_API_KEY=your_key_here
GLM_API_URL=https://openrouter.ai/api/v1/chat/completions
GLM_MODEL=z-ai/glm-4.7-flash
```

Start the backend:

```bash
python main.py
```

The API runs at `http://localhost:8000`. Interactive docs: `http://localhost:8000/docs`

### 2. Frontend

```bash
cd frontend
npm install
npm start
```

The app opens at `http://localhost:3000`.

### `POST /api/scan-url`

Request:

```json
{
  "url": "https://example.com"
}
```

Response:

```json
{
  "success": true,
  "analysis": "SCORES\nSecurity: 4/10\n..."
}
```

Validates the URL (http/https only, internal addresses blocked) before scanning.

Errors return standard FastAPI error JSON with a `detail` message (e.g., empty code, unsupported language, invalid URL, AI service failure).

## Usage

### Code Analysis
1. Open `http://localhost:3000` (Code Analysis tab)
2. Select the language from the dropdown — or click **Upload File** and the language is detected automatically
3. Paste your code into the editor (or upload a file)
4. Click **Analyze Code**
5. Read the report — quality/security score cards and severity chips at the top, then each issue with explanation and fix
6. Click **Download Report** to save a styled HTML report (Ctrl+P in your browser turns it into a PDF)

### URL Security Check
1. Switch to the **URL Security Check** tab
2. Read the authorization warning
3. Enter the URL (e.g., `https://your-target.com`)
4. Tick the checkbox confirming you own or have permission to test the target
5. Click **Scan URL**
6. Read the assessment — security score, severity chips, and each finding with the attack class it relates to and how to fix it

## API Reference

### `POST /api/analyze`

Request:

```json
{
  "language": "python",
  "code": "your code here"
}
```

Response:

```json
{
  "success": true,
  "analysis": "SUMMARY\nTotal Issues: 2\n..."
}
```

Errors return standard FastAPI error JSON with a `detail` message (e.g., empty code, unsupported language, AI service failure).

## Configuration

All settings live in `backend/.env` — no API keys are ever stored in source code.

| Variable | Purpose | Default |
|---|---|---|
| `GLM_API_KEY` | Your AI provider API key | (required) |
| `GLM_API_URL` | AI endpoint | OpenRouter |
| `GLM_MODEL` | Model name | `z-ai/glm-4.7-flash` |
| `BACKEND_HOST` / `BACKEND_PORT` | Server bind address | `127.0.0.1:8000` |
| `CORS_ORIGINS` | Allowed frontend origins | `http://localhost:3000` |

**Switching AI providers** (OpenRouter ↔ Zhipu direct, or any OpenAI-compatible endpoint) requires only a `.env` change — no code edits.

## Safety & Disclaimer

- The application treats all pasted code as **text**. It never executes user code.
- The URL check performs **one passive GET request only** — no payloads, no exploitation, no active scanning. Internal/localhost addresses are blocked.
- This is an **AI-assisted analysis**. Findings are hypotheses and should be verified manually by a developer or security professional.
- The AI never claims code or a website is completely secure.

## Future Roadmap

- AI-generated unit tests
- Multiple AI model selection
- Analysis history

---

Developed by **Dinesh** — dinesh.ai
