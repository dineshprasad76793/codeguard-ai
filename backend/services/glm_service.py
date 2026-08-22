import os
import httpx
from dotenv import load_dotenv

load_dotenv()

GLM_API_KEY = os.getenv("GLM_API_KEY", "")
GLM_API_URL = os.getenv("GLM_API_URL", "https://open.bigmodel.cn/api/paas/v4/chat/completions")
GLM_MODEL = os.getenv("GLM_MODEL", "glm-4-flash")

SYSTEM_PROMPT = """You are an AI code review and security analysis assistant. Analyze the provided source code carefully. Identify syntax problems, logical bugs, code-quality issues, and clearly identifiable common security weaknesses. Do not invent vulnerabilities. If you are uncertain, clearly state that the issue requires manual verification. Explain every finding in simple language. Provide severity, location, explanation, impact, and recommended fix. Never claim that code is completely secure.

Use these severity levels:
- Critical: Issues that will cause crashes, data loss, or immediate security breaches
- High: Serious bugs or security weaknesses
- Medium: Code quality problems or moderate issues
- Low: Minor improvements or style issues
- Informational: Observations that are not problems

Scoring rules:
- Code Quality score (0-10): rate readability, maintainability, naming, and structure. 10 = clean, well-organized code.
- Security score (0-10): rate the absence of clearly identified weaknesses. The security score reflects only this analysis and must never imply the code is fully secure.

Return your analysis in this exact format:

SCORES
Code Quality: X/10
Security: X/10

SUMMARY
Total Issues: X
Critical: X | High: X | Medium: X | Low: X

ISSUES

1. Issue: [short title]
   Severity: [Critical/High/Medium/Low/Informational]
   Line: [line number if applicable, or N/A]

   Explanation:
   [simple explanation]

   Why it is a problem:
   [impact description]

   Recommendation:
   [how to fix]

   Code Fix:
   [corrected code if applicable, or N/A]

[repeat for each issue]

DISCLAIMER: This is an AI-assisted analysis. All findings should be verified manually by a security professional."""


def build_user_prompt(language: str, code: str) -> str:
    return "Programming Language: " + language + "\n\nSource Code:\n```\n" + code + "\n```"


async def call_glm(system_prompt: str, user_prompt: str) -> str:
    if not GLM_API_KEY:
        return (
            "ERROR: GLM_API_KEY is not set. \n\n"
            "Please add your API key to the .env file:\n"
            "  GLM_API_KEY=your_key_here"
        )

    headers = {
        "Authorization": f"Bearer {GLM_API_KEY}",
        "Content-Type": "application/json",
        # OpenRouter attribution headers (ignored by other providers)
        "HTTP-Referer": "http://localhost:3000",
        "X-Title": "CodeGuard AI",
    }

    payload = {
        "model": GLM_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.3,
        "max_tokens": 8192,
    }

    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(GLM_API_URL, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()
        message = data["choices"][0]["message"]
        # GLM reasoning models may put text in "reasoning" if content is cut short
        content = message.get("content") or message.get("reasoning") or ""
        content = content.strip()
        if not content:
            return "The AI returned an empty analysis. Please try again."
        return content


async def analyze_code(language: str, code: str) -> str:
    return await call_glm(SYSTEM_PROMPT, build_user_prompt(language, code))
