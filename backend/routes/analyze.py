import re
from fastapi import APIRouter, HTTPException
import httpx
from models.schema import (
    AnalyzeRequest,
    AnalyzeResponse,
    UrlScanRequest,
    GithubScanRequest,
)
from services.glm_service import analyze_code
from services.url_scanner import analyze_url, validate_url
from services.github_service import analyze_github_repo, RepoNotFound

router = APIRouter()

SUPPORTED_LANGUAGES = {
    "python", "javascript", "typescript", "java", "go", "php",
    "c", "c++", "c#", "rust", "ruby", "kotlin", "swift", "html", "css", "auto",
}

MAX_CODE_CHARS = 150_000

GENERIC_AI_ERROR = (
    "The analysis service is temporarily unavailable. Please try again shortly."
)


def _safe_custom_rules(rules):
    if not isinstance(rules, list):
        return []
    clean = []
    for r in rules:
        if isinstance(r, str) and r.strip():
            clean.append(r.strip()[:200])
        if len(clean) >= 20:
            break
    return clean


@router.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    if not req.code or not req.code.strip():
        raise HTTPException(status_code=400, detail="Code cannot be empty.")
    if len(req.code) > MAX_CODE_CHARS:
        raise HTTPException(
            status_code=413,
            detail=f"Code is too large. Maximum {MAX_CODE_CHARS} characters.",
        )
    language = (req.language or "auto").strip().lower()
    if language not in SUPPORTED_LANGUAGES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported language: {req.language}",
        )

    options = {
        "owasp": bool(req.options.get("owasp")) if req.options else False,
        "secrets": bool(req.options.get("secrets")) if req.options else False,
        "deps": bool(req.options.get("deps")) if req.options else False,
    }
    custom_rules = _safe_custom_rules(req.custom_rules or [])

    try:
        analysis = await analyze_code(language, req.code, options, custom_rules)
        return AnalyzeResponse(success=True, analysis=analysis)
    except httpx.HTTPStatusError:
        # Never leak upstream URLs/status details to the client.
        raise HTTPException(status_code=502, detail=GENERIC_AI_ERROR)
    except httpx.HTTPError:
        raise HTTPException(status_code=504, detail=GENERIC_AI_ERROR)
    except Exception:
        raise HTTPException(status_code=500, detail=GENERIC_AI_ERROR)


@router.post("/api/scan-url", response_model=AnalyzeResponse)
async def scan_url(req: UrlScanRequest):
    try:
        url = validate_url(req.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        analysis = await analyze_url(url)
        return AnalyzeResponse(success=True, analysis=analysis)
    except httpx.HTTPStatusError:
        raise HTTPException(status_code=502, detail=GENERIC_AI_ERROR)
    except httpx.HTTPError:
        raise HTTPException(
            status_code=502,
            detail="Could not reach the target URL. Check the address and try again.",
        )
    except Exception:
        raise HTTPException(status_code=500, detail=GENERIC_AI_ERROR)


@router.post("/api/scan-github", response_model=AnalyzeResponse)
async def scan_github(req: GithubScanRequest):
    try:
        options = {
            "owasp": bool(req.options.get("owasp")) if req.options else False,
            "secrets": bool(req.options.get("secrets")) if req.options else False,
            "deps": bool(req.options.get("deps")) if req.options else False,
        }
        analysis = await analyze_github_repo(
            req.url, options, _safe_custom_rules(req.custom_rules or [])
        )
        return AnalyzeResponse(success=True, analysis=analysis)
    except RepoNotFound as e:
        raise HTTPException(status_code=400, detail=str(e))
    except httpx.HTTPStatusError:
        raise HTTPException(status_code=502, detail=GENERIC_AI_ERROR)
    except httpx.HTTPError:
        raise HTTPException(status_code=504, detail=GENERIC_AI_ERROR)
    except Exception:
        raise HTTPException(status_code=500, detail=GENERIC_AI_ERROR)
