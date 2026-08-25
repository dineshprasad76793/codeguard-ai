from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
import httpx
from models.schema import (
    AnalyzeRequest,
    AnalyzeResponse,
    UrlScanRequest,
    GithubScanRequest,
)
from services.glm_service import (
    analyze_code,
    build_system_prompt,
    build_user_prompt,
    stream_glm,
)
from services.url_scanner import (
    analyze_url,
    validate_url,
    collect_observations,
    URL_SYSTEM_PROMPT,
    build_user_prompt as build_url_prompt,
)
from services.github_service import (
    analyze_github_repo,
    collect_repo_files,
    RepoNotFound,
)
from services.sanitizer import sanitize_custom_rules, RuleRejected
from rate_limit import limiter

router = APIRouter()

SUPPORTED_LANGUAGES = {
    "python", "javascript", "typescript", "java", "go", "php",
    "c", "c++", "c#", "rust", "ruby", "kotlin", "swift", "html", "css", "auto",
}

MAX_CODE_CHARS = 150_000

GENERIC_AI_ERROR = (
    "The analysis service is temporarily unavailable. Please try again shortly."
)


def _clean_rules(rules):
    try:
        return sanitize_custom_rules(rules)
    except RuleRejected as e:
        raise HTTPException(status_code=400, detail=str(e))


def _opts(req):
    """Typed options -> plain dict for the prompt builder."""
    if req.options is None:
        return {"owasp": False, "secrets": False, "deps": False}
    return req.options.model_dump()


@router.post("/api/analyze", response_model=AnalyzeResponse)
@limiter.limit("6/minute")
async def analyze(request: Request, req: AnalyzeRequest):
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

    options = _opts(req)
    custom_rules = _clean_rules(req.custom_rules)

    if req.stream:
        return StreamingResponse(
            stream_glm(
                build_system_prompt(options, custom_rules),
                build_user_prompt(language, req.code),
            ),
            media_type="text/plain; charset=utf-8",
        )

    try:
        analysis = await analyze_code(language, req.code, options, custom_rules)
        return AnalyzeResponse(success=True, analysis=analysis)
    except httpx.HTTPStatusError:
        raise HTTPException(status_code=502, detail=GENERIC_AI_ERROR)
    except httpx.HTTPError:
        raise HTTPException(status_code=504, detail=GENERIC_AI_ERROR)
    except Exception:
        raise HTTPException(status_code=500, detail=GENERIC_AI_ERROR)


@router.post("/api/scan-url", response_model=AnalyzeResponse)
@limiter.limit("8/minute")
async def scan_url(request: Request, req: UrlScanRequest):
    try:
        url = validate_url(req.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if req.stream:
        try:
            obs = await collect_observations(url)
        except httpx.HTTPError:
            raise HTTPException(
                status_code=502,
                detail="Could not reach the target URL. Check the address and try again.",
            )
        return StreamingResponse(
            stream_glm(URL_SYSTEM_PROMPT, build_url_prompt(obs)),
            media_type="text/plain; charset=utf-8",
        )

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
@limiter.limit("8/minute")
async def scan_github(request: Request, req: GithubScanRequest):
    options = _opts(req)
    try:
        custom_rules = _clean_rules(req.custom_rules)

        if req.stream:
            files = await collect_repo_files(req.url)
            combined = "\n\n".join(f"=== FILE: {p} ===\n{c}" for p, c in files)
            langs = sorted({p.rsplit(".", 1)[-1].lower() for p, _ in files})
            language = f"Multiple ({', '.join(langs)}) - GitHub repository"
            return StreamingResponse(
                stream_glm(
                    build_system_prompt(options, custom_rules),
                    build_user_prompt(language, combined),
                ),
                media_type="text/plain; charset=utf-8",
            )

        analysis = await analyze_github_repo(req.url, options, custom_rules)
        return AnalyzeResponse(success=True, analysis=analysis)
    except RuleRejected as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RepoNotFound as e:
        raise HTTPException(status_code=400, detail=str(e))
    except httpx.HTTPStatusError:
        raise HTTPException(status_code=502, detail=GENERIC_AI_ERROR)
    except httpx.HTTPError:
        raise HTTPException(status_code=504, detail=GENERIC_AI_ERROR)
    except Exception:
        raise HTTPException(status_code=500, detail=GENERIC_AI_ERROR)
