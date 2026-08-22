from fastapi import APIRouter, HTTPException
from models.schema import AnalyzeRequest, AnalyzeResponse, UrlScanRequest
from services.glm_service import analyze_code
from services.url_scanner import analyze_url, validate_url

router = APIRouter()


@router.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    if not req.code.strip():
        raise HTTPException(status_code=400, detail="Code cannot be empty.")

    supported = ["python", "java", "c", "c++", "javascript", "html", "css"]
    if req.language.lower() not in supported:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported language: {req.language}. Supported: {', '.join(supported)}"
        )

    try:
        analysis = await analyze_code(req.language, req.code)
        return AnalyzeResponse(success=True, analysis=analysis)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/scan-url", response_model=AnalyzeResponse)
async def scan_url(req: UrlScanRequest):
    try:
        url = validate_url(req.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        analysis = await analyze_url(url)
        return AnalyzeResponse(success=True, analysis=analysis)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Could not scan the URL: {e}",
        )
