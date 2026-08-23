import os
import re
import secrets
import time
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from models.schema import AnalyzeResponse

router = APIRouter()

# In-memory share store. Entries expire after the TTL and the store is
# capped. Note: on free hosting tiers the process may restart (sleep),
# which clears shared links — acceptable for a v2 MVP; move to Redis or
# a database if persistence is required.
_SHARES: dict = {}
MAX_SHARES = 200
MAX_ANALYSIS_CHARS = 60_000
TTL_SECONDS = int(os.getenv("SHARE_TTL_SECONDS", 86400))  # 24h default


class ShareCreate(BaseModel):
    analysis: str
    title: str = ""


class ShareCreated(BaseModel):
    token: str
    expires_in: int


def _prune(now: float):
    expired = [t for t, v in _SHARES.items() if now - v["created"] > TTL_SECONDS]
    for t in expired:
        _SHARES.pop(t, None)
    while len(_SHARES) >= MAX_SHARES:
        oldest = min(_SHARES, key=lambda t: _SHARES[t]["created"])
        _SHARES.pop(oldest, None)


@router.post("/api/share", response_model=ShareCreated)
async def create_share(body: ShareCreate):
    analysis = (body.analysis or "").strip()
    if not analysis:
        raise HTTPException(status_code=400, detail="Analysis cannot be empty.")
    if len(analysis) > MAX_ANALYSIS_CHARS:
        analysis = analysis[:MAX_ANALYSIS_CHARS]
    title = (body.title or "").strip()[:200]

    _prune(time.time())
    token = secrets.token_urlsafe(24)
    _SHARES[token] = {"analysis": analysis, "title": title, "created": time.time()}
    return ShareCreated(token=token, expires_in=TTL_SECONDS)


@router.get("/api/share/{token}", response_model=AnalyzeResponse)
async def get_share(token: str):
    if not re.fullmatch(r"[A-Za-z0-9_\-]{10,64}", token):
        raise HTTPException(status_code=404, detail="Share link not found.")
    entry = _SHARES.get(token)
    if not entry:
        raise HTTPException(status_code=404, detail="Share link not found or expired.")
    if time.time() - entry["created"] > TTL_SECONDS:
        _SHARES.pop(token, None)
        raise HTTPException(status_code=410, detail="Share link has expired.")
    return AnalyzeResponse(success=True, analysis=entry["analysis"])
