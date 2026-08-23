import os
import re
import secrets
import sqlite3
import time
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from models.schema import AnalyzeResponse

router = APIRouter()

# Share links are persisted in SQLite so they survive server sleep/wake
# cycles. (On ephemeral free-tier filesystems they reset on redeploy.)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shares.db")
MAX_SHARES = 200
MAX_ANALYSIS_CHARS = 60_000
TTL_SECONDS = int(os.getenv("SHARE_TTL_SECONDS", 86400))  # 24h default


class ShareCreate(BaseModel):
    analysis: str
    title: str = ""


class ShareCreated(BaseModel):
    token: str
    expires_in: int


def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS shares (
            token TEXT PRIMARY KEY,
            title TEXT NOT NULL DEFAULT '',
            analysis TEXT NOT NULL,
            created REAL NOT NULL
        )
        """
    )
    return conn


def _prune(conn):
    conn.execute("DELETE FROM shares WHERE created < ?", (time.time() - TTL_SECONDS,))
    count = conn.execute("SELECT COUNT(*) FROM shares").fetchone()[0]
    if count > MAX_SHARES:
        conn.execute(
            """
            DELETE FROM shares WHERE token IN (
                SELECT token FROM shares ORDER BY created ASC LIMIT ?
            )
            """,
            (count - MAX_SHARES,),
        )
    conn.commit()


@router.post("/api/share", response_model=ShareCreated)
async def create_share(body: ShareCreate):
    analysis = (body.analysis or "").strip()
    if not analysis:
        raise HTTPException(status_code=400, detail="Analysis cannot be empty.")
    analysis = analysis[:MAX_ANALYSIS_CHARS]
    title = (body.title or "").strip()[:200]

    token = secrets.token_urlsafe(24)
    with _db() as conn:
        _prune(conn)
        conn.execute(
            "INSERT INTO shares (token, title, analysis, created) VALUES (?, ?, ?, ?)",
            (token, title, analysis, time.time()),
        )
    return ShareCreated(token=token, expires_in=TTL_SECONDS)


@router.get("/api/share/{token}", response_model=AnalyzeResponse)
async def get_share(token: str):
    if not re.fullmatch(r"[A-Za-z0-9_\-]{10,64}", token):
        raise HTTPException(status_code=404, detail="Share link not found.")
    with _db() as conn:
        row = conn.execute(
            "SELECT analysis, created FROM shares WHERE token = ?", (token,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Share link not found or expired.")
    analysis, created = row
    if time.time() - created > TTL_SECONDS:
        with _db() as conn:
            conn.execute("DELETE FROM shares WHERE token = ?", (token,))
        raise HTTPException(status_code=410, detail="Share link has expired.")
    return AnalyzeResponse(success=True, analysis=analysis)
