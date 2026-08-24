"""Expiring share links for analysis reports.

Tokens are HMAC-signed with a server secret (SHARE_SECRET) so tampering
is detected before any database lookup, and they remain stored in SQLite
so they survive server sleep/wake cycles and can be revoked/expired.
"""
import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from models.schema import AnalyzeResponse

router = APIRouter()

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shares.db")
MAX_SHARES = 200
MAX_ANALYSIS_CHARS = 60_000
TTL_SECONDS = int(os.getenv("SHARE_TTL_SECONDS", 86400))  # 24h default

# Falls back to a per-process random secret if SHARE_SECRET is unset.
# NOTE: with the fallback, tokens stop validating after a restart —
# set SHARE_SECRET in production for stable signatures.
SHARE_SECRET = os.getenv("SHARE_SECRET", "") or secrets.token_hex(32)


class ShareCreate(BaseModel):
    analysis: str
    title: str = ""


class ShareCreated(BaseModel):
    token: str
    expires_in: int


def _sign(nonce: str, created: int) -> str:
    msg = f"{nonce}.{created}".encode()
    mac = hmac.new(SHARE_SECRET.encode(), msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode()


def _make_token() -> str:
    nonce = secrets.token_urlsafe(18)
    created = int(time.time())
    return f"{nonce}.{created}.{_sign(nonce, created)}"


def _verify_token(token: str):
    """Return (nonce, created) if the signature is valid, else None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    nonce, created_str, sig = parts
    if not re.fullmatch(r"[A-Za-z0-9_\-]{10,64}", nonce):
        return None
    if not re.fullmatch(r"\d{9,12}", created_str):
        return None
    if not re.fullmatch(r"[A-Za-z0-9_\-]{20,64}", sig):
        return None
    expected = _sign(nonce, int(created_str))
    if not hmac.compare_digest(sig, expected):
        return None
    return nonce, int(created_str)


def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS shares (
            nonce TEXT PRIMARY KEY,
            title TEXT NOT NULL DEFAULT '',
            analysis TEXT NOT NULL,
            created REAL NOT NULL
        )
        """
    )
    # Migrate away from the pre-HMAC schema (token-keyed table): old links
    # cannot be valid under the new signing scheme, so recreate cleanly.
    cols = {row[1] for row in conn.execute("PRAGMA table_info(shares)")}
    if cols and "nonce" not in cols:
        conn.execute("DROP TABLE shares")
        conn.execute(
            """
            CREATE TABLE shares (
                nonce TEXT PRIMARY KEY,
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
            DELETE FROM shares WHERE nonce IN (
                SELECT nonce FROM shares ORDER BY created ASC LIMIT ?
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

    token = _make_token()
    nonce, created = _verify_token(token)
    with _db() as conn:
        _prune(conn)
        conn.execute(
            "INSERT INTO shares (nonce, title, analysis, created) VALUES (?, ?, ?, ?)",
            (nonce, title, analysis, float(created)),
        )
    return ShareCreated(token=token, expires_in=TTL_SECONDS)


@router.get("/api/share/{token}", response_model=AnalyzeResponse)
async def get_share(token: str):
    verified = _verify_token(token)
    if not verified:
        # Tampered or malformed: indistinguishable from "not found".
        raise HTTPException(status_code=404, detail="Share link not found or expired.")
    nonce, _ = verified
    with _db() as conn:
        row = conn.execute(
            "SELECT analysis, created FROM shares WHERE nonce = ?", (nonce,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Share link not found or expired.")
    analysis, created = row
    if time.time() - created > TTL_SECONDS:
        with _db() as conn:
            conn.execute("DELETE FROM shares WHERE nonce = ?", (nonce,))
        raise HTTPException(status_code=410, detail="Share link has expired.")
    return AnalyzeResponse(success=True, analysis=analysis)
