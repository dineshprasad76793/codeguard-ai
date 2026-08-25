"""Security middleware and helpers for CodeGuard AI.

- MANDATORY API-token auth (CG_API_TOKEN): every /api call except
  /api/health and share-link reads requires the X-API-Key header,
  verified with secrets.compare_digest (constant-time). Fail-closed:
  the application refuses to start without a token unless
  REQUIRE_API_AUTH=false (local development only).
- Security headers applied to EVERY response, including 401/429/413
  errors produced by middleware (this middleware must be the OUTERMOST
  app middleware; see main.py ordering).
- Request body size caps.
- /docs, /redoc, /openapi.json blocked in production (DOCS_ENABLED=true
  to re-enable locally).
"""
import logging
import os
import secrets
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger("codeguard.security")

MAX_BODY_BYTES = 1_000_000  # 1 MB
DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")

# Auth is enforced unless explicitly disabled for local development.
AUTH_REQUIRED = os.getenv("REQUIRE_API_AUTH", "true").strip().lower() != "false"

# Comma-separated list so keys can be rotated without downtime.
API_TOKENS = [t.strip() for t in os.getenv("CG_API_TOKEN", "").split(",") if t.strip()]

# Timing-normalization sentinel used when no token is configured.
_NO_TOKEN_DUMMY = secrets.token_hex(32)

MIN_TOKEN_LEN = 16
RECOMMENDED_TOKEN_LEN = 32


def validate_security_env():
    """Fail closed at startup: never serve an unprotected API by accident."""
    if not AUTH_REQUIRED:
        logger.warning("REQUIRE_API_AUTH=false: API authentication is DISABLED. "
                       "Never use this in production.")
        return
    if not API_TOKENS:
        raise RuntimeError(
            "CG_API_TOKEN is not set. The API refuses to start without an API key. "
            "Generate one with:  python -c \"import secrets; print(secrets.token_hex(32))\"  "
            "and set it in the environment. For local development only, set "
            "REQUIRE_API_AUTH=false."
        )
    for token in API_TOKENS:
        if len(token) < MIN_TOKEN_LEN:
            raise RuntimeError(
                f"CG_API_TOKEN must be at least {MIN_TOKEN_LEN} characters "
                "(32+ recommended). Refusing to start with a weak key."
            )
        if len(token) < RECOMMENDED_TOKEN_LEN:
            logger.warning("CG_API_TOKEN is shorter than %d characters; "
                           "32+ recommended.", RECOMMENDED_TOKEN_LEN)


def token_is_valid(provided: str) -> bool:
    """Constant-time check of a provided key against all configured keys.

    Always performs at least one comparison so that rejection timing does
    not reveal whether any token is configured.
    """
    tokens = API_TOKENS or [_NO_TOKEN_DUMMY]
    matched = False
    for token in tokens:
        if secrets.compare_digest(provided.encode("utf-8"), token.encode("utf-8")):
            matched = True
    return bool(API_TOKENS) and matched


def client_ip(request: Request) -> str:
    """Best-effort real client IP behind Cloudflare + Render.

    CF-Connecting-IP is set (and overwritten) by Cloudflare, so it cannot
    be spoofed by clients when traffic traverses Cloudflare. Without it,
    the RIGHTMOST X-Forwarded-For entry is used: it is appended by the
    nearest trusted proxy. Leftmost entries are client-controlled and
    must never be trusted (classic rate-limit bypass).
    """
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip.strip()
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


class ApiTokenMiddleware(BaseHTTPMiddleware):
    """Mandatory token auth on /api/* (fail closed when REQUIRE_API_AUTH).

    Accepts X-API-Key (preferred) or X-API-Token (legacy alias), verified
    in constant time against every configured key.

    Public: /api/health (uptime probes) and GET /api/share/{token}
    (share recipients authenticate via the HMAC-signed token itself,
    which is a 144-bit random nonce — infeasible to guess).
    """

    PUBLIC_PATHS = ("/api/health",)

    def _provided_token(self, request):
        return request.headers.get("x-api-key") or request.headers.get("x-api-token") or ""

    async def dispatch(self, request, call_next):
        if not AUTH_REQUIRED:
            return await call_next(request)

        path = request.url.path
        share_read = path.startswith("/api/share/") and request.method == "GET"
        is_api = path == "/api" or path.startswith("/api/")
        needs_auth = (
            is_api
            and not share_read
            and not any(path.startswith(p) for p in self.PUBLIC_PATHS)
        )
        if needs_auth and not token_is_valid(self._provided_token(request)):
            return JSONResponse(
                {"detail": "Invalid or missing API key (X-API-Key header)."},
                status_code=401,
                headers={"WWW-Authenticate": "ApiKey"},
            )
        return await call_next(request)


class DocsProtectionMiddleware(BaseHTTPMiddleware):
    """Hide interactive API documentation in production.

    Set DOCS_ENABLED=true in the environment to expose /docs during
    development. A valid API token also unlocks it.
    """

    async def dispatch(self, request, call_next):
        path = request.url.path.rstrip("/")
        if path in DOCS_PATHS and os.getenv("DOCS_ENABLED", "").lower() != "true":
            provided = request.headers.get("x-api-key", "") or request.headers.get(
                "x-api-token", ""
            )
            if not token_is_valid(provided):
                return JSONResponse({"detail": "Not found."}, status_code=404)
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Security headers on every response, including errors from inner
    middleware. Must be registered as the outermost app middleware
    (the first `add_middleware` call in main.py runs innermost; the
    CORS middleware sits above it)."""

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'"
        )
        if request.url.path.startswith("/api"):
            # API responses (AI analyses, share reads) must never be cached
            # by shared/CDN caches.
            response.headers.setdefault("Cache-Control", "no-store")
        # Origin servers must not advertise their implementation.
        try:
            del response.headers["Server"]
        except KeyError:
            pass
        return response


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized request bodies up front (Content-Length pre-check).

    Note: chunked bodies without Content-Length are additionally capped by
    Cloudflare's edge limits; Starlette does not expose the raw stream here.
    """

    async def dispatch(self, request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "Request body too large."}, status_code=413)
        return await call_next(request)
