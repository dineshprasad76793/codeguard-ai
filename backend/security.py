"""Security middleware for CodeGuard AI.

- Security headers on every response
- Per-IP rate limiting (strictest on AI endpoints)
- Request body size caps
- Optional API-token auth (CG_API_TOKEN): X-API-Key header,
  verified with secrets.compare_digest (constant-time)
- /docs, /redoc, /openapi.json blocked in production (DOCS_ENABLED=true
  to re-enable locally)
"""
import os
import secrets
import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# Expensive AI-backed endpoints get a stricter bucket.
AI_PATHS = ("/api/analyze", "/api/scan-url", "/api/scan-github")
RATE_BUCKETS = {
    "ai": (10, 60),       # 10 AI calls per minute per IP
    "default": (60, 60),  # 60 other API calls per minute per IP
}
MAX_BODY_BYTES = 1_000_000  # 1 MB

DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'"
        )
        return response


class DocsProtectionMiddleware(BaseHTTPMiddleware):
    """Hide interactive API documentation in production.

    Set DOCS_ENABLED=true in the environment to expose /docs during
    development. A valid API token (when auth is enabled) also unlocks it.
    """

    async def dispatch(self, request, call_next):
        path = request.url.path.rstrip("/")
        if path in DOCS_PATHS and os.getenv("DOCS_ENABLED", "").lower() != "true":
            token = os.getenv("CG_API_TOKEN", "")
            provided = request.headers.get("x-api-key", "") or request.headers.get(
                "x-api-token", ""
            )
            if not (token and provided and secrets.compare_digest(token, provided)):
                return JSONResponse({"detail": "Not found."}, status_code=404)
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple fixed-window per-IP limiter, in memory (per-instance)."""

    def __init__(self, app):
        super().__init__(app)
        self._hits = {}

    def _client_ip(self, request):
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    async def dispatch(self, request, call_next):
        path = request.url.path
        if path.startswith("/api"):
            bucket = "ai" if path.startswith(AI_PATHS) else "default"
            limit, window = RATE_BUCKETS[bucket]
            key = f"{bucket}:{self._client_ip(request)}"
            now = time.time()
            recent = [t for t in self._hits.get(key, []) if now - t < window]
            if len(recent) >= limit:
                return JSONResponse(
                    {"detail": "Too many requests. Please wait a minute and try again."},
                    status_code=429,
                    headers={"Retry-After": str(window)},
                )
            recent.append(now)
            self._hits[key] = recent
            if len(self._hits) > 10_000:  # opportunistic cleanup
                self._hits = {
                    k: v for k, v in self._hits.items() if v and now - v[-1] < window
                }
        return await call_next(request)


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "Request body too large."}, status_code=413)
        return await call_next(request)


class ApiTokenMiddleware(BaseHTTPMiddleware):
    """Optional token auth. Enabled only when CG_API_TOKEN is set.

    Accepts X-API-Key (preferred) or X-API-Token (legacy alias), verified
    with secrets.compare_digest (constant-time).

    Public: /api/health and GET /api/share/{token} (share recipients).
    """

    PUBLIC_PATHS = ("/api/health",)

    def _provided_token(self, request):
        return request.headers.get("x-api-key") or request.headers.get("x-api-token") or ""

    async def dispatch(self, request, call_next):
        token = os.getenv("CG_API_TOKEN", "")
        path = request.url.path
        share_read = path.startswith("/api/share/") and request.method == "GET"
        needs_auth = (
            token
            and path.startswith("/api")
            and not share_read
            and not any(path.startswith(p) for p in self.PUBLIC_PATHS)
        )
        if needs_auth and not secrets.compare_digest(
            self._provided_token(request), token
        ):
            return JSONResponse(
                {"detail": "Invalid or missing API key (X-API-Key header)."},
                status_code=401,
            )
        return await call_next(request)
