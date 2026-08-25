import os
import logging
from contextlib import asynccontextmanager

from dotenv import load_dotenv

# Must run BEFORE importing security/rate_limit/share: those modules read
# CG_API_TOKEN, REDIS_URL and SHARE_SECRET from the environment at import
# time, and load_dotenv() is what populates them from backend/.env locally.
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from security import (
    ApiTokenMiddleware,
    BodySizeLimitMiddleware,
    DocsProtectionMiddleware,
    SecurityHeadersMiddleware,
    validate_security_env,
)
from rate_limit import limiter

logger = logging.getLogger("codeguard")


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_security_env()
    logger.info("CodeGuard AI starting — security validation passed.")
    yield


app = FastAPI(
    title="CodeGuard AI",
    description="AI-powered code analysis by Dinesh",
    version="2.0.0",
    lifespan=lifespan,
)
app.state.limiter = limiter

# ── Middleware ────────────────────────────────────────────────────
# Starlette applies them in REVERSE registration order: the first
# `add_middleware` runs innermost (closest to the route handler),
# the last runs outermost (first to see every request/response).
#
# Desired request flow (outermost → innermost):
#   CORS → SecurityHeaders → ApiToken → DocsProtection → route
#
# Registration order (first = innermost):
#   1. DocsProtection   (only /docs /redoc /openapi.json)
#   2. ApiToken          (rejects 401 before the handler runs)
#   3. SecurityHeaders   (applies to 401/429/413 errors too)
#   4. CORS              (outermost — adds headers for cross-origin preflight)
app.add_middleware(DocsProtectionMiddleware)
app.add_middleware(ApiTokenMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(BodySizeLimitMiddleware)

# CORS is only enabled when explicitly configured (e.g. local development).
# In production the frontend is served from the same origin, so the
# default is "no CORS" — the strictest posture.
cors_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
if cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-API-Key", "X-API-Token"],
    )

from routes.analyze import router as analyze_router
from routes.share import router as share_router

app.include_router(analyze_router)
app.include_router(share_router)


@app.get("/api/health")
def health():
    # Deliberately generic: no version or build details from public endpoints.
    return {"status": "ok"}


# Serve the React production build (single-service deployment).
# In development the React dev server runs separately on port 3000.
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_BUILD = os.path.normpath(os.path.join(BACKEND_DIR, "..", "frontend", "build"))

if os.path.isdir(FRONTEND_BUILD):
    static_dir = os.path.join(FRONTEND_BUILD, "static")
    if os.path.isdir(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/{full_path:path}")
    def serve_frontend(full_path: str):
        # Reject obvious path-traversal attempts before normpath.
        if ".." in full_path:
            return FileResponse(os.path.join(FRONTEND_BUILD, "index.html"))
        candidate = os.path.normpath(os.path.join(FRONTEND_BUILD, full_path))
        if (
            full_path
            and candidate.startswith(FRONTEND_BUILD)
            and os.path.isfile(candidate)
        ):
            return FileResponse(candidate)
        return FileResponse(os.path.join(FRONTEND_BUILD, "index.html"))


if __name__ == "__main__":
    import uvicorn
    logging.basicConfig(level=logging.INFO)
    host = os.getenv("BACKEND_HOST", "127.0.0.1")
    port = int(os.getenv("BACKEND_PORT", "8000"))
    uvicorn.run(app, host=host, port=port, proxy_headers=True)
