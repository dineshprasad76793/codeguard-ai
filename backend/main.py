import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from dotenv import load_dotenv

from security import (
    ApiTokenMiddleware,
    BodySizeLimitMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)

load_dotenv()

app = FastAPI(
    title="CodeGuard AI",
    description="AI-powered code analysis by Dinesh",
    version="2.0.0",
)

# Middleware order: the last added runs first (outermost).
# We want security headers applied to every response, including
# errors returned by inner middleware, so it is added last.
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(ApiTokenMiddleware)
app.add_middleware(RateLimitMiddleware)
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
        allow_headers=["Content-Type", "X-API-Token"],
    )

from routes.analyze import router as analyze_router
from routes.share import router as share_router

app.include_router(analyze_router)
app.include_router(share_router)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "CodeGuard AI", "version": "2.0.0"}


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
    host = os.getenv("BACKEND_HOST", "127.0.0.1")
    port = int(os.getenv("BACKEND_PORT", "8000"))
    uvicorn.run(app, host=host, port=port, proxy_headers=True)
