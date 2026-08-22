import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(
    title="CodeGuard AI",
    description="AI-powered code analysis by Dinesh",
    version="1.0.0",
)

origins = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in origins],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from routes.analyze import router as analyze_router
app.include_router(analyze_router)

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
    uvicorn.run(app, host=host, port=port)
