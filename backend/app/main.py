import os
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from backend.app.config import settings
from backend.app.database.db import init_db
from backend.app.core.redaction import setup_redacting_logger
from backend.app.api.routes_investigation import router as investigation_router
from backend.app.api.routes_reports import router as reports_router
from backend.app.api.routes_config import router as config_router
from backend.app.api.routes_universal_forensics import router as universal_forensics_router
from backend.app.api.routes_osint import router as osint_router
from backend.app.api.routes_network_validation import router as network_validation_router
from backend.app.api.routes_dynamic_sandbox import router as dynamic_sandbox_router
from backend.app.api.routes_dynamic_lab import router as dynamic_lab_router
from backend.app.api.routes_credentials import router as credentials_router
from backend.app.api.routes_auth import router as auth_router
from backend.app.api.routes_oauth import router as oauth_router
from backend.app.api.routes_network_mode import router as network_mode_router
from backend.app.api.routes_opencode import router as opencode_router
from backend.app.api.routes_ip_details import router as ip_details_router
from backend.app.core.network_mode import init_network_mode

# Initialize centralized secret redacting logger
setup_redacting_logger()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database, logging redactor, and required storage directories
    setup_redacting_logger()
    init_db()
    init_network_mode()
    settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
    settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    settings.RULES_DIR.mkdir(parents=True, exist_ok=True)
    yield

app = FastAPI(
    title="Universal Digital Forensics & Evidence Intelligence Platform API",
    description="Multi-platform digital forensics, APK/EXE analysis, and evidence intelligence platform.",
    version="2.0.0",
    docs_url="/docs" if settings.ENABLE_API_DOCS else None,
    redoc_url="/redoc" if settings.ENABLE_API_DOCS else None,
    openapi_url="/openapi.json" if settings.ENABLE_API_DOCS else None,
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def workstation_security_boundary(request, call_next):
    """
    Enforces trusted network boundary policies:
    1. Single-user workstation mode binds exclusively to loopback (127.0.0.1, ::1).
    2. Remote network access is rejected in workstation mode.
    3. Untrusted forwarded headers cannot bypass loopback checks.
    4. Host header validation prevents DNS rebinding attacks.
    5. Origin validation restricts cross-origin API calls.
    """
    mode = getattr(settings, "DEPLOYMENT_MODE", "workstation").lower()
    if mode == "workstation":
        client_host = request.client.host if request.client else "127.0.0.1"
        is_loopback = client_host in ("127.0.0.1", "::1", "localhost", "testclient")
        if not is_loopback:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "Remote network access rejected in single-user workstation mode. The platform is bound exclusively to local loopback."
                }
            )

        # Host Header Validation (anti-DNS rebinding)
        host_header = request.headers.get("host", "")
        host_name = host_header.split(":")[0].lower() if host_header else ""
        if host_name and host_name not in ("127.0.0.1", "localhost", "::1", "testclient", "testserver"):
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=403,
                content={"detail": "Forbidden: Invalid Host header (DNS rebinding protection)."}
            )

        # Origin Header Validation for API requests
        origin = request.headers.get("origin")
        if origin and request.url.path.startswith("/api/"):
            allowed_prefixes = (
                "http://127.0.0.1", "http://localhost",
                "https://127.0.0.1", "https://localhost",
                "tauri://", "http://tauri.localhost", "https://tauri.localhost"
            )
            if not any(origin.startswith(prefix) for prefix in allowed_prefixes):
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Forbidden: Untrusted cross-origin request origin."}
                )

    response = await call_next(request)
    return response

@app.middleware("http")
async def tracex_bridge_token_enforcement(request, call_next):
    """
    SEC-BRIDGE-001: Enforce high-entropy desktop bridge token validation.
    When running in desktop mode (TRACEX_BRIDGE_TOKEN set in settings or os.environ),
    all /api/ requests (excluding /api/health) must supply matching 'X-TraceX-Bridge-Token' header.
    Rejects unauthorized local process or browser probing with 403 Forbidden.
    """
    bridge_token = getattr(settings, "BRIDGE_TOKEN", None) or os.getenv("TRACEX_BRIDGE_TOKEN")
    if bridge_token:
        path = request.url.path
        if path.startswith("/api/") and path != "/api/health":
            token = request.headers.get("x-tracex-bridge-token") or request.headers.get("X-TraceX-Bridge-Token")
            import hmac
            if not token or not hmac.compare_digest(token.strip(), bridge_token.strip()):
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Forbidden: Invalid or missing TraceX desktop bridge token."}
                )
    return await call_next(request)

# Include Routers
app.include_router(investigation_router)
app.include_router(reports_router)
app.include_router(config_router)
app.include_router(universal_forensics_router)
app.include_router(osint_router)
app.include_router(network_validation_router)
app.include_router(dynamic_sandbox_router)
app.include_router(dynamic_lab_router)
app.include_router(credentials_router)
app.include_router(auth_router)
app.include_router(oauth_router)
app.include_router(network_mode_router)
app.include_router(opencode_router)
app.include_router(ip_details_router)

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.VERSION,
        "local_only_mode": settings.LOCAL_ONLY_MODE,
        "network_mode": "LOCAL_ONLY" if settings.LOCAL_ONLY_MODE else "HYBRID"
    }

@app.post("/api/system/shutdown")
def shutdown_backend():
    """
    SEC-BRIDGE-001: Gracefully terminates the TraceX backend service.
    Protected by desktop bridge token enforcement middleware.
    """
    import threading
    import time
    import signal
    def _do_shutdown():
        time.sleep(0.2)
        try:
            os.kill(os.getpid(), signal.SIGINT)
        except Exception:
            pass

    threading.Thread(target=_do_shutdown, daemon=True).start()
    return {"status": "shutting_down", "message": "Graceful backend shutdown initiated."}

# Mount static frontend production build and SPA routes
frontend_dist = getattr(settings, "BUNDLE_FRONTEND_DIST", None)
if not frontend_dist or not frontend_dist.exists() or not (frontend_dist / "index.html").exists():
    frontend_dist = getattr(settings, "APP_DIR", Path(__file__).resolve().parent.parent.parent) / "frontend" / "dist"
if not frontend_dist.exists() or not (frontend_dist / "index.html").exists():
    frontend_dist = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

if frontend_dist.exists() and (frontend_dist / "index.html").exists():
    from fastapi.responses import FileResponse
    from fastapi import HTTPException

    assets_dir = frontend_dist / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="static_assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa_app(full_path: str):
        if full_path.startswith("api/") or full_path == "api":
            raise HTTPException(status_code=404, detail="API endpoint not found")
        target_file = frontend_dist / full_path
        if full_path and target_file.is_file():
            return FileResponse(str(target_file))
        return FileResponse(str(frontend_dist / "index.html"))
