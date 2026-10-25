from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.database import create_db_and_tables, check_db_connection
from app.auth import router as auth_router
# Import routers from app.routers
from app.routers import institution, aicte, verify, api


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize database tables at startup."""
    create_db_and_tables()
    yield


# Initialize the FastAPI application
app = FastAPI(
    title="APAAR Verify",
    description="APAAR ID-based Student Data Management and Verification Platform for AICTE",
    version="0.1.0",
    lifespan=lifespan,
)

# Project base directory
BASE_DIR = Path(__file__).resolve().parent

# Mount static files directory at /static
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# Configure Jinja2 templates pointing to app/templates
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

# Register router modules
app.include_router(auth_router)
app.include_router(institution.router)
app.include_router(aicte.router)
app.include_router(aicte.api_router)
app.include_router(verify.router)
app.include_router(api.router)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Render friendly HTML error pages for browser requests, or JSON for API clients."""
    if exc.status_code == 303:
        headers = dict(exc.headers or {})
        return RedirectResponse(url=headers.get("Location", "/login"), status_code=303)
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        if exc.status_code == 403:
            return templates.TemplateResponse(request=request, name="403.html", status_code=403)
        if exc.status_code == 404:
            return templates.TemplateResponse(request=request, name="404.html", status_code=404)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    """GET / route that renders index.html."""
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/health")
def health_check():
    """GET /health route returning status and database connectivity."""
    db_status = check_db_connection()
    return {"status": "ok", "database": db_status}


@app.get("/institutions", response_class=RedirectResponse)
def institutions_redirect():
    """Redirect /institutions to /aicte/institutions."""
    return RedirectResponse(url="/aicte/institutions", status_code=303)


@app.get("/report", response_class=RedirectResponse)
@app.get("/reports", response_class=RedirectResponse)
def reports_redirect():
    """Redirect /report and /reports to /aicte/reports."""
    return RedirectResponse(url="/aicte/reports", status_code=303)

