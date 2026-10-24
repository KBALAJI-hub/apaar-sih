from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Import routers from app.routers
from app.routers import institution, aicte, verify, api

# Initialize the FastAPI application
app = FastAPI(
    title="APAAR Verify",
    description="APAAR ID-based Student Data Management and Verification Platform for AICTE",
    version="0.1.0",
)

# Project base directory
BASE_DIR = Path(__file__).resolve().parent

# Mount static files directory at /static
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# Configure Jinja2 templates pointing to app/templates
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Register router modules
app.include_router(institution.router)
app.include_router(aicte.router)
app.include_router(verify.router)
app.include_router(api.router)


@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    """GET / route that renders base.html."""
    return templates.TemplateResponse(request=request, name="base.html")


@app.get("/health")
def health_check():
    """GET /health route returning status ok."""
    return {"status": "ok"}
