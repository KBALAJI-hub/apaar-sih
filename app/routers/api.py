from fastapi import APIRouter

# Router for external integration APIs (e.g. SIS bulk uploads, DigiLocker / APAAR mock)
router = APIRouter(prefix="/api", tags=["API"])
