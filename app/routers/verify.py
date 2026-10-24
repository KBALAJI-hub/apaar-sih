from fastapi import APIRouter

# Router for public/third-party student verification endpoints
router = APIRouter(prefix="/verify", tags=["Verify"])
