from fastapi import APIRouter

from .confirm import router as confirm_router
from .challenge import router as challenge_router
from .health import router as health_router

router = APIRouter(prefix="/api/v1")

router.include_router(confirm_router)
router.include_router(challenge_router)
router.include_router(health_router)