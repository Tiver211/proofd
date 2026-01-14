from fastapi import APIRouter

from .confirm import router as confirm_router
from .challenge import router as challenge_router
from .health import router as health_router
from .private_key import router as private_key_router
from .revoke import router as revoke_router

router = APIRouter(prefix="/api/v1")

router.include_router(confirm_router)
router.include_router(challenge_router)
router.include_router(health_router)
router.include_router(private_key_router)
router.include_router(revoke_router)