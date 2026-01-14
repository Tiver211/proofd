from fastapi import APIRouter
from .vc import router as vc_router
from .ac import router as ac_router

router = APIRouter()
router.include_router(vc_router)
router.include_router(ac_router)