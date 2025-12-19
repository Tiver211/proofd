from fastapi import APIRouter
from .vc import router as vc_router

router = APIRouter()
router.include_router(vc_router)