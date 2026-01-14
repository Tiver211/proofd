import os
from fastapi import APIRouter, Depends, HTTPException, Header
from app.db import get_session
from app.schemas import VCRegisterRequest, VCResponse, VCReworkRequest
from app.crud.vc import get_vc_by_name, list_active_vc
from app.services.ac_service import register_vc, rework_vc

router = APIRouter(prefix="/vc", tags=["vc"])

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")

@router.post("/register", response_model=VCResponse)
async def register(
    data: VCRegisterRequest,
    x_api_key: str = Header(),
    session = Depends(get_session)
):
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403)
    return await register_vc(session, data)

@router.post("/{name}/rework", response_model=VCResponse)
async def rework(
    name: str,
    data: VCReworkRequest,
    x_api_key: str = Header(),
    session = Depends(get_session)
):
    if x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403)

    return await rework_vc(session, data, name)

@router.get("", response_model=list[VCResponse])
async def list_vc(session = Depends(get_session)):
    return await list_active_vc(session)

@router.get("/{name}", response_model=VCResponse)
async def get_vc(name: str, session = Depends(get_session)):
    vc = await get_vc_by_name(session, name)
    if not vc:
        raise HTTPException(status_code=404)
    return vc
