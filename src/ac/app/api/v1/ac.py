import os
from fastapi import APIRouter, Depends, HTTPException, Header
from app.db import get_session
from app.schemas import ACKeyUpdateRequest, ACKeyResponse, ACPublicKeyResponse
from app.crud.ac_keys import update_ac_key, get_active_ac_key
from app.crypto import InvalidBase64Key

router = APIRouter(prefix="/ac", tags=["ac"])

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")

@router.post("/private-key", response_model=ACKeyResponse)
async def update_private_key(
    data: ACKeyUpdateRequest,
    x_api_key: str = Header(),
    session = Depends(get_session)
):
    """
    Update the AC private key. Supports auto-key generation or manual key update.
    
    - If private_key_b64 is not provided, a new keypair will be auto-generated
    - If private_key_b64 is provided, it will be used (public key can be extracted automatically)
    - All existing active keys will be deactivated
    - Requires ADMIN_API_KEY authentication via X-API-Key header
    """
    if not ADMIN_API_KEY or x_api_key != ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    
    try:
        key = await update_ac_key(
            session=session,
            private_key_b64=data.private_key_b64,
            public_key_b64=data.public_key_b64,
            valid_from=data.valid_from,
            valid_to=data.valid_to
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except InvalidBase64Key:
        raise HTTPException(status_code=400, detail="Invalid key format")
    
    return ACKeyResponse(
        id=key.id,
        public_key_b64=key.public_key_b64,
        fingerprint=key.fingerprint,
        valid_from=key.valid_from,
        valid_to=key.valid_to,
        active=key.active
    )

@router.get("/public-key", response_model=ACPublicKeyResponse)
async def get_public_key(session = Depends(get_session)):
    key = await get_active_ac_key(session=session)
    public_key = key.public_key_b64
    return ACPublicKeyResponse(public_key_b64=public_key)
