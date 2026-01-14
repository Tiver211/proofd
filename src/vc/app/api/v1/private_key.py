import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel
from sqlmodel.ext.asyncio.session import AsyncSession

from ..deps import get_session
from ...config import Config
from ...infra.repositories import VCKeyRepository
from ...infra.crypto import InvalidKeyError

router = APIRouter(
    prefix="/private-key",
    tags=["Key management"]
)


class VCKeyUpdateRequest(BaseModel):
    private_key_pem: str | None = None
    public_key_pem: str | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None


class VCKeyResponse(BaseModel):
    id: uuid.UUID
    public_key_pem: str
    valid_from: datetime
    valid_until: datetime
    active: bool


@router.post("", response_model=VCKeyResponse)
async def update_private_key(
    data: VCKeyUpdateRequest,
    x_api_key: str = Header(),
    session: AsyncSession = Depends(get_session)
):
    """
    Update the VC private key. Supports auto-key generation or manual key update.
    
    - If private_key_pem is not provided, a new Ed25519 keypair will be auto-generated
    - If private_key_pem is provided, it will be used (public key can be extracted automatically)
    - All existing active keys will be deactivated
    - Requires ADMIN_API_KEY authentication via x-api-key header
    """
    if not Config.ADMIN_API_KEY or x_api_key != Config.ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    
    repository = VCKeyRepository(session)
    
    try:
        key = await repository.update_key(
            private_key_pem=data.private_key_pem,
            public_key_pem=data.public_key_pem,
            valid_from=data.valid_from,
            valid_until=data.valid_until
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except InvalidKeyError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    return VCKeyResponse(
        id=key.id,
        public_key_pem=key.public_key_pem,
        valid_from=key.valid_from,
        valid_until=key.valid_until,
        active=key.active
    )
