from fastapi import APIRouter, Depends, HTTPException, Header, status
from pydantic import BaseModel, Field
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import Config
from ..deps import get_session
from ...services.revoke_service import RevokeDocumentService

router = APIRouter(
    prefix="/revoke",
    tags=["Document revocation"]
)


class RevokeDocumentRequest(BaseModel):
    document_hash: str = Field(
        ...,
        description="Криптографический хеш документа для отзыва",
        example="a3f5c9d1e8..."
    )
    hash_algo: str = Field(
        ...,
        description="Алгоритм хеширования",
        example="SHA-256"
    )


class RevokeDocumentResponse(BaseModel):
    document_hash: str
    hash_algo: str
    revoked_at: str

    class Config:
        schema_extra = {
            "example": {
                "document_hash": "a3f5c9d1e8...",
                "hash_algo": "SHA-256",
                "revoked_at": "2025-03-01T12:30:44Z"
            }
        }


@router.post(
    "",
    response_model=RevokeDocumentResponse,
    status_code=status.HTTP_200_OK,
    summary="Отзыв подтверждения документа",
    description=(
        "Отзывает подтверждение документа. После отзыва документ "
        "не может быть использован для challenge-подтверждения. "
        "Требует ADMIN_API_KEY аутентификации."
    )
)
async def revoke_document(
    payload: RevokeDocumentRequest,
    x_api_key: str = Header(),
    session: AsyncSession = Depends(get_session)
):
    """Revoke a document confirmation. Protected with API key."""
    if not Config.ADMIN_API_KEY or x_api_key != Config.ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")

    service = RevokeDocumentService(session)

    try:
        result = await service.revoke(
            document_hash=payload.document_hash,
            hash_algo=payload.hash_algo
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )

    return RevokeDocumentResponse(
        document_hash=result.document_hash,
        hash_algo=result.hash_algo,
        revoked_at=result.revoked_at.isoformat() + "Z"
    )
