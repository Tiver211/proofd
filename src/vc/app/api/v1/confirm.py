from fastapi import APIRouter, Depends, status, HTTPException, Header
from pydantic import BaseModel, Field
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import Config
from ..deps import get_session
from ...services.confirm_service import ConfirmDocumentService


router = APIRouter(
    prefix="/confirm",
    tags=["Document confirmation"]
)

class ConfirmDocumentRequest(BaseModel):
    document_hash: str = Field(
        description="Криптографический хеш документа",
        example="a3f5c9d1e8..."
    )
    hash_algo: str = Field(
        description="Алгоритм хеширования",
        example="SHA-256"
    )


class ConfirmDocumentResponse(BaseModel):
    document_hash: str
    hash_algo: str
    confirmed_at: str

    class Config:
        schema_extra = {
            "example": {
                "document_hash": "a3f5c9d1e8...",
                "hash_algo": "SHA-256",
                "confirmed_at": "2025-03-01T12:30:44Z"
            }
        }

@router.post(
    "",
    response_model=ConfirmDocumentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Подтверждение документа",
    description=(
        "Фиксирует факт согласия стороны с конкретной версией документа, "
        "представленной в виде криптографического хеша. "
        "Документ не передаётся и не хранится."
    )
)
async def confirm_document(
    payload: ConfirmDocumentRequest,
    x_api_key: str = Header(),
    session: AsyncSession = Depends(get_session)):
    if not Config.ADMIN_API_KEY or x_api_key != Config.ADMIN_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")

    service = ConfirmDocumentService(session)

    result = await service.confirm(
        document_hash=payload.document_hash,
        hash_algo=payload.hash_algo
    )

    return ConfirmDocumentResponse(
        document_hash=result.document_hash,
        hash_algo=result.hash_algo,
        confirmed_at=result.confirmed_at.isoformat() + "Z"
    )
