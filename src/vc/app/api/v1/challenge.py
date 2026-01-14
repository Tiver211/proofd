import base64

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlmodel.ext.asyncio.session import AsyncSession

from ..deps import get_session
from ...services.challenge_service import ChallengeVCService
from ...domain.errors import DocumentNotConfirmed, DocumentRevoked

router = APIRouter(
    prefix="/challenge",
    tags=["Verification challenge"]
)


class ChallengeRequest(BaseModel):
    document_hash: str = Field(
        ...,
        description="Хеш проверяемого документа"
    )
    hash_algo: str = Field(
        ...,
        description="Алгоритм хеширования",
        example="SHA-256"
    )
    nonce: str = Field(
        ...,
        description="Случайная строка (challenge) от клиента",
        example="f93kd02ls9"
    )


class ChallengeResponse(BaseModel):
    document_hash: str
    response: bytes = Field(
        ...,
        description="Криптографический ответ VC (подпись challenge + хеша)"
    )
    valid_until: str

@router.post(
    "",
    response_model=ChallengeResponse,
    summary="Challenge-подтверждение VC",
    description=(
        "Позволяет клиенту убедиться, что VC действительно "
        "подтверждал конкретную версию документа. "
        "Используется схема challenge-response."
    )
)
async def challenge_vc(
    payload: ChallengeRequest,
    session: AsyncSession = Depends(get_session)
):
    service = ChallengeVCService(session)

    try:
        result = await service.challenge(
            document_hash=payload.document_hash,
            hash_algo=payload.hash_algo,
            nonce=payload.nonce
        )
    except DocumentNotConfirmed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not confirmed by this VC"
        )
    except DocumentRevoked:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Document has been revoked"
        )

    return ChallengeResponse(
        document_hash=result.document_hash,
        response=base64.b64encode(result.response).decode("ascii"),
        valid_until=result.valid_until.isoformat() + "Z"
    )
