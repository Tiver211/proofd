from datetime import datetime
from sqlmodel.ext.asyncio.session import AsyncSession

from ..infra.repositories import DocumentConfirmationRepository
from .dto import RevokeDocumentResultDTO


class RevokeDocumentService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = DocumentConfirmationRepository(session)

    async def revoke(
        self,
        document_hash: str,
        hash_algo: str
    ) -> RevokeDocumentResultDTO:
        """Revoke a document confirmation."""
        confirmation = await self.repo.revoke_document(document_hash)
        
        if not confirmation:
            raise ValueError(f"Document with hash {document_hash} not found")
        
        return RevokeDocumentResultDTO(
            document_hash=confirmation.document_hash,
            hash_algo=confirmation.hash_algo,
            revoked_at=confirmation.revoked_at or datetime.utcnow()
        )
