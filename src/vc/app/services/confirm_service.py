from datetime import datetime
from sqlmodel.ext.asyncio.session import AsyncSession

from ..domain.value_objects import DocumentHash
from ..domain.policies import DocumentConfirmationPolicy

from ..infra.repositories import DocumentConfirmationRepository
from .dto import ConfirmDocumentResultDTO

class ConfirmDocumentService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.repo = DocumentConfirmationRepository(session)

    async def confirm(
        self,
        document_hash: str,
        hash_algo: str
    ) -> ConfirmDocumentResultDTO:

        dh = DocumentHash(
            value=document_hash,
            algo=hash_algo
        )

        now = datetime.utcnow()

        confirmed = await DocumentConfirmationPolicy.confirm(
            document_hash=dh,
            now=now
        )

        model = await self.repo.create_if_not_exists(
            document_hash=dh.value,
            hash_algo=dh.algo
        )

        return ConfirmDocumentResultDTO(
            document_hash=model.document_hash,
            hash_algo=model.hash_algo,
            confirmed_at=model.confirmed_at
        )

