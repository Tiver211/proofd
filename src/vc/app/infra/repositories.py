from sqlmodel import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from datetime import datetime

from .models import DocumentConfirmation, VCKeyModel

class DocumentConfirmationRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_hash(
        self,
        document_hash: str
    ) -> Optional[DocumentConfirmation]:

        stmt = select(DocumentConfirmation).where(
            DocumentConfirmation.document_hash == document_hash
        )
        result = await self.session.exec(stmt)
        return result.first()

    async def create_if_not_exists(
        self,
        document_hash: str,
        hash_algo: str
    ) -> DocumentConfirmation:

        existing = await self.get_by_hash(document_hash)
        if existing:
            return existing

        confirmation = DocumentConfirmation(
            document_hash=document_hash,
            hash_algo=hash_algo
        )

        self.session.add(confirmation)

        try:
            await self.session.commit()
        except Exception:
            # если словили race-condition — просто читаем
            await self.session.rollback()
            return await self.get_by_hash(document_hash)

        await self.session.refresh(confirmation)
        return confirmation


class VCKeyRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_active_key(
        self,
        now: datetime
    ) -> VCKeyModel:

        stmt = (
            select(VCKeyModel)
            .where(VCKeyModel.active == True)
            .where(VCKeyModel.valid_from <= now)
            .where(VCKeyModel.valid_until >= now)
            .limit(1)
        )

        result = await self.session.exec(stmt)
        key = result.first()

        if not key:
            raise RuntimeError("No active VC key found")

        return key

    async def create_key(
        self,
        public_key_pem: str,
        private_key_pem: str,
        valid_from: datetime,
        valid_until: datetime
    ) -> VCKeyModel:

        key = VCKeyModel(
            public_key_pem=public_key_pem,
            private_key_pem=private_key_pem,
            valid_from=valid_from,
            valid_until=valid_until,
            active=True
        )

        self.session.add(key)
        await self.session.commit()
        await self.session.refresh(key)

        return key
