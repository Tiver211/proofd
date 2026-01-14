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
            # If document was revoked, clear the revocation upon re-confirmation
            if existing.revoked:
                existing.revoked = False
                existing.revoked_at = None
                existing.confirmed_at = datetime.utcnow()  # Update confirmation timestamp
                await self.session.commit()
                await self.session.refresh(existing)
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
            existing = await self.get_by_hash(document_hash)
            if existing:
                # Handle revocation clearing if document was created by another process
                if existing.revoked:
                    existing.revoked = False
                    existing.revoked_at = None
                    existing.confirmed_at = datetime.utcnow()
                    await self.session.commit()
                    await self.session.refresh(existing)
                return existing
            # If no existing document found after rollback, something unexpected happened
            # Re-raise to let caller handle it
            raise

        await self.session.refresh(confirmation)
        return confirmation

    async def revoke_document(
        self,
        document_hash: str
    ) -> DocumentConfirmation | None:
        """Revoke a document confirmation by hash."""
        confirmation = await self.get_by_hash(document_hash)
        if not confirmation:
            return None
        
        if confirmation.revoked:
            return confirmation  # Already revoked
        
        confirmation.revoked = True
        confirmation.revoked_at = datetime.utcnow()
        
        await self.session.commit()
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

    async def deactivate_all_keys(self) -> None:
        """Deactivate all currently active VC keys."""
        stmt = select(VCKeyModel).where(VCKeyModel.active == True)
        result = await self.session.exec(stmt)
        active_keys = result.all()
        for key in active_keys:
            key.active = False
        await self.session.commit()

    async def update_key(
        self,
        private_key_pem: str | None = None,
        public_key_pem: str | None = None,
        valid_from: datetime | None = None,
        valid_until: datetime | None = None
    ) -> VCKeyModel:
        """Update or create a new VC key. Deactivates old keys and creates a new one."""
        # Deactivate all existing keys
        await self.deactivate_all_keys()

        now = datetime.utcnow()

        # Import here to avoid circular dependency
        from ..infra.crypto import generate_ed25519_keypair, extract_public_key_from_private, InvalidKeyError

        # Auto-generate keypair if not provided
        if private_key_pem is None:
            priv, pub = generate_ed25519_keypair()
        else:
            priv = private_key_pem
            # Extract public key from private key if not provided
            if public_key_pem is None:
                try:
                    pub = extract_public_key_from_private(priv)
                except InvalidKeyError:
                    raise ValueError("Invalid private key format")
            else:
                pub = public_key_pem

        # Validate that public key matches private key if both provided
        if private_key_pem is not None and public_key_pem is not None:
            try:
                extracted_pub = extract_public_key_from_private(priv)
                if extracted_pub != pub:
                    raise ValueError("Public key does not match private key")
            except InvalidKeyError:
                raise ValueError("Invalid private key format")

        # Set default validity dates if not provided
        if valid_from is None:
            valid_from = now
        if valid_until is None:
            valid_until = now.replace(year=now.year + 10)

        # Create new key
        return await self.create_key(
            public_key_pem=pub,
            private_key_pem=priv,
            valid_from=valid_from,
            valid_until=valid_until
        )
