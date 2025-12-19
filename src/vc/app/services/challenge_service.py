from datetime import datetime
from sqlmodel.ext.asyncio.session import AsyncSession

from ..domain.value_objects import DocumentHash, ChallengeNonce
from ..domain.entities import VCKey
from ..domain.errors import DocumentNotConfirmed

from ..domain.policies import VCChallengePolicy
from ..infra.repositories import (
    DocumentConfirmationRepository,
    VCKeyRepository
)
from .dto import ChallengeResponseDTO


class ChallengeVCService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.confirmations = DocumentConfirmationRepository(session)
        self.keys = VCKeyRepository(session)


    async def challenge(
        self,
        document_hash: str,
        hash_algo: str,
        nonce: str
    ) -> ChallengeResponseDTO:

        confirmation = await self.confirmations.get_by_hash(document_hash)
        if not confirmation:
            raise DocumentNotConfirmed("Document not confirmed")

        now = datetime.utcnow()

        key_model = await self.keys.get_active_key(now)

        vc_key = VCKey(
            public_key_pem=key_model.public_key_pem,
            private_key_pem=key_model.private_key_pem,
            valid_from=key_model.valid_from,
            valid_until=key_model.valid_until
        )

        response = await VCChallengePolicy.build_challenge_response(
            document_hash=DocumentHash(document_hash, hash_algo),
            nonce=ChallengeNonce(nonce),
            vc_key=vc_key,
            now=now
        )

        return ChallengeResponseDTO(
            document_hash=document_hash,
            response=response,
            valid_until=key_model.valid_until
        )
