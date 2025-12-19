import sys
from datetime import datetime
import base64

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from .entities import ConfirmedDocument, VCKey
from .value_objects import Timestamp, ChallengeNonce, DocumentHash
from .errors import KeyExpired


class DocumentConfirmationPolicy:

    @staticmethod
    async def confirm(
        document_hash: DocumentHash,
        now: datetime
    ) -> ConfirmedDocument:

        return ConfirmedDocument(
            document_hash=document_hash,
            confirmed_at=Timestamp(now)
        )


class VCChallengePolicy:

    @staticmethod
    async def build_challenge_response(
        document_hash: DocumentHash,
        nonce: ChallengeNonce,
        vc_key: VCKey,
        now: datetime
    ) -> bytes:

        if not vc_key.is_valid(now):
            raise KeyExpired("VC key expired")

        payload = (
            document_hash.value +
            document_hash.algo +
            nonce.value
        ).encode()
        print(payload, flush=True)

        pem_bytes = base64.b64decode(vc_key.private_key_pem)

        private_key = serialization.load_pem_private_key(
            pem_bytes,
            password=None
        )

        signature = private_key.sign(
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size,  # ← 32 байта
            ),
            hashes.SHA256(),
        )

        return signature
