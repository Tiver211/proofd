from dataclasses import dataclass
from .value_objects import DocumentHash, ChallengeNonce


@dataclass(frozen=True)
class ConfirmDocumentCommand:
    document_hash: DocumentHash


@dataclass(frozen=True)
class ChallengeVCCommand:
    document_hash: DocumentHash
    nonce: ChallengeNonce
