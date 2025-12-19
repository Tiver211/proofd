from dataclasses import dataclass
from datetime import datetime


@dataclass
class ConfirmDocumentResultDTO:
    document_hash: str
    hash_algo: str
    confirmed_at: datetime


@dataclass
class ChallengeResponseDTO:
    document_hash: str
    response: bytes
    valid_until: datetime
