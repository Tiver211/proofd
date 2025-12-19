from dataclasses import dataclass
from datetime import datetime

from .value_objects import DocumentHash, Timestamp

@dataclass
class ConfirmedDocument:
    document_hash: DocumentHash
    confirmed_at: Timestamp


@dataclass
class VCKey:
    public_key_pem: str
    private_key_pem: str
    valid_from: datetime
    valid_until: datetime

    def is_valid(self, now: datetime) -> bool:
        return self.valid_from <= now <= self.valid_until