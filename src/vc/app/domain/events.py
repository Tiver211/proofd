from dataclasses import dataclass
from .value_objects import DocumentHash, Timestamp


@dataclass(frozen=True)
class DocumentConfirmedEvent:
    document_hash: DocumentHash
    confirmed_at: Timestamp
