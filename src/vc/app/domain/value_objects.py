from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class DocumentHash:
    value: str
    algo: str

    def __post_init__(self):
        if not self.value or len(self.value) < 16:
            raise ValueError("Invalid document hash")


@dataclass(frozen=True)
class ChallengeNonce:
    value: str

    def __post_init__(self):
        if not self.value or len(self.value) < 8:
            raise ValueError("Invalid nonce")


@dataclass(frozen=True)
class Timestamp:
    value: datetime