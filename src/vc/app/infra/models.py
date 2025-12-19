from sqlmodel import SQLModel, Field
from datetime import datetime
import uuid


class DocumentConfirmation(SQLModel, table=True):
    __tablename__ = "document_confirmations"

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        primary_key=True
    )

    document_hash: str = Field(
        index=True,
        unique=True,
        nullable=False
    )

    hash_algo: str = Field(
        default="SHA-256",
        nullable=False
    )

    first_seen: datetime = Field(
        default_factory=datetime.utcnow,
        nullable=False
    )

    confirmed_at: datetime = Field(
        default_factory=datetime.utcnow,
        nullable=False
    )


class VCKeyModel(SQLModel, table=True):
    __tablename__ = "vc_keys"

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        primary_key=True
    )

    public_key_pem: str = Field(nullable=False)
    private_key_pem: str = Field(nullable=False)

    valid_from: datetime = Field(nullable=False)
    valid_until: datetime = Field(nullable=False)

    active: bool = Field(default=True, index=True)
