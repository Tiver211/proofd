from sqlalchemy import Column, DateTime
from sqlmodel import SQLModel, Field
from datetime import datetime, timezone, timedelta
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

    revoked: bool = Field(
        default=False,
        nullable=False,
        index=True
    )

    revoked_at: datetime | None = Field(
        default=None,
        nullable=True
    )


class VCKeyModel(SQLModel, table=True):
    __tablename__ = "vc_keys"

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        primary_key=True
    )

    public_key_pem: str = Field(nullable=False)
    private_key_pem: str = Field(nullable=False)

    valid_from: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False),
        default_factory=lambda: datetime.now(timezone.utc),
    )

    valid_until: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False),
        default_factory=lambda: (datetime.now(timezone.utc) + timedelta(days=7)),
    )

    active: bool = Field(default=True, index=True)
