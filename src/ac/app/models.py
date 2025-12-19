import uuid
from datetime import datetime

from sqlalchemy import Column
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlmodel import SQLModel, Field

class ACKey(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    public_key_b64: str
    private_key_b64: str
    fingerprint: str
    valid_from: datetime = Field(sa_column=Column(TIMESTAMP(timezone=True)))
    valid_to: datetime = Field(sa_column=Column(TIMESTAMP(timezone=True)))
    active: bool = Field(default=True)

class VCRegistry(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str = Field(unique=True, index=True)
    description: str | None = None
    public_key_b64: str
    key_fingerprint: str
    valid_from: datetime = Field(sa_column=Column(TIMESTAMP(timezone=True)))
    valid_to: datetime = Field(sa_column=Column(TIMESTAMP(timezone=True)))
    endpoint: str = Field(nullable=True, default=None)
    revoked: bool = Field(default=False)
    ac_signature_b64: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
