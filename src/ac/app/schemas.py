import uuid
from datetime import datetime
from pydantic import BaseModel

class VCRegisterRequest(BaseModel):
    name: str
    description: str | None = None
    public_key_b64: str
    endpoint: str | None = None
    valid_from: datetime
    valid_to: datetime

class VCReworkRequest(BaseModel):
    public_key_b64: str
    valid_from: datetime
    valid_to: datetime

class VCResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    public_key_b64: str
    key_fingerprint: str
    valid_from: datetime
    valid_to: datetime
    endpoint: str | None = None
    revoked: bool
    ac_signature_b64: str

class ACKeyUpdateRequest(BaseModel):
    private_key_b64: str | None = None
    public_key_b64: str | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None

class ACKeyResponse(BaseModel):
    id: uuid.UUID
    public_key_b64: str
    fingerprint: str
    valid_from: datetime
    valid_to: datetime
    active: bool
