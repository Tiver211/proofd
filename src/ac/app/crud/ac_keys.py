from datetime import datetime
from sqlmodel import select
from ..models import ACKey
from ..crypto import generate_rsa_keypair, fingerprint, extract_public_key_from_private, InvalidBase64Key

async def get_active_ac_key(session):
    result = await session.exec(select(ACKey).where(ACKey.active == True))
    return result.first()

async def create_ac_key(session):
    priv, pub = generate_rsa_keypair()
    key = ACKey(
        public_key_b64=pub,
        private_key_b64=priv,
        fingerprint=fingerprint(pub),
        valid_from=datetime.utcnow(),
        valid_to=datetime.utcnow().replace(year=datetime.utcnow().year + 10),
        active=True
    )
    session.add(key)
    await session.commit()
    await session.refresh(key)
    return key

async def deactivate_all_ac_keys(session):
    """Deactivate all currently active AC keys."""
    result = await session.exec(select(ACKey).where(ACKey.active == True))
    active_keys = result.all()
    for key in active_keys:
        key.active = False
    await session.commit()

async def update_ac_key(
    session,
    private_key_b64: str | None = None,
    public_key_b64: str | None = None,
    valid_from: datetime | None = None,
    valid_to: datetime | None = None
):
    """Update or create a new AC key. Deactivates old keys and creates a new one."""
    # Deactivate all existing keys
    await deactivate_all_ac_keys(session)
    
    now = datetime.utcnow()
    
    # Auto-generate keypair if not provided
    if private_key_b64 is None:
        priv, pub = generate_rsa_keypair()
    else:
        priv = private_key_b64
        # Extract public key from private key if not provided
        if public_key_b64 is None:
            try:
                pub = extract_public_key_from_private(priv)
            except InvalidBase64Key:
                raise ValueError("Invalid private key format")
        else:
            pub = public_key_b64
    
    # Validate that public key matches private key if both provided
    if private_key_b64 is not None and public_key_b64 is not None:
        try:
            extracted_pub = extract_public_key_from_private(priv)
            if extracted_pub != pub:
                raise ValueError("Public key does not match private key")
        except InvalidBase64Key:
            raise ValueError("Invalid private key format")
    
    # Set default validity dates if not provided
    if valid_from is None:
        valid_from = now
    if valid_to is None:
        valid_to = now.replace(year=now.year + 10)
    
    # Create new key
    key = ACKey(
        public_key_b64=pub,
        private_key_b64=priv,
        fingerprint=fingerprint(pub),
        valid_from=valid_from,
        valid_to=valid_to,
        active=True
    )
    session.add(key)
    await session.commit()
    await session.refresh(key)
    return key
