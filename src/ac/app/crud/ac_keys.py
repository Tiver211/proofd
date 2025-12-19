from datetime import datetime
from sqlmodel import select
from ..models import ACKey
from ..crypto import generate_rsa_keypair, fingerprint

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
