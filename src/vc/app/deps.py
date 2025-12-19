

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from fastapi import Depends

from app.services.vc import (
    AuthorityCenterService,
    VerificationCenterQueryService,
)
from app.infra.db import get_session
from app.config import Config



def get_ac_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        Config.AC_PRIVATE_KEY
    )


def get_ac_public_key() -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(
        Config.AC_PUBLIC_KEY
    )


def get_ac_service(
    private_key=Depends(get_ac_private_key),
) -> AuthorityCenterService:
    return AuthorityCenterService(private_key)


def get_vc_service(
    public_key=Depends(get_ac_public_key),
) -> VerificationCenterQueryService:
    return VerificationCenterQueryService(public_key)
