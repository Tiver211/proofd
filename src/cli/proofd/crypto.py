from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import base64


def load_ed25519_public_key_pem(pem_b64: bytes) -> Ed25519PublicKey:
    pem_bytes = base64.b64decode(pem_b64)

    return serialization.load_pem_public_key(pem_bytes)


def verify_vc_signature(
    public_key_pem_b64: bytes,
    signature_b64: str,
    nonce: str,
    document_hash: str,
    hash_algo: str,
) -> bool:
    pubkey = load_ed25519_public_key_pem(public_key_pem_b64)

    payload = (
        f"{document_hash}:{hash_algo}:{nonce}"
    ).encode("utf-8")
    signature = base64.b64decode(signature_b64)

    try:
        pubkey.verify(signature, payload)
        return True
    except InvalidSignature:
        return False
