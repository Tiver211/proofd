from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import base64

def load_private_key(pem: str) -> ed25519.Ed25519PrivateKey:
    return serialization.load_pem_private_key(
        pem.encode(),
        password=None
    )

def load_public_key(pem: str) -> ed25519.Ed25519PublicKey:
    return serialization.load_pem_public_key(
        pem.encode()
    )

def sign_payload(
    payload: bytes,
    private_key_pem: str
) -> str:
    private_key = load_private_key(private_key_pem)
    signature = private_key.sign(payload)
    return base64.b64encode(signature).decode()

def verify_signature(
    payload: bytes,
    signature_b64: str,
    public_key_pem: str
) -> bool:
    public_key = load_public_key(public_key_pem)
    signature = base64.b64decode(signature_b64)

    try:
        public_key.verify(signature, payload)
        return True
    except Exception:
        return False
