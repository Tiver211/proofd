from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import base64


class InvalidKeyError(Exception):
    pass


def generate_ed25519_keypair() -> tuple[str, str]:
    """Generate Ed25519 keypair and return as PEM strings."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_pem, public_pem


def extract_public_key_from_private(private_key_pem: str) -> str:
    """Extract public key from private key in PEM format."""
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        return public_pem
    except (ValueError, TypeError, Exception) as e:
        raise InvalidKeyError(f"Invalid private key format: {e}") from e


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
