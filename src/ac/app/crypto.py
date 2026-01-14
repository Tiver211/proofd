import base64
import hashlib
import binascii
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

class InvalidBase64Key(Exception):
    pass

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )

    public_bytes = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return (
        base64.b64encode(private_bytes).decode(),
        base64.b64encode(public_bytes).decode()
    )

def fingerprint(public_key_b64: str) -> str:
    try:
        decoded = base64.b64decode(public_key_b64)
    except binascii.Error:
        raise InvalidBase64Key()
    return hashlib.sha256(decoded).hexdigest()

def extract_public_key_from_private(private_key_b64: str) -> str:
    """Extract public key from private key in base64 format."""
    try:
        private_key = serialization.load_pem_private_key(
            base64.b64decode(private_key_b64),
            password=None
        )
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(public_bytes).decode()
    except (binascii.Error, ValueError, TypeError) as e:
        raise InvalidBase64Key() from e

def sign(private_key_b64: str, payload: bytes) -> str:
    private_key = serialization.load_pem_private_key(
        base64.b64decode(private_key_b64),
        password=None
    )

    signature = private_key.sign(
        payload,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode()
