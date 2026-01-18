import hashlib
import json

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import base64

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


def load_ed25519_public_key_pem(pem_b64: bytes) -> Ed25519PublicKey:
    pem_bytes = base64.b64decode(pem_b64)

    return serialization.load_pem_public_key(pem_bytes)

def load_rsa_public_key_pem(pem_b64: bytes) -> RSAPublicKey:
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

def verify_ac_signature(
        public_key_pem_b64: bytes,
        signature_b64: str,
        name: str,
        fingerprint: str,
        valid_from: str,
        valid_to: str,
) -> bool:
    pubkey = load_rsa_public_key_pem(public_key_pem_b64)

    payload = canonical_payload({
        "name": name,
        "fingerprint": fingerprint,
        "valid_from": valid_from,
        "valid_to": valid_to
    })
    signature = base64.b64decode(signature_b64)


    try:
        pubkey.verify(
            signature,
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def canonical_payload(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def calc_fingerprint(public_key_b64: str) -> str:
    raw = base64.b64decode(public_key_b64)
    digest = hashlib.sha256(raw).hexdigest()
    return "SHA256:" + ":".join(digest[i:i+2] for i in range(0, len(digest), 2))
