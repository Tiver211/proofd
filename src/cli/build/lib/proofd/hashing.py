import hashlib
import logging
from pathlib import Path

log = logging.getLogger("proofd.hashing")

SUPPORTED_ALGORITHMS = {
    "sha256": hashlib.sha256,
}

def calc_hash(path: str | Path, algorithm: str = "sha256") -> dict:
    """
    Calculate file hash.
    Returns dict suitable for .verify format.
    """
    path = Path(path)

    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    log.debug(f"Calculating hash for {path}")
    log.debug(f"Algorithm: {algorithm}")

    h = SUPPORTED_ALGORITHMS[algorithm]()

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)

    digest = h.hexdigest()

    log.info(f"Hash calculated: {digest}")

    return {
        "algorithm": algorithm,
        "value": digest,
    }
