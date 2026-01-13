import json
import logging
from pathlib import Path
from typing import Any

from proofd.constraints import FORMAT_VERSION, SUPPORTED_HASHES

log = logging.getLogger("proofd.format")


class VerifyFormatError(Exception):
    pass


def load_verify(path: str | Path) -> dict[str, Any]:
    """
    Load and parse .verify file
    """
    path = Path(path)
    log.debug(f"Loading verify file: {path}")

    if not path.exists():
        raise VerifyFormatError(f"Verify file does not exist: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        log.error("Failed to parse JSON")
        raise VerifyFormatError(f"Invalid JSON format: {e}") from e

    log.debug("Verify file loaded successfully")
    return data


def save_verify(path: str | Path, data: dict[str, Any], force: bool = False):
    """
    Save .verify file
    """
    path = Path(path)
    log.debug(f"Saving verify file: {path}")

    if path.exists() and not force:
        raise VerifyFormatError(
            f"Verify file already exists: {path} (use --force to overwrite)"
        )

    try:
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError as e:
        log.error("Failed to write verify file")
        raise VerifyFormatError(f"Failed to write file: {e}") from e

    log.info(f"Verify file saved: {path}")


def create_verify(
    hash_info: dict[str, str],
    verifiers: list[str] | None = None,
) -> dict[str, Any]:
    """
    Create base verify structure
    """
    log.debug("Creating verify structure")

    if verifiers is None:
        verifiers = []

    data = {
        "version": FORMAT_VERSION,
        "hash": {
            "algorithm": hash_info["algorithm"],
            "value": hash_info["value"],
        },
        "verifiers": list(verifiers),
    }

    log.debug("Verify structure created")
    return data


def validate_verify(data: dict[str, Any]):
    """
    Validate verify structure
    """
    log.debug("Validating verify structure")

    if not isinstance(data, dict):
        raise VerifyFormatError("Verify data must be an object")

    # version
    version = data.get("version")
    if version != FORMAT_VERSION:
        raise VerifyFormatError(
            f"Unsupported format version: {version}"
        )

    # hash
    hash_block = data.get("hash")
    if not isinstance(hash_block, dict):
        raise VerifyFormatError("Missing or invalid 'hash' section")

    algorithm = hash_block.get("algorithm")
    value = hash_block.get("value")

    if algorithm not in SUPPORTED_HASHES:
        raise VerifyFormatError(f"Unsupported hash algorithm: {algorithm}")

    if not isinstance(value, str) or not value:
        raise VerifyFormatError("Hash value must be non-empty string")

    # verifiers
    verifiers = data.get("verifiers")
    if not isinstance(verifiers, list):
        raise VerifyFormatError("'verifiers' must be a list")

    for v in verifiers:
        if not isinstance(v, str) or not v:
            raise VerifyFormatError("Verifier IDs must be non-empty strings")

    log.info("Verify structure is valid")


def add_verifier(data: dict[str, Any], verifier_id: str):
    """
    Add verifier to verify data
    """
    log.debug(f"Adding verifier: {verifier_id}")

    validate_verify(data)

    if verifier_id in data["verifiers"]:
        log.warning("Verifier already exists")
        return

    data["verifiers"].append(verifier_id)
    log.info(f"Verifier added: {verifier_id}")


def remove_verifier(data: dict[str, Any], verifier_id: str):
    """
    Remove verifier from verify data
    """
    log.debug(f"Removing verifier: {verifier_id}")

    validate_verify(data)

    try:
        data["verifiers"].remove(verifier_id)
        log.info(f"Verifier removed: {verifier_id}")
    except ValueError:
        log.warning("Verifier not found")


def list_verifiers(data: dict[str, Any]) -> list[str]:
    """
    Return list of verifiers
    """
    validate_verify(data)
    return list(data["verifiers"])
