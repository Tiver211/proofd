import json

def canonical_payload(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
