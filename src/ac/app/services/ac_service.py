from sqlalchemy.exc import IntegrityError

from app.crud.vc import get_vc_by_name
from app.crypto import fingerprint, sign
from app.utils import canonical_payload
from app.crud.ac_keys import get_active_ac_key, create_ac_key
from app.models import VCRegistry
from fastapi import HTTPException
from app.schemas import VCReworkRequest, VCRegisterRequest

from app.crypto import InvalidBase64Key


async def register_vc(session, data: VCRegisterRequest):
    ac_key = await get_active_ac_key(session)
    if not ac_key:
        ac_key = await create_ac_key(session)

    try:
        fp = fingerprint(data.public_key_b64)
    except InvalidBase64Key:
        raise HTTPException(status_code=400, detail="Invalid base64 public key")

    payload = canonical_payload({
        "name": data.name,
        "fingerprint": fp,
        "valid_from": data.valid_from.isoformat(),
        "valid_to": data.valid_to.isoformat()
    })

    signature = sign(ac_key.private_key_b64, payload)

    vc = VCRegistry(
        name=data.name,
        description=data.description,
        public_key_b64=data.public_key_b64,
        key_fingerprint=fp,
        endpoint=data.endpoint,
        valid_from=data.valid_from,
        valid_to=data.valid_to,
        ac_signature_b64=signature
    )

    session.add(vc)
    try:
        await session.commit()

    except IntegrityError as e:
        raise HTTPException(status_code=400, detail="VC already exists")

    await session.refresh(vc)

    return vc

async def rework_vc(session, data: VCReworkRequest, vc_name):
    ac_key = await get_active_ac_key(session)
    if not ac_key:
        ac_key = await create_ac_key(session)

    try:
        fp = fingerprint(data.public_key_b64)
    except InvalidBase64Key:
        raise HTTPException(status_code=400, detail="Invalid base64 public key")

    vc = await get_vc_by_name(session, vc_name)

    if not vc:
        raise HTTPException(status_code=404, detail="VC not found")

    payload = canonical_payload({
        "name": vc.name,
        "fingerprint": fp,
        "valid_from": data.valid_from.isoformat().replace("+00:00", "Z"),
        "valid_to": data.valid_to.isoformat().replace("+00:00", "Z")
    })

    signature = sign(ac_key.private_key_b64, payload)

    vc.public_key_b64 = data.public_key_b64
    vc.valid_from = data.valid_from
    vc.valid_to = data.valid_to
    vc.key_fingerprint = fp
    vc.ac_signature_b64 = signature

    await session.commit()

    return vc
