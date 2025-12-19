from sqlmodel import select
from ..models import VCRegistry

async def get_vc_by_name(session, name: str):
    result = await session.exec(select(VCRegistry).where(VCRegistry.name == name))
    return result.first()

async def list_active_vc(session):
    result = await session.exec(select(VCRegistry).where(VCRegistry.revoked == False))
    return result.all()
