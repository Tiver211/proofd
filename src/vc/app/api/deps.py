from typing import AsyncGenerator
from sqlmodel.ext.asyncio.session import AsyncSession

from ..infra.db import async_session_factory

async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        yield session
