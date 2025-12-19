from typing import AsyncGenerator

from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    create_async_engine,
)
from sqlalchemy.ext.asyncio.session import async_sessionmaker

from .config import Config


engine: AsyncEngine = create_async_engine(
    Config.DATABASE_URL,
    echo=Config.DB_ECHO,
    future=True,
)


async_session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        yield session


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
