import asyncio
import os
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine
from sqlmodel import SQLModel  # <-- Добавьте это
from alembic import context

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# Импортируйте ВСЕ ваши модели здесь!
from app.models import *

target_metadata = SQLModel.metadata

# Используйте metadata из SQLModel

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = os.getenv("DATABASE_URL")
    # Если URL не содержит asyncpg, добавляем его
    if url and "postgresql://" in url and "asyncpg" not in url:
        url = url.replace("postgresql://", "postgresql+asyncpg://")

    context.configure(
        url=url,
        target_metadata=target_metadata,  # <-- Убедитесь, что передается
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Функция для запуска миграций через синхронное соединение."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata  # <-- Убедитесь, что передается
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """В этом случае мы можем запустить миграции в асинхронном режиме."""

    database_url = os.getenv("DATABASE_URL")

    # Если URL не содержит asyncpg, добавляем его
    if database_url and "postgresql://" in database_url and "asyncpg" not in database_url:
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://")

    connectable = create_async_engine(
        database_url,
        poolclass=pool.NullPool,
        echo=False  # Можно включить для отладки
    )

    async with connectable.connect() as connection:
        # Запускаем миграции через run_sync для синхронного контекста
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Запуск миграций в 'онлайн' режиме."""

    connectable = config.attributes.get("connection", None)

    if connectable is None:
        # Если нет готового соединения, запускаем асинхронно
        asyncio.run(run_async_migrations())
    else:
        # Если соединение уже предоставлено (для тестов и т.д.)
        do_run_migrations(connectable)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()