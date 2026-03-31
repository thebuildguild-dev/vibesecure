"""
Alembic migration environment configuration.
"""

from logging.config import fileConfig

from sqlmodel import SQLModel

from alembic import context
from app.core.config import settings
from app.core.database import engine

# Import all models so they are registered with SQLModel metadata
from app.models import (  # noqa: F401
    Consent,
    DomainVerification,
    DomainVerificationAudit,
    Finding,
    GovernanceJob,
    Scan,
)

config = context.config
config.set_main_option("sqlalchemy.url", settings.database_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = SQLModel.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
