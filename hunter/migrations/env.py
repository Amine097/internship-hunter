"""Alembic environment. The connection is handed in by hunter.db (no alembic.ini needed)."""
from alembic import context

from hunter.models import Base

connection = context.config.attributes["connection"]
context.configure(
    connection=connection, target_metadata=Base.metadata,
    compare_type=True, render_as_batch=connection.dialect.name == "sqlite",
)
with context.begin_transaction():
    context.run_migrations()
