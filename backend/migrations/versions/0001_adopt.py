"""Adopt legacy databases without dropping assessment evidence."""
from alembic import op

revision = '0001_adopt'
down_revision = None


def upgrade():
    from migrations.snapshot import create_snapshot, adopt_columns
    connection = op.get_bind()
    create_snapshot(connection)
    if connection.dialect.name == 'sqlite':
        adopt_columns(connection)


def downgrade():
    raise RuntimeError('Restore a database backup to downgrade the adopted schema.')
