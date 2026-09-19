"""Opt-in aggressive lab mode flag on targets."""
from alembic import op
import sqlalchemy as sa

revision = '0003_aggressive_lab'
down_revision = '0002_workflows'


def upgrade():
    additions = {
        'targets': [('aggressive_lab', sa.Boolean(), '0')],
    }
    connection = op.get_bind()
    for table, columns in additions.items():
        existing = {column['name'] for column in sa.inspect(connection).get_columns(table)}
        for name, kind, default in columns:
            if name not in existing:
                op.add_column(table, sa.Column(name, kind, server_default=default))


def downgrade():
    raise RuntimeError('Restore a database backup to downgrade.')
