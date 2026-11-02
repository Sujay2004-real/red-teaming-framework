"""Protected originals and revision-checked workflow publication."""
from alembic import op
import sqlalchemy as sa

revision = '0005_protected_workflows'
down_revision = '0004_campaign'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('assessments', sa.Column('workflow_revision', sa.Integer(), nullable=False, server_default='1'))
    op.add_column('assessments', sa.Column('current_report_version_id', sa.Integer()))
    op.add_column('assessments', sa.Column('evidence_protected', sa.Boolean(), nullable=False, server_default=sa.false()))
    for table in ('tool_executions', 'execution_attempts'):
        op.add_column(table, sa.Column('raw_encrypted', sa.Text(), server_default=''))
        op.add_column(table, sa.Column('evidence_sha256', sa.String(), server_default=''))
    op.add_column('report_versions', sa.Column('restricted', sa.Boolean(), nullable=False, server_default=sa.true()))
    op.add_column('report_versions', sa.Column('raw_encrypted', sa.Text(), server_default=''))


def downgrade():
    raise RuntimeError('Protected evidence cannot be downgraded to plaintext storage')
