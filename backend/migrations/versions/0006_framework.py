"""Reusable scenarios and campaign records."""
from alembic import op
import sqlalchemy as sa

revision = '0006_framework'
down_revision = '0005_protected_workflows'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('assessments', sa.Column('scenario', sa.JSON()))
    op.add_column('assessments', sa.Column('framework_state', sa.JSON()))
    op.create_table('scenario_versions',
        sa.Column('id', sa.Integer(), primary_key=True), sa.Column('scenario_id', sa.String(), nullable=False),
        sa.Column('version', sa.String(), nullable=False), sa.Column('digest', sa.String(), nullable=False),
        sa.Column('definition', sa.JSON(), nullable=False), sa.Column('created_at', sa.DateTime()),
        sa.UniqueConstraint('scenario_id', 'version'))
    op.create_table('framework_events',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('assessment_id', sa.Integer(), sa.ForeignKey('assessments.id'), nullable=False),
        sa.Column('kind', sa.String(), nullable=False), sa.Column('actor', sa.String()),
        sa.Column('payload', sa.JSON()), sa.Column('created_at', sa.DateTime()))
    op.create_index('ix_framework_events_assessment_id', 'framework_events', ['assessment_id'])
    op.create_table('operator_credentials',
        sa.Column('id', sa.Integer(), primary_key=True), sa.Column('name', sa.String(), nullable=False, unique=True),
        sa.Column('key_hash', sa.String(), nullable=False, unique=True), sa.Column('role', sa.String(), nullable=False),
        sa.Column('active', sa.Boolean(), nullable=False, server_default=sa.true()), sa.Column('created_at', sa.DateTime()))
    op.create_table('worker_registrations', sa.Column('id', sa.String(), primary_key=True),
        sa.Column('hostname', sa.String(), nullable=False), sa.Column('capabilities', sa.JSON()),
        sa.Column('heartbeat_at', sa.DateTime(), nullable=False))
    op.create_table('execution_leases', sa.Column('resource', sa.String(), primary_key=True),
        sa.Column('worker_id', sa.String(), nullable=False), sa.Column('execution_id', sa.Integer(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False))


def downgrade():
    raise RuntimeError('Campaign evidence must be preserved; restore a backup to revert this migration')
