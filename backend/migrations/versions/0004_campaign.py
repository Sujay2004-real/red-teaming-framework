"""Semi-autonomous campaign: footholds, loot, engagement hosts, autopilot.

Adds the tables the post-exploitation and lateral-movement phases are anchored
to, plus the two assessment columns that make a discovery sweep promotable into
a child assessment and let the operator opt in to autopilot.
"""
from alembic import op
import sqlalchemy as sa

revision = '0004_campaign'
down_revision = '0003_aggressive_lab'


def upgrade():
    connection = op.get_bind()
    inspector = sa.inspect(connection)

    existing = {column['name'] for column in inspector.get_columns('assessments')}
    for name, kind, default in (
        ('parent_assessment_id', sa.Integer(), None),
        ('autopilot', sa.Boolean(), '0'),
        ('autopilot_state', sa.JSON(), None),
    ):
        if name not in existing:
            op.add_column('assessments', sa.Column(name, kind, server_default=default))

    if 'footholds' not in inspector.get_table_names():
        op.create_table(
            'footholds',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('assessment_id', sa.Integer(), sa.ForeignKey('assessments.id'), nullable=False),
            sa.Column('host', sa.String(), server_default=''),
            sa.Column('kind', sa.String(), server_default='session'),
            sa.Column('remote_id', sa.String(), server_default=''),
            sa.Column('username', sa.String(), server_default=''),
            sa.Column('privilege', sa.String(), server_default=''),
            sa.Column('state', sa.String(), server_default='open'),
            sa.Column('pivot_ready', sa.Boolean(), server_default='0'),
            sa.Column('source_tool', sa.String(), server_default=''),
            sa.Column('source_execution_id', sa.Integer()),
            sa.Column('evidence', sa.Text(), server_default=''),
            sa.Column('opened_at', sa.DateTime()),
            sa.Column('last_seen_at', sa.DateTime()),
            sa.Column('closed_at', sa.DateTime()),
            sa.UniqueConstraint('assessment_id', 'host', 'kind', 'remote_id', name='uq_foothold_identity'),
        )
        op.create_index('ix_footholds_assessment_id', 'footholds', ['assessment_id'])
        op.create_index('ix_foothold_assessment_state', 'footholds', ['assessment_id', 'state'])

    if 'loot' not in inspector.get_table_names():
        op.create_table(
            'loot',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('assessment_id', sa.Integer(), sa.ForeignKey('assessments.id'), nullable=False),
            sa.Column('foothold_id', sa.Integer(), sa.ForeignKey('footholds.id')),
            sa.Column('host', sa.String(), server_default=''),
            sa.Column('service', sa.String(), server_default=''),
            sa.Column('username', sa.String(), server_default=''),
            sa.Column('secret_kind', sa.String(), server_default='password'),
            sa.Column('secret_encrypted', sa.Text(), server_default=''),
            sa.Column('secret_fingerprint', sa.String(), server_default=''),
            sa.Column('source_tool', sa.String(), server_default=''),
            sa.Column('source_execution_id', sa.Integer()),
            sa.Column('validated', sa.Boolean(), server_default='0'),
            sa.Column('notes', sa.Text(), server_default=''),
            sa.Column('created_at', sa.DateTime()),
            sa.UniqueConstraint('assessment_id', 'host', 'service', 'username', 'secret_kind',
                                'secret_fingerprint', name='uq_loot_identity'),
        )
        op.create_index('ix_loot_assessment_id', 'loot', ['assessment_id'])
        op.create_index('ix_loot_secret_fingerprint', 'loot', ['secret_fingerprint'])

    if 'engagement_hosts' not in inspector.get_table_names():
        op.create_table(
            'engagement_hosts',
            sa.Column('id', sa.Integer(), primary_key=True),
            sa.Column('assessment_id', sa.Integer(), sa.ForeignKey('assessments.id'), nullable=False),
            sa.Column('address', sa.String(), server_default=''),
            sa.Column('hostname', sa.String(), server_default=''),
            sa.Column('role', sa.String(), server_default='discovered'),
            sa.Column('os_name', sa.String(), server_default=''),
            sa.Column('state', sa.String(), server_default='known'),
            sa.Column('child_assessment_id', sa.Integer()),
            sa.Column('notes', sa.Text(), server_default=''),
            sa.Column('created_at', sa.DateTime()),
            sa.UniqueConstraint('assessment_id', 'address', name='uq_engagement_host'),
        )
        op.create_index('ix_engagement_hosts_assessment_id', 'engagement_hosts', ['assessment_id'])


def downgrade():
    raise RuntimeError('Restore a database backup to downgrade.')