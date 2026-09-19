"""Job state, history, SSH trust, reviews and report provenance."""
from alembic import op
import sqlalchemy as sa

revision = '0002_workflows'
down_revision = '0001_adopt'


def upgrade():
    additions = {
        'targets': [('engagement_policy', sa.JSON(), '{}')],
        'app_settings': [('ssh_fingerprint', sa.String(), ''), ('ssh_private_key', sa.Text(), ''), ('ssh_key_passphrase', sa.Text(), '')],
        'assessments': [('plan_version', sa.Integer(), '1'), ('analysis_metadata', sa.JSON(), '{}')],
        'tool_executions': [('state', sa.String(), 'queued'), ('cancel_requested', sa.Boolean(), '0'),
                            ('worker_id', sa.String(), ''), ('heartbeat_at', sa.DateTime(), None),
                            ('live_output', sa.Text(), ''), ('output_cursor', sa.Integer(), '0'),
                            ('plan_version', sa.Integer(), '1')],
    }
    connection = op.get_bind()
    for table, columns in additions.items():
        existing = {column['name'] for column in sa.inspect(connection).get_columns(table)}
        for name, kind, default in columns:
            if name not in existing:
                op.add_column(table, sa.Column(name, kind, server_default=default))
    connection.execute(sa.text("UPDATE tool_executions SET state='completed' WHERE return_code=0"))
    connection.execute(sa.text("UPDATE tool_executions SET state='failed' WHERE return_code IS NOT NULL AND return_code<>0"))
    connection.execute(sa.text("UPDATE tool_executions SET state='interrupted', return_code=-1 WHERE return_code IS NULL"))
    connection.execute(sa.text("UPDATE tool_executions SET state='completed_with_findings' WHERE tool_name='zap-baseline.py' AND return_code IN (1,2)"))
    # Import each surviving historical attempt without inventing missing older runs.
    import json
    fields = ('id', 'step_index', 'tool_name', 'command', 'stdout', 'stderr', 'return_code', 'duration_ms', 'approved_by_user', 'attempt', 'executed_at', 'execution_host', 'state', 'plan_version')
    for row in connection.execute(sa.text('SELECT * FROM tool_executions')).mappings().all():
        snapshot = {key: row.get(key) for key in fields}
        connection.execute(sa.text('INSERT INTO execution_attempts (execution_id, assessment_id, attempt, snapshot, created_at) SELECT :id, :assessment_id, :attempt, :snapshot, CURRENT_TIMESTAMP WHERE NOT EXISTS (SELECT 1 FROM execution_attempts WHERE execution_id=:id AND attempt=:attempt)'),
            {'id': row['id'], 'assessment_id': row['assessment_id'], 'attempt': row['attempt'] or 1, 'snapshot': json.dumps(snapshot, default=str)})
    for table, name, columns in [
        ('findings', 'ix_finding_assessment_priority', ['assessment_id', 'priority_score']),
        ('tool_executions', 'ix_tool_executions_state', ['state']),
    ]:
        if name not in {item['name'] for item in sa.inspect(connection).get_indexes(table)}:
            op.create_index(name, table, columns)


def downgrade():
    raise RuntimeError('Restore a database backup to downgrade this audit-preserving migration.')
