"""Frozen adoption schema; never import evolving application metadata here."""
from sqlalchemy import inspect, text

DDL = ['\nCREATE TABLE IF NOT EXISTS app_settings (\n\tid INTEGER NOT NULL, \n\tgemini_api_key TEXT, \n\tapi_base_url VARCHAR, \n\tmodel_name VARCHAR, \n\tproxy_url VARCHAR, \n\tproxy_username VARCHAR, \n\tproxy_password TEXT, \n\texecution_mode VARCHAR, \n\tssh_host VARCHAR, \n\tssh_port INTEGER, \n\tssh_username VARCHAR, \n\tssh_password TEXT, \n\tssh_fingerprint VARCHAR, \n\tssh_private_key TEXT, \n\tssh_key_passphrase TEXT, \n\toperator_key_hash VARCHAR, \n\tupdated_at DATETIME, \n\tPRIMARY KEY (id)\n)\n\n', '\nCREATE TABLE IF NOT EXISTS targets (\n\tid INTEGER NOT NULL, \n\tname VARCHAR NOT NULL, \n\tscope_domain_ip VARCHAR NOT NULL, \n\tauthorized_scopes JSON, \n\tcriticality INTEGER, \n\trestricted_tools JSON, \n\texploitation_authorized BOOLEAN, \n\tengagement_policy JSON, \n\tcreated_at DATETIME, \n\tPRIMARY KEY (id)\n)\n\n', '\nCREATE TABLE IF NOT EXISTS assessments (\n\tid INTEGER NOT NULL, \n\ttarget_id INTEGER NOT NULL, \n\tobjective TEXT NOT NULL, \n\tstatus VARCHAR, \n\t"plan" JSON, \n\tengagement_brief JSON, \n\tapproval_required BOOLEAN, \n\tanalysis_mode VARCHAR, \n\tcurrent_phase VARCHAR, \n\tanalyzed_phases JSON, \n\tplan_version INTEGER NOT NULL, \n\tanalysis_metadata JSON, \n\tcreated_at DATETIME, \n\tcompleted_at DATETIME, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(target_id) REFERENCES targets (id)\n)\n\n', '\nCREATE TABLE IF NOT EXISTS finding_reviews (\n\tid INTEGER NOT NULL, \n\tassessment_id INTEGER NOT NULL, \n\tfingerprint VARCHAR NOT NULL, \n\tstatus VARCHAR, \n\towner VARCHAR, \n\tdue_date VARCHAR, \n\tjustification TEXT, \n\tcomments JSON, \n\tretest_evidence TEXT, \n\tupdated_at DATETIME, \n\tPRIMARY KEY (id), \n\tUNIQUE (assessment_id, fingerprint), \n\tFOREIGN KEY(assessment_id) REFERENCES assessments (id)\n)\n\n', '\nCREATE TABLE IF NOT EXISTS findings (\n\tid INTEGER NOT NULL, \n\tassessment_id INTEGER NOT NULL, \n\tfingerprint VARCHAR, \n\ttitle VARCHAR NOT NULL, \n\tdescription TEXT, \n\tseverity VARCHAR, \n\tevidence TEXT, \n\tremediation TEXT, \n\trisk_score INTEGER, \n\tpriority_score INTEGER, \n\tconfidence_score INTEGER, \n\tendpoint VARCHAR, \n\tparameter VARCHAR, \n\texploitability INTEGER, \n\timpact INTEGER, \n\texposure INTEGER, \n\tverification VARCHAR, \n\texploit_evidence TEXT, \n\tverified_by JSON, \n\tphase VARCHAR, \n\tsource_tools JSON, \n\tcreated_at DATETIME, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(assessment_id) REFERENCES assessments (id)\n)\n\n', '\nCREATE TABLE IF NOT EXISTS recommendation_tasks (\n\tid INTEGER NOT NULL, \n\tassessment_id INTEGER NOT NULL, \n\texecution_id INTEGER NOT NULL, \n\tattempt INTEGER, \n\tstate VARCHAR, \n\tdetail VARCHAR, \n\tcreated_at DATETIME, \n\tupdated_at DATETIME, \n\tPRIMARY KEY (id), \n\tUNIQUE (execution_id, attempt), \n\tFOREIGN KEY(assessment_id) REFERENCES assessments (id)\n)\n\n', '\nCREATE TABLE IF NOT EXISTS recommendations (\n\tid INTEGER NOT NULL, \n\tassessment_id INTEGER NOT NULL, \n\ttrigger_execution_id INTEGER, \n\tphase VARCHAR, \n\tpayload JSON, \n\torigin VARCHAR, \n\tcreated_at DATETIME, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(assessment_id) REFERENCES assessments (id)\n)\n\n', '\nCREATE TABLE IF NOT EXISTS report_versions (\n\tid INTEGER NOT NULL, \n\tassessment_id INTEGER NOT NULL, \n\tdigest VARCHAR NOT NULL, \n\tpath VARCHAR NOT NULL, \n\tprovenance JSON, \n\tcreated_at DATETIME, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(assessment_id) REFERENCES assessments (id)\n)\n\n', '\nCREATE TABLE IF NOT EXISTS tool_executions (\n\tid INTEGER NOT NULL, \n\tassessment_id INTEGER NOT NULL, \n\tstep_index INTEGER, \n\ttool_name VARCHAR NOT NULL, \n\tcommand TEXT NOT NULL, \n\tstdout TEXT, \n\tstderr TEXT, \n\treturn_code INTEGER, \n\tduration_ms INTEGER, \n\tapproved_by_user BOOLEAN, \n\tattempt INTEGER, \n\texecuted_at DATETIME, \n\texecution_host JSON, \n\tstate VARCHAR, \n\tcancel_requested BOOLEAN, \n\tworker_id VARCHAR, \n\theartbeat_at DATETIME, \n\tlive_output TEXT, \n\toutput_cursor INTEGER, \n\tplan_version INTEGER, \n\tPRIMARY KEY (id), \n\tCONSTRAINT uq_tool_execution_step UNIQUE (assessment_id, step_index), \n\tFOREIGN KEY(assessment_id) REFERENCES assessments (id)\n)\n\n', '\nCREATE TABLE IF NOT EXISTS execution_attempts (\n\tid INTEGER NOT NULL, \n\texecution_id INTEGER NOT NULL, \n\tassessment_id INTEGER NOT NULL, \n\tattempt INTEGER NOT NULL, \n\tsnapshot JSON NOT NULL, \n\tcreated_at DATETIME, \n\tPRIMARY KEY (id), \n\tUNIQUE (execution_id, attempt), \n\tFOREIGN KEY(execution_id) REFERENCES tool_executions (id), \n\tFOREIGN KEY(assessment_id) REFERENCES assessments (id)\n)\n\n']

def create_snapshot(connection):
    for ddl in DDL:
        connection.execute(text(ddl))

def adopt_columns(connection):
    additions = {
        # Every column added to AppSettings after the first release has to be
        # listed here. create_all only creates missing tables, so a database
        # from an earlier version keeps its old app_settings shape, and
        # _encrypt_stored_secrets below then SELECTs proxy_password from a
        # table that has no such column - an OperationalError at import time
        # that takes the whole backend down before it can serve anything.
        'app_settings': [
            ('api_base_url', "VARCHAR DEFAULT ''"), ('model_name', "VARCHAR DEFAULT ''"),
            ('proxy_url', "VARCHAR DEFAULT ''"), ('proxy_username', "VARCHAR DEFAULT ''"),
            ('proxy_password', "TEXT DEFAULT ''"), ('updated_at', 'DATETIME'),
            ('execution_mode', "VARCHAR DEFAULT 'local'"), ('ssh_host', "VARCHAR DEFAULT ''"),
            ('ssh_port', 'INTEGER DEFAULT 22'), ('ssh_username', "VARCHAR DEFAULT ''"),
            ('ssh_password', "TEXT DEFAULT ''"), ('operator_key_hash', "VARCHAR DEFAULT ''"),
        ],
        'targets': [('authorized_scopes', "JSON DEFAULT '[]'"), ('criticality', 'INTEGER DEFAULT 70'), ('restricted_tools', "JSON DEFAULT '[]'"), ('exploitation_authorized', 'BOOLEAN DEFAULT 0'), ('aggressive_lab', 'BOOLEAN DEFAULT 0')],
        'assessments': [('approval_required', 'BOOLEAN DEFAULT 1'), ('completed_at', 'DATETIME'), ('engagement_brief', 'JSON'), ('analysis_mode', "VARCHAR DEFAULT ''"), ('current_phase', "VARCHAR DEFAULT 'recon'"), ('analyzed_phases', "JSON DEFAULT '[]'")],
        'tool_executions': [('step_index', 'INTEGER DEFAULT 0'), ('duration_ms', 'INTEGER DEFAULT 0'), ('approved_by_user', 'BOOLEAN DEFAULT 0'), ('attempt', 'INTEGER DEFAULT 1'), ('execution_host', 'JSON')],
        'findings': [('fingerprint', "VARCHAR DEFAULT ''"), ('risk_score', 'INTEGER DEFAULT 0'), ('priority_score', 'INTEGER DEFAULT 0'), ('confidence_score', 'INTEGER DEFAULT 0'), ('source_tools', "JSON DEFAULT '[]'"), ('created_at', 'DATETIME'), ('endpoint', "VARCHAR DEFAULT ''"), ('parameter', "VARCHAR DEFAULT ''"), ('exploitability', 'INTEGER DEFAULT 3'), ('impact', 'INTEGER DEFAULT 3'), ('exposure', 'INTEGER DEFAULT 3'), ('verification', "VARCHAR DEFAULT ''"), ('exploit_evidence', "TEXT DEFAULT ''"), ('verified_by', "JSON DEFAULT '[]'"), ('phase', "VARCHAR DEFAULT 'recon'")],
    }
    from contextlib import nullcontext
    with nullcontext(connection) as conn:
        known = inspect(conn)
        for table, columns in additions.items():
            existing = {column['name'] for column in known.get_columns(table)}
            for name, ddl in columns:
                if name not in existing:
                    conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {name} {ddl}'))
        duplicate = conn.execute(text('SELECT 1 FROM tool_executions GROUP BY assessment_id, step_index HAVING COUNT(*) > 1 LIMIT 1')).first()
        if not duplicate:
            conn.execute(text('CREATE UNIQUE INDEX IF NOT EXISTS uq_tool_execution_step_idx ON tool_executions (assessment_id, step_index)'))
