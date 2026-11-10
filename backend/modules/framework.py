"""Campaign state derived from durable executions and independently verified evidence."""
from fastapi import HTTPException
from database import FrameworkEvent, ToolExecution, utcnow
from modules.campaign_objectives import objective_result
from modules.evidence import known_secrets, redact
from modules.outcomes import outcome, SUCCESS
from modules.scenarios import digest
from modules.techniques import technique


def event(db, row, kind, payload, actor=None):
    actor = actor or db.info.get('principal', {}).get('name', 'system')
    db.add(FrameworkEvent(assessment_id=row.id, kind=kind, actor=actor,
                          payload=redact(payload, known_secrets(db, row.id))))
    row.current_report_version_id = None


def node_states(db, row, ignore_index=None):
    if not row.scenario:
        return []
    executions = {e.step_index: e for e in db.query(ToolExecution).filter_by(assessment_id=row.id).all()
                  if e.step_index != ignore_index}
    criteria = {c.get('node_id'): c for c in objective_result(db, row)['criteria']}
    nodes = []
    by_id = {}
    for index, definition in enumerate(row.scenario['definition']['steps']):
        execution = executions.get(index)
        node = {'id': definition['id'], 'index': index, 'technique': definition['technique'],
                'phase': technique(definition['technique']).phase, 'depends_on': definition['depends_on'],
                'status': 'ready', 'reason': 'Ready for individual approval.', 'execution_id': None,
                'attempt': None, 'objective': criteria.get(definition['id'])}
        pending, refused = [], []
        for dependency in definition['depends_on']:
            parent = by_id[dependency['step']]
            condition = dependency['condition']
            if parent['status'] in ('ready', 'waiting', 'running', 'queued'):
                pending.append(parent['id'])
                continue
            if condition == 'verified' and parent['objective'] and parent['objective']['status'] == 'pending':
                pending.append(parent['id'])
                continue
            matched = ((condition == 'succeeded' and parent['status'] == 'completed')
                       or (condition == 'failed' and parent['status'] == 'failed')
                       or (condition == 'completed' and parent['status'] in ('completed', 'failed'))
                       or (condition == 'verified' and parent['status'] == 'completed'
                           and parent['objective'] and parent['objective']['status'] == 'achieved'))
            if not matched:
                refused.append(parent['id'])
        if refused:
            node.update(status='skipped', reason='Branch condition was not met: ' + ', '.join(refused))
        elif pending:
            node.update(status='waiting', reason='Waiting for prerequisites: ' + ', '.join(pending))
        if execution:
            state = outcome(execution.tool_name, execution.return_code, execution.stderr, execution.state)
            node.update(execution_id=execution.id, attempt=execution.attempt, evidence_sha256=execution.evidence_sha256,
                        status='completed' if state in SUCCESS and execution.approved_by_user else
                               state if state in ('queued', 'running') else 'failed',
                        reason='Execution ' + state + '.')
        nodes.append(node)
        by_id[node['id']] = node
    return nodes


def skipped_indices(db, row):
    return {node['index'] for node in node_states(db, row) if node['status'] == 'skipped'}


def enforce_node(db, row, index):
    control = (row.framework_state or {}).get('control', 'active')
    if control != 'active':
        raise HTTPException(409, f'Campaign is {control}; execution is unavailable')
    if not row.scenario:
        return
    if digest(row.plan) != row.scenario['plan_digest']:
        raise HTTPException(409, 'The immutable scenario plan no longer matches its recorded digest')
    nodes = node_states(db, row, ignore_index=index)
    node = nodes[index]
    descendants = {node['id']}
    for successor in nodes[index + 1:]:
        if any(dep['step'] in descendants for dep in successor['depends_on']):
            descendants.add(successor['id'])
            if successor['execution_id'] is not None:
                raise HTTPException(409, 'A dependent step has already executed; create a retest to revisit this prerequisite')
    if node['status'] != 'ready':
        raise HTTPException(409, node['reason'])
    if row.scenario['definition'].get('stop_on_failure') and any(n['status'] == 'failed' for n in nodes[:index]):
        raise HTTPException(409, 'Scenario stopped at a failed step; resolve that step before continuing')


def next_scenario_phase(row, current):
    phases = list(dict.fromkeys(step['phase'] for step in row.plan))
    index = phases.index(current)
    return phases[index + 1] if index + 1 < len(phases) else 'reporting'


def detection_summary(db, row):
    """Correlate supplied telemetry to exact execution attempts; never infer absence."""
    records = db.query(FrameworkEvent).filter_by(assessment_id=row.id, kind='telemetry').order_by(FrameworkEvent.id).all()
    executions = db.query(ToolExecution).filter_by(assessment_id=row.id).all()
    items = []
    for execution in executions:
        matched = [r for r in records if r.payload.get('execution_id') == execution.id
                   and r.payload.get('attempt') == execution.attempt
                   and r.payload.get('evidence_sha256') == execution.evidence_sha256]
        alerts = [r for r in matched if r.payload.get('event_type') == 'alert']
        reviewed = any(r.payload.get('event_type') == 'reviewed_no_alert' for r in matched)
        items.append({'execution_id': execution.id, 'attempt': execution.attempt, 'step_index': execution.step_index,
                      'status': 'alert_observed' if alerts else 'reviewed_no_alert' if reviewed else 'not_evaluated',
                      'alerts': len(alerts), 'events': len(matched),
                      'sources': sorted({r.payload['source'] for r in matched}),
                      'first_alert_delay_seconds': min((r.payload['delay_seconds'] for r in alerts), default=None)})
    evaluated = sum(item['status'] != 'not_evaluated' for item in items)
    detected = sum(item['status'] == 'alert_observed' for item in items)
    return {'items': items, 'evaluated': evaluated, 'alerted': detected, 'total': len(items),
            'note': 'Imported telemetry is operator-supplied evidence. Missing telemetry is not a missed detection.'}


def snapshot(db, row):
    nodes = node_states(db, row)
    cleanup = (row.framework_state or {}).get('cleanup', {})
    executed = [node for node in nodes if node['execution_id'] is not None]
    cleanup_items = [{ 'node_id': node['id'], 'instruction': technique(node['technique']).cleanup,
                      'status': 'operator_attested' if cleanup.get(node['id'], {}).get('attempt') == node['attempt'] else 'pending',
                      'record': cleanup.get(node['id'])} for node in executed]
    definition = (row.scenario or {}).get('definition')
    return {'assessment_id': row.id, 'workflow_revision': row.workflow_revision,
            'scenario': {'id': definition['id'], 'version': definition['version'], 'name': definition['name'],
                         'digest': row.scenario['digest']} if definition else None,
            'control': (row.framework_state or {}).get('control', 'active'), 'nodes': nodes,
            'cleanup': cleanup_items, 'detection': detection_summary(db, row),
            'can_complete': bool(definition and row.current_phase == 'reporting'
                                 and all(item['status'] == 'operator_attested' for item in cleanup_items)),
            'updated_at': (row.framework_state or {}).get('updated_at')}


def control_campaign(db, row, action, note, actor=None):
    control = (row.framework_state or {}).get('control', 'active')
    if control in ('stopped', 'completed'):
        raise HTTPException(409, f'A {control} campaign is immutable; create a retest run')
    if action == 'complete' and not snapshot(db, row)['can_complete']:
        raise HTTPException(409, 'Analyze all scenario phases and record cleanup review before completing')
    if action == 'resume' and control != 'paused':
        raise HTTPException(409, 'Only a paused campaign can resume')
    next_control = {'pause': 'paused', 'resume': 'active', 'stop': 'stopped', 'complete': 'completed'}[action]
    row.framework_state = {**(row.framework_state or {}), 'control': next_control, 'updated_at': utcnow().isoformat()}
    if action in ('pause', 'stop'):
        for execution in db.query(ToolExecution).filter_by(assessment_id=row.id).filter(ToolExecution.state.in_(['queued', 'running'])).all():
            execution.cancel_requested = True
            if execution.state == 'queued':
                from modules.jobs import archive_attempt
                execution.state, execution.return_code = 'cancelled', -1
                execution.stderr = f'Campaign {next_control} before execution started.'
                archive_attempt(db, execution)
        db.flush()
        if not db.query(ToolExecution.id).filter_by(assessment_id=row.id, state='running').first():
            from main import refresh_assessment_status
            refresh_assessment_status(db, row)
    event(db, row, 'control', {'action': action, 'note': note}, actor)
