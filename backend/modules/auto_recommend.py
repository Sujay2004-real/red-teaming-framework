"""Opt-in autopilot for the semi-autonomous campaign loop.

Autopilot is deliberately not a bypass of human approval. It never approves a
step, never executes a command, and never runs an analysis. What it removes is
the operator's bookkeeping round-trips: after each batch of approved steps has
run, one iteration ingests the campaign evidence those steps produced, drafts
the next kill-chain phase when the framework is allowed to, records a fresh
batch of proposals, and states exactly what the operator must decide next.

It is opt-in per assessment (default off), it requires the same aggressive lab
gate as the tools it plans for, and it is bounded by an iteration budget and a
stop-on-no-progress rule so a stalled engagement cannot spin.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Iterations per assessment. One iteration per batch of executed steps is the
# natural rate; this is the backstop that keeps an unattended loop from running
# forever against an engagement that has stopped producing new evidence.
AUTOPILOT_MAX_ITERATIONS = 25
AUTOPILOT_NOTE_CHARS = 500


def _now():
    return datetime.now(timezone.utc).isoformat()


def _note(text, limit=AUTOPILOT_NOTE_CHARS):
    return ' '.join(str(text or '').split())[:limit]


def autopilot_state(row):
    """The autopilot bookkeeping for one assessment, normalized."""
    state = row.autopilot_state if isinstance(row.autopilot_state, dict) else {}
    return {
        'iterations': int(state.get('iterations') or 0),
        'stopped': state.get('stopped') or '',
        'next_action': state.get('next_action') or '',
        'last_summary': state.get('last_summary') or '',
        'signature': state.get('signature') or '',
        'updated_at': state.get('updated_at') or '',
    }


def _signature(db, row):
    """What "the state changed" means for the stop-on-no-progress rule."""
    import main as api
    finished = db.query(api.ToolExecution).filter(
        api.ToolExecution.assessment_id == row.id,
        api.ToolExecution.return_code.is_not(None)).count()
    return f'{row.plan_version or 1}:{row.current_phase or "recon"}:{finished}:{len(row.plan or [])}'


def _persist(db, row, state, summary):
    row.autopilot_state = {
        'iterations': state['iterations'] + 1,
        'stopped': summary.get('stopped') or '',
        'next_action': summary.get('next_action') or '',
        'last_summary': _note(summary.get('summary') or summary.get('next_action')),
        'signature': summary.get('signature') or state['signature'],
        'updated_at': _now(),
    }
    db.commit()
    return row.autopilot_state


def run_autopilot_iteration(db, row, target):
    """One bounded autopilot pass over the current engagement state.

    Returns a summary dict. Every refusal - autopilot off, wrong mode, running
    command, exhausted budget, nothing new - is recorded as a stop reason
    rather than raised, because the operator asked for an unattended loop and
    the loop's reasons for idling are the report it owes them.
    """
    import main as api

    state = autopilot_state(row)
    summary = {
        'assessment_id': row.id,
        'iteration': state['iterations'] + 1,
        'phase': row.current_phase or 'recon',
        'ingested': {'footholds': 0, 'closed': 0, 'loot': 0, 'hosts': 0},
        'drafted': {'phase': None, 'steps': 0, 'note': ''},
        'proposed': 0,
        'next_action': '',
        'stopped': '',
        'signature': state['signature'],
    }

    if not row.autopilot:
        summary['stopped'] = 'autopilot is off for this assessment'
        return summary
    api.claim_workflow(db, row, allow_running=True)
    if not api.aggressive_lab(target):
        summary['stopped'] = ('autopilot drives the lab-only kill chain, so it needs a target in '
                              'aggressive lab mode that authorizes controlled exploitation')
        _persist(db, row, state, summary)
        return summary
    if state['iterations'] >= AUTOPILOT_MAX_ITERATIONS:
        summary['stopped'] = f'iteration budget of {AUTOPILOT_MAX_ITERATIONS} exhausted'
        _persist(db, row, state, summary)
        return summary
    if row.status == 'running':
        summary['stopped'] = 'a command is still executing'
        _persist(db, row, state, summary)
        return summary
    if len(row.plan or []) >= api.MAX_PLAN_STEPS:
        summary['stopped'] = 'the plan is already at its step limit'
        _persist(db, row, state, summary)
        return summary

    # 1. Ingest whatever the finished executions proved about the campaign.
    finished = db.query(api.ToolExecution).filter(
        api.ToolExecution.assessment_id == row.id,
        api.ToolExecution.return_code.is_not(None)).all()
    ingested = {'footholds': 0, 'closed': 0, 'loot': 0, 'hosts': 0}
    for execution in finished:
        recorded = api.ingest_execution_evidence(db, execution)
        for key in ingested:
            ingested[key] += recorded.get(key, 0)
    summary['ingested'] = ingested
    db.flush()

    # 2. Draft the phase the current state unlocks, when the framework may.
    next_phase = api.next_draftable_phase(row.current_phase or '', True)
    if next_phase:
        steps, notes, _refusal = api.try_draft_phase(db, row, target, next_phase)
        if steps:
            row.plan = api.normalize_plan(list(row.plan or []) + steps)
            row.plan_version = (row.plan_version or 1) + 1
            row.current_phase = next_phase
            row.status = 'awaiting_approval'
            row.current_report_version_id = None
            db.flush()
            summary['drafted'] = {'phase': next_phase, 'steps': len(steps), 'note': ''}
        else:
            summary['drafted'] = {'phase': next_phase, 'steps': 0, 'note': _note(notes)}

    # 4. Say what the operator has to decide next, and stop when idling.
    enabled = [index for index in api.phase_steps(row) if (row.plan or [])[index].get('enabled', True)]
    executed = {execution.step_index for execution in finished}
    pending = sorted(set(enabled) - executed)
    if pending:
        summary['next_action'] = (f'approve and execute {len(pending)} step(s) in the '
                                  f'{row.current_phase} phase')
    elif enabled and (row.current_phase or '') not in (row.analyzed_phases or []):
        summary['next_action'] = f'analyze the {row.current_phase} phase'
    elif not next_phase:
        summary['next_action'] = 'generate the report'

    signature = _signature(db, row)
    summary['signature'] = signature
    if signature == state['signature'] and state['iterations'] and not pending:
        summary['stopped'] = 'no new evidence to act on'
    summary['summary'] = summary['next_action'] or summary['stopped']
    _persist(db, row, state, summary)
    # Advisory publication is separate from the atomic local phase transition.
    # Release the write lock before contacting a provider, then reject proposals
    # if a user changed the engagement while the provider was answering.
    revision = row.workflow_revision
    try:
        payload = api.run_proposal(db, row, target)
        api.claim_workflow(db, row, revision)
        db.add(api.Recommendation(assessment_id=row.id, trigger_execution_id=None,
                                  phase=row.current_phase or 'recon', payload=payload,
                                  origin='autopilot'))
        db.commit()
        summary['proposed'] = len(payload.get('candidates') or [])
    except Exception:
        db.rollback()
        logger.exception('autopilot_proposal_failed', extra={'assessment_id': row.id})
        summary['drafted']['note'] = summary['drafted']['note'] or 'the advisor was unavailable or the assessment changed'
    return summary
