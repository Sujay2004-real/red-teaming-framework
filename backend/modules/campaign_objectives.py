"""Evaluate explicit campaign goals from executed evidence, independently of AI.

The first adapters cover SQLmap confirmation and bounded database-banner
disclosure. A completed scan without proof means 'not demonstrated', never
'secure'. Unsupported or malformed criteria cannot become achieved.
"""
import re
import shlex
from urllib.parse import parse_qsl, urlsplit

from modules.verification import command_endpoint, confirmation_match, verification_key


LABELS = {
    'sql_injection': 'Confirm SQL injection',
    'database_banner': 'Demonstrate database version disclosure',
}
ANSI_RE = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
BANNER_RE = re.compile(r"^\s*banner:\s*['\"]?(?P<value>[^\r\n]+)", re.IGNORECASE)
UNUSABLE = {'queued', 'running', 'failed', 'cancelled', 'interrupted', 'timed_out'}


def criterion_key(criterion):
    # This first objective adapter covers query parameters only. Duplicate
    # parameters and POST/cookie injection need a richer request identity.
    try:
        pairs = parse_qsl(urlsplit(criterion.get('endpoint', '')).query, keep_blank_values=True)
        if sum(name == criterion.get('parameter') for name, _ in pairs) != 1:
            return None
    except (ValueError, TypeError):
        return None
    return verification_key({'title': 'SQL injection', 'endpoint': criterion.get('endpoint'),
                             'parameter': criterion.get('parameter')})


def _receipt(execution, line):
    return {
        'execution_id': execution['id'], 'attempt': execution.get('attempt', 1),
        'phase': execution.get('phase', ''), 'tool': 'sqlmap',
        'evidence_sha256': execution.get('evidence_sha256', ''),
        'excerpt': line.strip()[:600],
    }


def evaluate_sql_objectives(brief, executions, analyzed_phases=()):
    """Return public receipts only; callers redact known secrets before display.

Executions must come from stored originals and their actual plan phases. A
finding's title, score, or AI-authored verification field is never an input.
"""
    criteria = (brief or {}).get('success_criteria') or []
    result = {'status': 'not_configured', 'criteria': [], 'scope_note':
              'Results cover these explicit objectives and completed checks only. '
              'Not demonstrated does not establish that the target is secure.'}
    if not criteria:
        return result

    records = []
    for execution in executions:
        if execution.get('tool') != 'sqlmap' or execution.get('phase') not in ('exploitation', 'post_exploitation'):
            continue
        endpoint = command_endpoint('sqlmap', execution.get('command', ''))
        if not endpoint:
            continue
        completed = (execution.get('return_code') == 0 and execution.get('state') not in UNUSABLE
                     and execution.get('approved_by_user') is True)
        analyzed = execution.get('phase') in analyzed_phases
        text = ANSI_RE.sub('', str(execution.get('stdout', '')) + '\n' + str(execution.get('stderr', '')))
        confirmations, banners = [], []
        if completed and analyzed:
            for line in text.splitlines():
                match = confirmation_match(line)
                if match and re.search(r'\bGET\s+parameter\s', line, re.IGNORECASE):
                    key = criterion_key({'endpoint': endpoint, 'parameter': match.group('param')})
                    if key:
                        confirmations.append((key, _receipt(execution, line)))
                banner = BANNER_RE.match(line)
                if banner:
                    value = banner.group('value').strip().strip("'\"")
                    if value and value.lower() not in {'none', 'null', 'unknown', 'n/a', '(null)'}:
                        banners.append(_receipt(execution, line))
        try:
            tokens = shlex.split(execution.get('command', ''))
        except ValueError:
            tokens = []
        records.append({'endpoint': endpoint, 'execution': execution, 'completed': completed,
                        'analyzed': analyzed, 'confirmations': confirmations,
                        'banners': banners if '--banner' in tokens else []})

    for criterion in criteria[:10]:
        kind = criterion.get('kind')
        key = criterion_key(criterion)
        item = {**{k: criterion.get(k, '') for k in ('kind', 'endpoint', 'parameter')},
                'label': LABELS.get(kind, 'Unsupported objective'), 'status': 'pending',
                'reason': 'No applicable analyzed execution is available.', 'evidence': []}
        result['criteria'].append(item)
        if kind not in LABELS or key is None:
            item.update(status='inconclusive', reason='The objective has no supported evidence adapter.')
            continue
        relevant = [r for r in records if criterion_key({'endpoint': r['endpoint'],
                                                        'parameter': criterion['parameter']}) == key]
        proof = [receipt for r in relevant for confirmed_key, receipt in r['confirmations'] if confirmed_key == key]
        banners = [receipt for r in relevant for receipt in r['banners']
                   if not criterion.get('node_id') or r['execution'].get('node_id') == criterion['node_id']]
        if proof and (kind == 'sql_injection' or banners):
            item.update(status='achieved', reason='Confirmed by successful, analyzed scanner output.',
                        evidence=proof[:1] + (banners[:1] if kind == 'database_banner' else []))
        elif any(not r['completed'] and r['execution'].get('return_code') is not None for r in relevant):
            item.update(status='inconclusive', reason='An applicable execution failed or was incomplete; it cannot establish the objective.')
        elif any(r['completed'] and r['analyzed'] for r in relevant):
            if kind == 'database_banner' and proof and not any('--banner' in r['execution'].get('command', '') for r in relevant):
                item['reason'] = 'Injection is confirmed; database version disclosure has not been tested.'
            else:
                item.update(status='not_demonstrated', reason=(
                    'The completed checks did not establish SQL injection; impact is not demonstrated.'
                    if not proof else 'No usable database banner was recovered by the completed checks.'))
    statuses = {c['status'] for c in result['criteria']}
    result['status'] = ('achieved' if statuses == {'achieved'} else 'inconclusive' if 'inconclusive' in statuses
                        else 'pending' if 'pending' in statuses else 'not_demonstrated')
    return result


def evaluate_objectives(brief, executions, analyzed_phases=()):
    from modules.objective_adapters import LABELS as GENERIC, evaluate_generic, aggregate_status, validate_criterion
    criteria = (brief or {}).get('success_criteria') or []
    result = evaluate_sql_objectives({}, [], analyzed_phases)
    for criterion in criteria[:50]:
        try:
            checked = validate_criterion({k: v for k, v in criterion.items() if k != 'node_id'})
        except (ValueError, TypeError, AttributeError):
            result['criteria'].append({'label': 'Unsupported objective', 'status': 'inconclusive',
                                       'reason': 'The objective has no supported evidence adapter.', 'evidence': []})
            continue
        node_id = criterion.get('node_id')
        scoped = [e for e in executions if not node_id or e.get('node_id') == node_id]
        if checked['kind'] in GENERIC:
            item = evaluate_generic(checked, scoped, analyzed_phases)
        else:
            # Banner evidence belongs to this node. SQL confirmation can come
            # from its previously verified injection prerequisite.
            candidates = executions if checked['kind'] == 'database_banner' else scoped
            item = evaluate_sql_objectives({'success_criteria': [{**checked, 'node_id': node_id}]}, candidates, analyzed_phases)['criteria'][0]
        if criterion.get('node_id'):
            item['node_id'] = criterion['node_id']
        result['criteria'].append(item)
    result['status'] = aggregate_status(result['criteria'])
    return result


def objective_result(db, assessment):
    """Compute a result without making evidence-heavy queries for other runs."""
    criteria = ((assessment.scenario or {}).get('criteria') if getattr(assessment, 'scenario', None)
                else (assessment.engagement_brief or {}).get('success_criteria'))
    if not criteria:
        return evaluate_objectives({}, [])
    from database import ToolExecution
    from modules.evidence import original, known_secrets, redact
    rows = db.query(ToolExecution).filter_by(assessment_id=assessment.id).all()
    plan = assessment.plan or []
    executions = []
    for row in rows:
        step = plan[row.step_index] if 0 <= row.step_index < len(plan) else {}
        phase = step.get('phase', '')
        executions.append({**original(row), 'id': row.id, 'attempt': row.attempt,
                           'node_id': step.get('scenario_node'),
                           'phase': phase, 'tool': row.tool_name, 'state': row.state,
                           'return_code': row.return_code, 'approved_by_user': row.approved_by_user,
                           'evidence_sha256': row.evidence_sha256})
    result = evaluate_objectives({'success_criteria': criteria}, executions, assessment.analyzed_phases or [])
    return redact(result, known_secrets(db, assessment.id))
