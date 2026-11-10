"""Evidence adapters for explicit objectives, separate from finding inference."""
import re
import shlex
from urllib.parse import urlsplit

from modules.techniques import validate_input

LABELS = {'http_response': 'Observe an HTTP response', 'tcp_service': 'Observe an open TCP service'}


def validate_criterion(value):
    if not isinstance(value, dict):
        raise ValueError('An objective must be an object')
    kind = value.get('kind')
    allowed = {'sql_injection': {'kind', 'endpoint', 'parameter'},
               'database_banner': {'kind', 'endpoint', 'parameter'},
               'http_response': {'kind', 'endpoint', 'expected_status'},
               'tcp_service': {'kind', 'endpoint', 'port'}}
    if kind not in allowed or set(value) - allowed[kind]:
        raise ValueError('Unsupported objective type or fields')
    endpoint = validate_input('host' if kind == 'tcp_service' else 'url', value.get('endpoint'))
    normalized = {**value, 'endpoint': endpoint}
    if kind in ('sql_injection', 'database_banner'):
        from modules.campaign_objectives import criterion_key
        normalized['parameter'] = validate_input('parameter', value.get('parameter'))
        if criterion_key(normalized) is None:
            raise ValueError('SQL objectives need one unambiguous query parameter')
    if kind == 'http_response' and 'expected_status' in value:
        status = value['expected_status']
        if type(status) is not int or not 100 <= status <= 599:
            raise ValueError('Expected status must be an HTTP status code')
    if kind == 'tcp_service' and (type(value.get('port')) is not int or not 1 <= value['port'] <= 65535):
        raise ValueError('TCP objectives require a port between 1 and 65535')
    return normalized


def url_identity(value):
    try:
        p = urlsplit(value)
        return (p.scheme, (p.hostname or '').lower().rstrip('.'), p.port or (443 if p.scheme == 'https' else 80),
                p.path or '/', p.query)
    except ValueError:
        return None


def evidence_match(criterion, execution):
    """Return (applicable, proof), with no inference from an exit code alone."""
    from modules.policy_engine import policy_engine
    try:
        tokens = shlex.split(execution.get('command', ''))
        tool = execution.get('tool')
        if not tokens or tokens[0] != tool:
            return False, ''
        arguments = []
        targets, _, error = policy_engine.scan_arguments(tokens, policy_engine.tool_registry()[tool], arguments)
        if error or len(targets) != 1:
            return False, ''
    except (ValueError, KeyError):
        return False, ''
    output = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', execution.get('stdout') or '')
    if criterion['kind'] == 'http_response' and tool == 'curl':
        # Only header requests without redirects can attribute the status to
        # this exact endpoint. Do not interpret an arbitrary response body.
        header_request = any(t in ('-I', '--head') or (t.startswith('-') and not t.startswith('--') and 'I' in t) for t in tokens[1:])
        redirects = any(t == '--location' or (t.startswith('-') and not t.startswith('--') and 'L' in t) for t in tokens[1:])
        if not header_request or redirects or url_identity(targets[0]) != url_identity(criterion['endpoint']):
            return False, ''
        statuses = re.findall(r'^HTTP/(?:1\.[01]|2|3) ([1-5]\d\d)(?:[^\r\n]*)', output, re.MULTILINE)
        expected = criterion.get('expected_status')
        proof = statuses[-1] if statuses and (expected is None or int(statuses[-1]) == expected) else ''
        return True, f'HTTP status {proof} at {criterion["endpoint"]}' if proof else ''
    if criterion['kind'] == 'tcp_service' and tool == 'nmap':
        if targets[0].lower().rstrip('.') != criterion['endpoint'].lower().rstrip('.'):
            return False, ''
        matches = re.findall(rf'^\s*{criterion["port"]}/tcp\s+open\s+[^\r\n]+', output, re.MULTILINE)
        return True, matches[0].strip() if matches else ''
    return False, ''


def evaluate_generic(criterion, executions, analyzed_phases):
    from modules.outcomes import outcome, SUCCESS
    item = {**criterion, 'label': LABELS[criterion['kind']], 'status': 'pending',
            'reason': 'No applicable analyzed execution is available.', 'evidence': []}
    usable = False
    failed = False
    for execution in executions:
        applicable, proof = evidence_match(criterion, execution)
        if not applicable:
            continue
        complete = execution.get('return_code') is not None
        successful = outcome(execution['tool'], execution.get('return_code'), execution.get('stderr', ''), execution.get('state', '')) in SUCCESS
        if complete and not successful:
            failed = True
        if not successful or execution.get('approved_by_user') is not True or execution.get('phase') not in analyzed_phases:
            continue
        usable = True
        if proof:
            item.update(status='achieved', reason='Confirmed by successful, analyzed scanner output.', evidence=[{
                'execution_id': execution['id'], 'attempt': execution.get('attempt', 1), 'tool': execution['tool'],
                'phase': execution['phase'], 'evidence_sha256': execution.get('evidence_sha256', ''), 'excerpt': proof[:600]}])
            return item
    if failed:
        item.update(status='inconclusive', reason='An applicable execution failed; the objective cannot be established.')
    elif usable:
        item.update(status='not_demonstrated', reason='The completed checks did not establish this objective.')
    return item


def aggregate_status(criteria):
    statuses = {item['status'] for item in criteria}
    return ('not_configured' if not statuses else 'achieved' if statuses == {'achieved'} else
            'inconclusive' if 'inconclusive' in statuses else 'pending' if 'pending' in statuses else 'not_demonstrated')
