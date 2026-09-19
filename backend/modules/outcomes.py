"""Scanner exit codes describe both findings and process failures."""
SUCCESS = {'completed', 'completed_with_findings'}


def outcome(tool, code, stderr='', state=''):
    if state in {'cancelled', 'interrupted', 'timed_out'}:
        return state
    if code is None:
        return state if state in {'queued', 'running'} else 'running'
    if 'timed out' in (stderr or '').lower():
        return 'timed_out'
    if tool == 'zap-baseline.py' and code in (1, 2):
        return 'completed_with_findings'
    return 'completed' if code == 0 else 'failed'
