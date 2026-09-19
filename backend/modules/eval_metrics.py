"""Exact, auditable ground-truth scoring with explicit coverage assumptions."""
def identity(item):
    return tuple(str(item.get(key, '')).strip().casefold() for key in ('title', 'endpoint', 'parameter'))


def evaluate(findings, truth):
    if isinstance(truth, list) and all(isinstance(item, str) for item in truth):
        expected = {item.strip().casefold() for item in truth if item.strip()}
        observed = {str(f.get('title', '')).strip().casefold() for f in findings}
        matched = expected & observed
        return {'mode': 'exact-title, partial checklist', 'expected': len(expected), 'matched': len(matched),
                'missed': sorted(expected - observed), 'recall': len(matched) / max(1, len(expected)), 'precision': None,
                'note': 'Partial title checklists cannot establish false-positive rates.'}
    expected = {identity(item): item for item in truth.get('findings', [])}
    observed = {identity(item): item for item in findings}
    matches = expected.keys() & observed.keys()
    false_positive = len(observed.keys() - expected.keys()) if truth.get('complete') else None
    verified = [key for key in matches if isinstance(expected[key].get('verified'), bool)]
    correct = sum((observed[key].get('verification') == 'verified') == expected[key]['verified'] for key in verified)
    return {'mode': 'exact title/endpoint/parameter', 'expected': len(expected), 'matched': len(matches),
            'missed': [list(key) for key in expected.keys() - observed.keys()], 'false_positives': false_positive,
            'recall': len(matches) / max(1, len(expected)),
            'precision': len(matches) / max(1, len(observed)) if truth.get('complete') else None,
            'verification_accuracy': correct / len(verified) if verified else None,
            'verification_labeled_count': len(verified)}
