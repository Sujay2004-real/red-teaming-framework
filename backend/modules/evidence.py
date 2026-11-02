"""Encrypted originals, public redaction and legacy evidence adoption.

Raw output is available only to internal parsers and audited reveal routes.
Redaction recognizes supported credential formats and known recovered values;
it is not a general classifier for every possible secret in arbitrary text.
"""
import hashlib
import html
import json
import re
from pathlib import Path
from urllib.parse import quote
from sqlalchemy import inspect
from modules.secret_store import encrypt_secret, decrypt_required

MASK = '[REDACTED]'
RAW_FIELDS = ('command', 'stdout', 'stderr')
STRUCTURAL_KEYS = {'tool', 'tool_name', 'phase', 'state', 'status', 'fingerprint', 'id', 'source_tools',
                   'verification', 'secret_kind', 'host', 'address', 'username', 'service', 'analyzed_phases', 'verified_by'}
PUBLIC_TEXT_FIELDS = {
    'Assessment': {'objective', 'plan', 'engagement_brief', 'analysis_metadata', 'autopilot_state'},
    'ToolExecution': set(),  # protect_execution handles the original/projection pair.
    'ExecutionAttempt': {'snapshot'}, 'Finding': {'title', 'description', 'evidence', 'remediation', 'exploit_evidence'},
    'FindingReview': {'justification', 'comments', 'retest_evidence'}, 'Foothold': {'evidence'}, 'Loot': {'notes'},
    'EngagementHost': {'notes'}, 'Recommendation': {'payload'}, 'ReportVersion': {'provenance'},
}
# Structured JSON, key=value, headers, scanner messages and URL credentials.
LABELED = re.compile(r'''(?i)(["']?(?:password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|(?:access[_-]?|refresh[_-]?)?token|authorization|cookie|set-cookie)["']?\s*[:=]\s*)("(?:\\.|[^"\\])*"|'[^']*'|[^\s"'<,;}&]+)''')
HEADERS = re.compile(r'(?im)^((?:authorization|cookie|set-cookie)\s*:\s*)[^\r\n]*')
PRIVATE_KEY = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)', re.S)
URL_SECRET = re.compile(r'(://[^\s/@:]+:)[^\s/@]+(@)')


def credential_values(text):
    from modules.footholds import parse_msf_credentials, parse_hydra, parse_netexec
    items = parse_msf_credentials(text) + parse_hydra(text) + parse_netexec(text)
    values = {item.get('secret') for item in items if item.get('secret')}
    # A hash pair must also be masked when a tool echoes just one half.
    for value in list(values):
        if re.fullmatch(r'[0-9a-fA-F]{32}:[0-9a-fA-F]{32}', value):
            values.update(value.split(':'))
    return values


def redact(value, secrets=()):
    if isinstance(value, list):
        return [redact(item, secrets) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item, secrets) for item in value)
    if isinstance(value, dict):
        return {key: item if key in STRUCTURAL_KEYS else redact(item, secrets) for key, item in value.items()}
    if not isinstance(value, str) or not value:
        return value
    values = set(secrets) | credential_values(value)
    variants = set()
    for secret in values:
        variants.update((secret, html.escape(secret), quote(secret, safe=''), json.dumps(secret)[1:-1]))
    for secret in sorted(variants - {''}, key=len, reverse=True):
        value = value.replace(secret, MASK)
    value = PRIVATE_KEY.sub(MASK, value)
    value = HEADERS.sub(lambda match: match[1] + MASK, value)
    def label(match):
        token = match[2].strip().strip('\"\'')
        if re.fullmatch(r'\$\$loot:\d+\$\$', token):
            return match[0]
        quoted = match[2][0] if match[2][0] in ('\"', "'") else ''
        return match[1] + quoted + MASK + quoted
    value = LABELED.sub(label, value)
    return URL_SECRET.sub(lambda match: match[0] if re.search(r':\$\$loot:\d+\$\$@$', match[0])
                          else match[1] + MASK + match[2], value)


def seal(payload):
    # JSON wrapping prevents plaintext beginning "enc:v1:" from bypassing
    # encryption via the legacy settings helper's pass-through behavior.
    return encrypt_secret(json.dumps(payload, ensure_ascii=False))


def unseal(ciphertext):
    payload = json.loads(decrypt_required(ciphertext))
    if not isinstance(payload, dict):
        raise ValueError('Invalid protected evidence')
    return payload


def original(execution):
    if getattr(execution, 'raw_encrypted', ''):
        return unseal(execution.raw_encrypted)
    return {key: getattr(execution, key, '') or '' for key in RAW_FIELDS}


def evidence_digest(payload):
    return hashlib.sha256(json.dumps([payload.get('stdout', ''), payload.get('stderr', '')], ensure_ascii=False).encode()).hexdigest()


def protect_execution(execution, secrets=()):
    raw = original(execution)
    state = inspect(execution)
    projection = getattr(execution, '_protected_projection', {})
    for key in RAW_FIELDS:
        if state.attrs[key].history.has_changes() and getattr(execution, key) != projection.get(key):
            raw[key] = getattr(execution, key) or ''
    values = set(secrets) | credential_values(raw.get('stdout', '') + '\n' + raw.get('stderr', ''))
    execution.raw_encrypted = seal(raw)
    execution.evidence_sha256 = evidence_digest(raw)
    for key in RAW_FIELDS:
        setattr(execution, key, redact(raw.get(key, ''), values))
    execution._protected_projection = {key: getattr(execution, key) for key in RAW_FIELDS}
    execution.live_output = redact(execution.live_output or '', values)
    return values


def known_secrets(db, assessment_id):
    from database import Loot
    return {decrypt_required(row.secret_encrypted) for row in db.query(Loot).filter_by(assessment_id=assessment_id)
            if row.secret_encrypted}


def protect_pending(db):
    """Defense at the persistence boundary, including imports and worker writes."""
    from database import Assessment, ToolExecution, ExecutionAttempt, Finding, FindingReview, Foothold, Loot, EngagementHost, Recommendation, ReportVersion
    supported = (Assessment, ToolExecution, ExecutionAttempt, Finding, FindingReview, Foothold, Loot, EngagementHost, Recommendation, ReportVersion)
    pending = [row for row in set(db.new) | set(db.dirty) if isinstance(row, supported)]
    cache = {}
    for row in pending:
        aid = row.id if isinstance(row, Assessment) else row.assessment_id
        if aid not in cache:
            cache[aid] = known_secrets(db, aid) if aid else set()
        if isinstance(row, ToolExecution):
            cache[aid].update(protect_execution(row, cache[aid]))
    for row in pending:
        aid = row.id if isinstance(row, Assessment) else row.assessment_id
        if isinstance(row, Assessment) and row.plan and cache[aid]:
            from modules.planners import resolve_references
            loot = db.query(Loot).filter_by(assessment_id=aid).all()
            row.plan = [{**step, 'command': resolve_references(step.get('command', ''), loot)[1]} for step in row.plan]
        for attr in inspect(row).mapper.column_attrs:
            if attr.key in PUBLIC_TEXT_FIELDS[type(row).__name__]:
                value = getattr(row, attr.key)
                if isinstance(row, Assessment) and attr.key == 'plan' and isinstance(value, list):
                    # Commands are executable source. Known recovered values
                    # were replaced by resolvable loot references above. Do
                    # not change probe payloads into different commands.
                    safe = [{**redact(step, cache[aid]), 'command': step.get('command', '')} for step in value]
                else:
                    safe = redact(value, cache[aid])
                if safe != value:
                    setattr(row, attr.key, safe)


def backfill_evidence(sessions, reports_dir=Path('./data/reports')):
    """Adopt old evidence once, before serving requests or starting workers.

    Old reports are retired, preserved encrypted with their original digest,
    and removed from public files after the transaction commits. Regeneration
    creates a new redacted version; old digests are never silently rewritten.
    """
    from database import Assessment, ToolExecution, ExecutionAttempt, Finding, FindingReview, Foothold, Loot, EngagementHost, Recommendation, ReportVersion
    from sqlalchemy.orm.attributes import flag_dirty
    with sessions() as db:
        for assessment in db.query(Assessment).filter_by(evidence_protected=False).all():
            secrets = known_secrets(db, assessment.id)
            executions = db.query(ToolExecution).filter_by(assessment_id=assessment.id).all()
            for row in executions:
                secrets.update(credential_values(row.stdout or ''))
                secrets.update(credential_values(row.stderr or ''))
            for row in executions:
                protect_execution(row, secrets)
            for row in db.query(ExecutionAttempt).filter_by(assessment_id=assessment.id):
                raw = {key: (row.snapshot or {}).get(key, '') for key in RAW_FIELDS}
                if not row.raw_encrypted:
                    row.raw_encrypted, row.evidence_sha256 = seal(raw), evidence_digest(raw)
                row.snapshot = redact(row.snapshot, secrets)
            for model in (Finding, FindingReview, Foothold, Loot, EngagementHost, Recommendation):
                for row in db.query(model).filter_by(assessment_id=assessment.id):
                    for attr in inspect(row).mapper.column_attrs:
                        if attr.key in PUBLIC_TEXT_FIELDS[type(row).__name__]:
                            value = getattr(row, attr.key)
                            safe = redact(value, secrets)
                            if value != safe:
                                setattr(row, attr.key, safe)
            current = reports_dir / f'report_{assessment.id}.html'
            versions = db.query(ReportVersion).filter_by(assessment_id=assessment.id).all()
            if current.is_file() and not any(Path(v.path) == current for v in versions):
                versions.append(ReportVersion(assessment_id=assessment.id, path=str(current),
                    digest=hashlib.sha256(current.read_bytes()).hexdigest(), restricted=True))
            for row in versions:
                if not row.raw_encrypted and Path(row.path).is_file():
                    import base64
                    row.raw_encrypted = seal({'content_base64': base64.b64encode(Path(row.path).read_bytes()).decode()})
                row.restricted = True
                row.provenance = redact(row.provenance or {}, secrets)
                db.add(row)
            from modules.planners import resolve_references
            loot = db.query(Loot).filter_by(assessment_id=assessment.id).all()
            assessment.plan = [{**redact(step, secrets), 'command': resolve_references(step.get('command', ''), loot)[1]}
                               for step in (assessment.plan or [])]
            assessment.objective = redact(assessment.objective, secrets)
            assessment.engagement_brief = redact(assessment.engagement_brief, secrets)
            assessment.current_report_version_id = None
            if assessment.status == 'reported':
                assessment.status = 'analyzed'
            assessment.evidence_protected = True
            flag_dirty(assessment)
        db.commit()
        # Retried on every startup if an earlier filesystem cleanup failed.
        for row in db.query(ReportVersion).filter_by(restricted=True):
            if row.raw_encrypted:
                unseal(row.raw_encrypted)  # Never erase a file without a readable original.
                if not db.query(ReportVersion.id).filter_by(path=row.path, restricted=False).first():
                    Path(row.path).unlink(missing_ok=True)
