"""Foothold, loot, and host ingestion: turning tool output into campaign state.

The post-exploitation and lateral-movement phases are only as good as what the
framework actually knows: which hosts exist on the engagement, which sessions
are open, which credentials were recovered, and which session can be pivoted
through. This module owns that knowledge.

Everything here is derived from output a tool genuinely printed. Nothing is
inferred, guessed, or synthesised: a parser that does not match produces no
row, so an empty campaign is the honest result of an engagement that found
nothing. That property is what keeps the later phases from acting on fiction.

Secrets are never stored in plaintext. A captured password or hash is written
as a Fernet ciphertext (modules.secret_store) plus a SHA-256 fingerprint of the
plaintext, so the same secret recovered twice deduplicates without the value
itself existing twice in the database.
"""
import hashlib
import re

from database import EngagementHost, Foothold, Loot, utcnow
from modules.secret_store import decrypt_secret, encrypt_value

# Bounds: a long engagement must not grow the campaign tables without limit.
MAX_FOOTHOLDS = 50
MAX_LOOT = 200
MAX_HOSTS = 512
MAX_EVIDENCE_CHARS = 4000

# The marker the SSH foothold step prints so a successful login is
# distinguishable from a banner grab or a refused connection.
FOOTHOLD_MARKER = 'RT-FOOTHOLD'

METERPRETER_TYPES = {'meterpreter'}
SHELL_TYPES = {'shell', 'command shell', 'powershell', 'cmd', 'python', 'php', 'ruby'}

# `sessions -l` rows: id, optional name, type, then the information column
# ("root @ metasploitable") and the connection pair.
MSF_SESSION_ROW_RE = re.compile(
    r'^\s*(?P<sid>\d+)\s+(?P<name>\S*)\s+'
    r'(?P<type>meterpreter|shell|powershell|cmd|python|php|ruby)\b(?P<tail>.*)$',
    re.IGNORECASE)
MSF_SESSION_OPEN_RE = re.compile(
    r'(?P<type>meterpreter|command shell|shell|powershell)\s+session\s+'
    r'(?P<sid>\d+)\s+opened\s*\((?P<connection>[^)]*)\)',
    re.IGNORECASE)
MSF_SESSION_CLOSED_RE = re.compile(
    r'session\s+(?P<sid>\d+)\s+closed', re.IGNORECASE)
MSF_CONNECTION_RE = re.compile(
    r'(?P<lhost>\d{1,3}(?:\.\d{1,3}){3}):(?P<lport>\d+)\s*->\s*'
    r'(?P<rhost>\d{1,3}(?:\.\d{1,3}){3}):(?P<rport>\d+)')
# "root @ metasploitable" / "NT AUTHORITY\SYSTEM @ WIN-DC"
MSF_IDENTITY_RE = re.compile(r'(?P<user>[\w.$\\ -]+?)\s+@\s+(?P<host>[\w.\-]+)')

MSF_CREDS_COLUMNS = ('host', 'origin', 'service', 'public', 'private', 'realm', 'private_type')
# hashdump / secretsdump line: user:uid:lmhash:nthash:::
HASHDUMP_RE = re.compile(
    r'^(?P<user>[^:\s]+):(?P<uid>\d+):(?P<lm>[0-9a-fA-F]{32}):(?P<nt>[0-9a-fA-F]{32}):::')
# /etc/shadow line: user:$1$salt$hash:17000:0:99999:7:::
SHADOW_RE = re.compile(
    r'^(?P<user>[A-Za-z0-9_.\-]+):(?P<hash>\$[0-9a-z]+\$[^:]+):\d+:\d+:\d+')

HYDRA_RE = re.compile(
    r'^\[(?P<port>\d+)\]\[(?P<service>[^\]]+)\]\s+host:\s*(?P<host>\S+)\s+'
    r'login:\s*(?P<login>\S+)\s+password:\s*(?P<password>.*\S)?\s*$', re.MULTILINE)

NXC_RE = re.compile(
    r'^\s*(?:\[[*+-]\]\s*)?(?P<proto>SMB|SSH|LDAP|MSSQL|WINRM|RDP|FTP|VNC|NFS|WMI)\s+'
    r'(?P<host>\S+)\s+(?P<port>\d+)\s+\S*\s*\[\+\]\s*(?P<detail>.+?)\s*$',
    re.IGNORECASE | re.MULTILINE)
NXC_SECRET_RE = re.compile(
    r'(?:(?P<domain>[\w.\-]+)\\)?(?P<user>[^\s:]+):(?P<secret>[^\s(]+)')

NMAP_HOST_RE = re.compile(r'^Nmap scan report for\s+(?P<host>.+?)\s*$', re.MULTILINE)
NMAP_ADDRESS_RE = re.compile(r'^Nmap scan report for\s+(?P<host>[^\s(]+)\s+\((?P<address>[^)]+)\)', re.MULTILINE)
NMAP_BARE_ADDRESS_RE = re.compile(r'^Nmap scan report for\s+(?P<address>\d{1,3}(?:\.\d{1,3}){3})\s*$', re.MULTILINE)

PRIVILEGED_USERS = {'root', 'system', 'nt authority\\system', 'administrator'}


def fingerprint_secret(value):
    """A stable identifier for a plaintext secret, without storing it."""
    return hashlib.sha256((value or '').encode('utf-8', errors='ignore')).hexdigest()[:32]


def _evidence(*parts):
    text = '\n'.join(part for part in parts if part)
    return text[:MAX_EVIDENCE_CHARS]


def _parse_fixed_table(text, columns, minimum_columns=3):
    """Yield dict rows from a column-aligned table whose header names `columns`.

    Metasploit prints tables with the column name at a fixed offset and values
    aligned beneath it, so the header's own offsets are the column boundaries.
    Requiring every expected column to appear in one line makes a data row
    matching by accident effectively impossible.
    """
    lines = text.splitlines()
    for index, line in enumerate(lines):
        found = []
        for name in columns:
            match = re.search(rf'(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])', line, re.IGNORECASE)
            if match:
                found.append((name, match.start()))
        # Older Metasploit releases omit trailing columns; a header is still a
        # header so long as the leading ones are present, and the columns that
        # did appear keep their real offsets.
        if len(found) >= minimum_columns and all(
                found[i][1] < found[i + 1][1] for i in range(len(found) - 1)):
            names = [name for name, _ in found]
            positions = [start for _, start in found]
            for row in lines[index + 1:]:
                if not row.strip():
                    break
                if set(row) <= set('-= 	'):
                    continue
                values = {}
                for offset, (name, start) in enumerate(zip(names, positions)):
                    end = positions[offset + 1] if offset + 1 < len(positions) else None
                    values[name] = (row[start:end] if end else row[start:]).strip()
                yield values
            return


def parse_discovered_hosts(text):
    """Every host an nmap run reported, as {address, hostname}."""
    hosts = {}
    for match in NMAP_ADDRESS_RE.finditer(text or ''):
        hosts[match.group('address')] = match.group('host')
    for match in NMAP_BARE_ADDRESS_RE.finditer(text or ''):
        hosts.setdefault(match.group('address'), '')
    return [{'address': address, 'hostname': hostname} for address, hostname in hosts.items()]


def parse_msf_sessions(text):
    """Open/close/list events from msfconsole output.

    Returns {'opened': [...], 'listed': [...], 'closed': [remote_id, ...]}. A
    `sessions -l` row and an "opened" line describe the same session, so they
    are merged by remote id with the opener preferred for the connection data.
    """
    text = text or ''
    opened, closed = {}, []
    for match in MSF_SESSION_OPEN_RE.finditer(text):
        sid = match.group('sid')
        kind = match.group('type').lower().replace('command ', '')
        connection = match.group('connection')
        target = MSF_CONNECTION_RE.search(connection)
        opened[sid] = {
            'remote_id': sid,
            'kind': 'meterpreter' if kind == 'meterpreter' else kind,
            'host': target.group('rhost') if target else '',
            'username': '',
            'privilege': '',
            'evidence': match.group(0),
            'pivot_ready': kind == 'meterpreter',
        }
    listed = {}
    for row in _parse_fixed_table(text, ('id', 'name', 'type', 'information', 'connection'), minimum_columns=3):
        sid = (row.get('id') or '').strip()
        if not sid.isdigit():
            continue
        kind = (row.get('type') or '').strip().lower()
        if not kind:
            continue
        identity = MSF_IDENTITY_RE.search(row.get('information') or '')
        target = MSF_CONNECTION_RE.search(row.get('connection') or '')
        username = identity.group('user').strip() if identity else ''
        listed[sid] = {
            'remote_id': sid,
            'kind': 'meterpreter' if kind.startswith('meterpreter') else kind.split()[0],
            # The connection address is the actionable one: it is what a later
            # RHOSTS or scope check needs, while the identity host is a name.
            'host': (target.group('rhost') if target else '') or (identity.group('host') if identity else ''),
            'username': username,
            'privilege': username.lower() if username.lower() in PRIVILEGED_USERS else '',
            'evidence': ' | '.join(filter(None, [row.get('type'), row.get('information'), row.get('connection')])),
            'pivot_ready': kind.startswith('meterpreter'),
        }
    for match in MSF_SESSION_CLOSED_RE.finditer(text):
        closed.append(match.group('sid'))
    merged = dict(listed)
    merged.update(opened)
    return {'opened': list(merged.values()), 'closed': closed}


def parse_msf_credentials(text):
    """Credentials from the `creds` table, hashdump, and /etc/shadow output."""
    found = []
    for row in _parse_fixed_table(text or '', MSF_CREDS_COLUMNS):
        secret = (row.get('private') or '').strip()
        if not secret:
            continue
        service = (row.get('service') or '').strip()
        private_type = (row.get('private_type') or '').strip().lower()
        found.append({
            'host': (row.get('host') or '').strip(),
            'service': re.sub(r'\s*\(.*\)', '', service).strip(),
            'username': (row.get('public') or '').strip(),
            'secret': secret,
            'secret_kind': 'hash' if 'hash' in private_type or re.fullmatch(r'[0-9a-fA-F]{32}', secret) else 'password',
            'validated': False,
            'notes': private_type,
        })
    for line in (text or '').splitlines():
        line = line.strip()
        if match := HASHDUMP_RE.match(line):
            hashes = f"{match.group('lm')}:{match.group('nt')}"
            found.append({
                'host': '', 'service': 'smb', 'username': match.group('user'),
                'secret': hashes, 'secret_kind': 'hash', 'validated': False,
                'notes': 'NTLM hash pair (LM:NT) from hashdump',
            })
        elif match := SHADOW_RE.match(line):
            found.append({
                'host': '', 'service': 'shadow', 'username': match.group('user'),
                'secret': match.group('hash'), 'secret_kind': 'hash', 'validated': False,
                'notes': 'crypt(3) password hash from /etc/shadow',
            })
    return found


def parse_hydra(text):
    return [{
        'host': match.group('host'),
        'service': match.group('service').lower(),
        'username': match.group('login'),
        'secret': match.group('password') or '',
        'secret_kind': 'password',
        'validated': True,
        'notes': f'hydra confirmed login on port {match.group("port")}',
    } for match in HYDRA_RE.finditer(text or '')]


def parse_netexec(text):
    found = []
    for match in NXC_RE.finditer(text or ''):
        detail = match.group('detail')
        credential = NXC_SECRET_RE.search(detail)
        if not credential:
            continue
        secret = credential.group('secret')
        if not secret or secret.startswith('['):
            continue
        user = credential.group('user')
        if credential.group('domain'):
            user = f"{credential.group('domain')}\\{user}"
        found.append({
            'host': match.group('host'),
            'service': match.group('proto').lower(),
            'username': user,
            'secret': secret,
            'secret_kind': 'hash' if re.fullmatch(r'[0-9a-fA-F]{32}', secret) else 'password',
            'validated': 'pwn3d' in detail.lower(),
            'notes': 'validated administrator access' if 'pwn3d' in detail.lower() else '',
        })
    return found


def parse_ssh_foothold(command, stdout, return_code):
    """An SSH login this framework performed itself, proven by its marker."""
    if return_code != 0 or FOOTHOLD_MARKER not in (stdout or ''):
        return None
    host, username = '', ''
    if pair := re.search(r'(?P<user>[\w.\-]+)@(?P<host>[\w.\-]+)', command or ''):
        username, host = pair.group('user'), pair.group('host')
    elif match := re.search(r'(?:(?<=^)|(?<=\s))(?P<host>\d{1,3}(?:\.\d{1,3}){3})(?=\s|$)', command or ''):
        host = match.group('host')
    privilege = 'root' if re.search(r'uid=0\b', stdout or '') else ''
    return {
        'remote_id': '', 'kind': 'ssh', 'host': host, 'username': username,
        'privilege': privilege, 'pivot_ready': True,
        'evidence': _evidence(command, stdout),
    }


def extract_evidence(tool, command, stdout, stderr, return_code):
    """Everything one finished execution proves about the campaign.

    Returns a dict with 'footholds', 'loot', and 'hosts' lists. A tool with no
    parser contributes nothing, so unknown output can never invent campaign
    state.
    """
    output = f'{stdout or ""}\n{stderr or ""}'
    result = {'footholds': [], 'loot': [], 'hosts': []}
    tool = (tool or '').lower()

    if tool == 'nmap':
        result['hosts'] = parse_discovered_hosts(stdout or '')
        return result

    if tool == 'msfconsole':
        sessions = parse_msf_sessions(output)
        result['footholds'] = sessions['opened']
        result['loot'] = parse_msf_credentials(output)
        result['hosts'] = [
            {'address': foothold['host'], 'hostname': ''}
            for foothold in sessions['opened'] if foothold.get('host')
        ]
        return result

    if tool == 'hydra':
        result['loot'] = parse_hydra(output)
        result['hosts'] = [{'address': item['host'], 'hostname': ''} for item in result['loot']]
        return result

    if tool == 'nxc':
        result['loot'] = parse_netexec(output)
        result['hosts'] = [{'address': item['host'], 'hostname': ''} for item in result['loot']]
        return result

    if tool == 'ssh':
        if foothold := parse_ssh_foothold(command, stdout, return_code):
            result['footholds'] = [foothold]
            if foothold.get('host'):
                result['hosts'] = [{'address': foothold['host'], 'hostname': ''}]
        return result

    return result


def _upsert_host(db, assessment_id, address, hostname='', role='discovered'):
    address = (address or '').strip()
    if not address:
        return None
    row = db.query(EngagementHost).filter_by(assessment_id=assessment_id, address=address).first()
    if row is None:
        if db.query(EngagementHost).filter_by(assessment_id=assessment_id).count() >= MAX_HOSTS:
            return None
        row = EngagementHost(assessment_id=assessment_id, address=address, hostname=hostname, role=role)
        db.add(row)
        db.flush()
        return row
    if hostname and not row.hostname:
        row.hostname = hostname
    if role == 'owned':
        row.role = 'owned'
        row.state = 'owned'
    return row


def ingest_execution(db, assessment_id, execution):
    """Persist everything one finished execution proves. Returns a summary.

    Idempotent: re-running the same evidence updates the existing row instead of
    duplicating it, which matters because a failed step can be retried and the
    same session list is then parsed twice.
    """
    summary = {'footholds': 0, 'closed': 0, 'loot': 0, 'hosts': 0}
    if execution is None or execution.return_code is None:
        return summary
    from modules.evidence import original
    raw = original(execution)
    evidence = extract_evidence(
        execution.tool_name, raw['command'], raw['stdout'], raw['stderr'],
        execution.return_code if execution.return_code is not None else 0)
    if not any(evidence.values()):
        return summary

    for host in evidence['hosts']:
        if _upsert_host(db, assessment_id, host.get('address'), host.get('hostname')):
            summary['hosts'] += 1

    for item in evidence['footholds']:
        if not item.get('host'):
            continue
        row = db.query(Foothold).filter_by(
            assessment_id=assessment_id, host=item['host'],
            kind=item.get('kind', 'session'), remote_id=item.get('remote_id', '')).first()
        if row is None:
            if db.query(Foothold).filter_by(assessment_id=assessment_id).count() >= MAX_FOOTHOLDS:
                continue
            row = Foothold(assessment_id=assessment_id, host=item['host'],
                           kind=item.get('kind', 'session'), remote_id=item.get('remote_id', ''))
            db.add(row)
            summary['footholds'] += 1
        row.username = item.get('username') or row.username or ''
        row.privilege = item.get('privilege') or row.privilege or ''
        row.pivot_ready = bool(item.get('pivot_ready')) or bool(row.pivot_ready)
        row.state = 'open'
        row.source_tool = execution.tool_name
        row.source_execution_id = execution.id
        row.evidence = _evidence(item.get('evidence'), row.evidence)
        row.last_seen_at = utcnow()
        _upsert_host(db, assessment_id, item['host'], '', 'owned')

    if tool_sessions := parse_msf_sessions(f'{raw["stdout"]}\n{raw["stderr"]}'):
        for remote_id in tool_sessions['closed']:
            row = db.query(Foothold).filter_by(
                assessment_id=assessment_id, remote_id=remote_id, state='open').first()
            if row:
                row.state = 'closed'
                row.closed_at = utcnow()
                summary['closed'] += 1

    for item in evidence['loot']:
        host = item.get('host') or ''
        if not host:
            # hashdump/shadow lines carry no host of their own; attribute them
            # to the session the command ran on when there is exactly one.
            open_footholds = db.query(Foothold).filter_by(assessment_id=assessment_id, state='open').all()
            if len(open_footholds) == 1:
                host = open_footholds[0].host
        secret = item.get('secret') or ''
        fingerprint = fingerprint_secret(secret)
        row = db.query(Loot).filter_by(
            assessment_id=assessment_id, host=host, service=item.get('service', ''),
            username=item.get('username', ''), secret_kind=item.get('secret_kind', 'password'),
            secret_fingerprint=fingerprint).first()
        if row is None:
            if db.query(Loot).filter_by(assessment_id=assessment_id).count() >= MAX_LOOT:
                continue
            row = Loot(assessment_id=assessment_id, host=host, service=item.get('service', ''),
                       username=item.get('username', ''), secret_kind=item.get('secret_kind', 'password'),
                       secret_fingerprint=fingerprint)
            db.add(row)
            summary['loot'] += 1
        if secret:
            row.secret_encrypted = encrypt_value(secret)
        row.validated = bool(item.get('validated')) or bool(row.validated)
        row.notes = _evidence(item.get('notes'), row.notes)[:1000]
        row.source_tool = execution.tool_name
        row.source_execution_id = execution.id

    db.flush()
    return summary


def footholds_for(db, assessment_id, state='open'):
    query = db.query(Foothold).filter_by(assessment_id=assessment_id)
    if state:
        query = query.filter_by(state=state)
    return query.order_by(Foothold.id).all()


def loot_for(db, assessment_id):
    return db.query(Loot).filter_by(assessment_id=assessment_id).order_by(Loot.id).all()


def hosts_for(db, assessment_id):
    return db.query(EngagementHost).filter_by(assessment_id=assessment_id).order_by(EngagementHost.address).all()


def serialize_foothold(row):
    return {
        'id': row.id,
        'host': row.host,
        'kind': row.kind,
        'remote_id': row.remote_id,
        'username': row.username,
        'privilege': row.privilege,
        'state': row.state,
        'pivot_ready': bool(row.pivot_ready),
        'source_tool': row.source_tool,
        'source_execution_id': row.source_execution_id,
        'evidence': row.evidence,
        'opened_at': row.opened_at.isoformat() if row.opened_at else None,
        'closed_at': row.closed_at.isoformat() if row.closed_at else None,
    }


def serialize_loot(row):
    """A loot row as the list view shows it: never the plaintext."""
    return {
        'id': row.id,
        'host': row.host,
        'service': row.service,
        'username': row.username,
        'secret_kind': row.secret_kind,
        'secret_masked': f'<encrypted:{row.secret_fingerprint[:8]}>',
        'fingerprint': row.secret_fingerprint,
        'validated': bool(row.validated),
        'source_tool': row.source_tool,
        'source_execution_id': row.source_execution_id,
        'notes': row.notes,
        'has_secret': bool(row.secret_encrypted),
    }


def serialize_host(row):
    return {
        'id': row.id,
        'address': row.address,
        'hostname': row.hostname,
        'role': row.role,
        'os_name': row.os_name,
        'state': row.state,
        'child_assessment_id': row.child_assessment_id,
        'notes': row.notes,
    }


def reveal_secret(row):
    """Decrypt one loot value. Callers must audit that this happened."""
    from modules.secret_store import decrypt_required
    return decrypt_required(row.secret_encrypted)
