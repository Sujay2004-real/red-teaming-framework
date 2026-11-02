"""Deterministic planners for the post-compromise kill chain.

Where the recon planner drafts from the target alone and the exploit planner
drafts from the previous phase's findings, these planners draft from what the
engagement has actually *obtained*: recovered credentials, open footholds, and
the hosts enumeration discovered. The kill chain is strictly sequential, so a
credential-validation step can only exist because post-exploitation actually
recovered a credential, and a lateral-movement step can only exist because a
credential was actually proven to work.

Secrets never enter the plan or the audit trail. A planner writes a
placeholder - $$loot:12$$ or $$foothold:3$$ - and the execute path resolves it
to the real value only at the moment the command runs (resolve_references),
validating and executing the concrete form while persisting the masked one.

Every drafted step is validated through the policy engine before it is
returned, so a bug here can produce a useless step but never an unreviewed or
out-of-scope command: fail-closed, exactly like the other planners.
"""

import re
import shlex
from urllib.parse import urlsplit

from modules.phases import preceding_plan_phase
from modules.policy_engine import (
    SESSION_AGGRESSIVE_COMMANDS, SESSION_SAFE_COMMANDS,
    policy_engine,
)

# Caps. A credential-rich engagement must not turn one phase into hundreds of
# near-identical steps, and every step still costs a human approval.
MAX_CREDENTIAL_STEPS = 6
MAX_FOOTHOLD_STEPS = 4
MAX_POST_STEPS = 8
MAX_LATERAL_STEPS = 6
MAX_IMPACT_STEPS = 6
# Session commands proposed per open session. Enough to characterise the host,
# small enough to review in one pass.
MAX_SESSION_COMMANDS = 3

LOOT_REFERENCE_RE = re.compile(r'\$\$loot:(?P<id>\d+)\$\$')
FOOTHOLD_REFERENCE_RE = re.compile(r'\$\$foothold:(?P<id>\d+)\$\$')

# Services a recovered credential can be replayed against, mapped to the
# hydra URI scheme that speaks them.
HYDRA_SCHEMES = {
    'ssh': 'ssh', 'ftp': 'ftp', 'smb': 'smb', 'cifs': 'smb', 'netbios': 'smb',
    'rdp': 'rdp', 'mssql': 'mssql', 'mysql': 'mysql', 'vnc': 'vnc',
    'telnet': 'telnet', 'smtp': 'smtp', 'imap': 'imap', 'pop3': 'pop3',
    'postgres': 'postgres', 'postgresql': 'postgres', 'http': 'http', 'https': 'https',
}
NXC_PROTOCOLS = ('smb', 'winrm', 'ldap', 'ssh', 'mssql', 'rdp', 'ftp', 'vnc', 'wmi')
# A credential that names one of these is a hash, not a password: nxc takes it
# through -H, and it is what Windows remote execution actually needs.
HASH_KINDS = {'ntlm', 'hash', 'nthash', 'lm', 'lmhash'}
# Services whose credential can open a remote session on a Windows host.
REMOTE_EXEC_SERVICES = ('smb', 'cifs', 'netbios', 'winrm', 'mssql', 'rdp', 'wmi')


def loot_reference(loot_id):
    """The masked token a planner writes instead of a recovered secret."""
    return '$$loot:' + str(loot_id) + '$$'


def foothold_reference(foothold_id):
    """The masked token a planner writes instead of a session id."""
    return '$$foothold:' + str(foothold_id) + '$$'


def resolve_references(command, loot_rows=(), footholds=()):
    """Resolve planner placeholders into the command an executor actually runs.

    Returns (concrete, masked):

    * masked - the command with every *plaintext secret the framework knows*
      replaced by its placeholder. A planner-authored command already carries
      placeholders, so for those this is the input unchanged; for an
      operator-authored command that reached the plan carrying a literal
      secret, this is what makes the stored plan and the audit trail safe.
    * concrete - the masked command with every placeholder expanded to the real
      value (shell-quoted so it survives shlex.split as one argument) and every
      $$foothold:<id>$$ expanded to the foothold's remote id. This is the form
      that is policy-validated and executed.

    A reference that cannot be resolved (the row is gone, the ciphertext is
    unreadable, the value is empty) is left as its placeholder rather than
    silently dropped, so the command fails loudly instead of running with a
    hole in it.
    """
    command = command or ''
    loot_by_id = {row.id: row for row in loot_rows}
    footholds_by_id = {row.id: row for row in footholds}

    # Mask literal secrets first, so the executed form is derived from the
    # masked form and the two can never disagree about which spans are secret.
    # A row this command already references by placeholder is skipped: its value
    # is expanded below, and masking a coincidental literal elsewhere (a
    # username that happens to equal the password) would only garble the plan.
    referenced = {int(match.group('id')) for match in LOOT_REFERENCE_RE.finditer(command)}
    masked = command
    for row in loot_rows:
        if row.id in referenced:
            continue
        value = _reveal(row)
        if value and value in masked:
            masked = masked.replace(value, loot_reference(row.id))

    resolutions = {}
    for match in LOOT_REFERENCE_RE.finditer(masked):
        loot_id = int(match.group('id'))
        if loot_id in resolutions:
            continue
        row = loot_by_id.get(loot_id)
        value = _reveal(row) if row is not None else ''
        # A secret that carries whitespace or shell metacharacters is quoted so
        # the concrete command still tokenizes to the argument the tool expects.
        resolutions[loot_id] = shlex.quote(value) if value else match.group(0)

    def _loot_value(match):
        return resolutions.get(int(match.group('id')), match.group(0))

    def _foothold_value(match):
        row = footholds_by_id.get(int(match.group('id')))
        if row is None:
            return match.group(0)
        return str(row.remote_id or row.host or '') or match.group(0)

    concrete = LOOT_REFERENCE_RE.sub(_loot_value, masked)
    concrete = FOOTHOLD_REFERENCE_RE.sub(_foothold_value, concrete)
    return concrete, masked


def _reveal(row):
    """Decrypt one loot value, tolerating an absent or unreadable ciphertext."""
    if row is None:
        return ''
    from modules.footholds import reveal_secret
    try:
        return reveal_secret(row) or ''
    except Exception:
        return ''


def command_proves_endpoint(command, endpoint):
    """True when a command names the host an endpoint lives on.

    Used to tie a campaign step back to the finding that motivated it, so the
    report can show which evidence a follow-up act was built from instead of
    listing it free of provenance.
    """
    endpoint = str(endpoint or '').strip()
    if not endpoint:
        return False
    try:
        tokens = [token for token in re.split(r'[\s,=]+', str(command or '')) if token]
    except TypeError:
        return False
    host = _endpoint_host(endpoint)
    if not host:
        return False
    return any(_endpoint_host(token) == host for token in tokens)


def _endpoint_host(value):
    value = str(value or '').strip()
    if not value:
        return ''
    if '://' not in value:
        value = '//' + value.lstrip('/')
    try:
        return (urlsplit(value).hostname or '').strip('[]').lower().rstrip('.')
    except ValueError:
        return ''


def _step(tool, command, reason, phase):
    return {'tool': tool, 'command': command, 'reason': reason, 'enabled': True, 'phase': phase}


def _nxc_protocol(service):
    service = (service or '').lower()
    for protocol in NXC_PROTOCOLS:
        if protocol in service:
            return protocol
    return 'smb'


def _hydra_scheme(service):
    service = (service or '').lower()
    for name, scheme in HYDRA_SCHEMES.items():
        if name in service:
            return scheme
    return ''


def _usable_loot(loot):
    """Loot worth acting on: a secret we hold, keyed to a host and a user."""
    return [row for row in loot
            if row.get('has_secret') and row.get('host') and row.get('username')]


def _secret_flag(row):
    return '-H' if str(row.get('secret_kind') or '').lower() in HASH_KINDS else '-p'


def _secret_placeholder(row):
    return loot_reference(row.get('id'))


def draft_credential_validation_plan(loot, target, authorized_scopes, aggressive=False):
    """Prove that each recovered credential actually authenticates.

    Recovery is not proof: a hashdump line or a cracked password only becomes
    evidence once a service accepts it. Each step re-uses the credential the
    engagement already holds, through a read-only check, and the tool's own
    output is what marks the loot validated.
    """
    steps, notes = [], []
    if not aggressive:
        return [], ['Credential validation runs only in aggressive lab mode.']
    candidates = _usable_loot(loot)
    if not candidates:
        return [], ['No recovered credential with a host and a username is available to validate.']

    for row in candidates:
        if len(steps) >= MAX_CREDENTIAL_STEPS:
            notes.append('Only the first ' + str(MAX_CREDENTIAL_STEPS) + ' credential checks were drafted; '
                         + str(len(candidates) - MAX_CREDENTIAL_STEPS) + ' more recovered credential(s) remain.')
            break
        host, user, secret = row['host'], row['username'], _secret_placeholder(row)
        service = row.get('service') or ''
        scheme = _hydra_scheme(service)
        if scheme:
            command = 'hydra -l ' + user + ' -p ' + secret + ' -f -t 4 ' + scheme + '://' + host
            valid, _, _ = policy_engine.validate_command(command, authorized_scopes,
                                                         expected_tool='hydra', aggressive=True)
            if valid:
                steps.append(_step('hydra', command,
                                   'Prove the recovered ' + (service or 'service') + ' credential for ' + user
                                   + ' on ' + host + ' authenticates; stop at the first accepted login.',
                                   'credential_validation'))
                continue
        protocol = _nxc_protocol(service)
        command = ('nxc ' + protocol + ' ' + host + ' -u ' + user + ' ' + _secret_flag(row) + ' '
                   + secret + ' --shares --no-bruteforce')
        valid, _, _ = policy_engine.validate_command(command, authorized_scopes,
                                                     expected_tool='nxc', aggressive=True)
        if valid:
            steps.append(_step('nxc', command,
                               'Validate the recovered ' + (service or protocol) + ' credential for ' + user
                               + ' on ' + host + ' and list the shares it can reach.', 'credential_validation'))

    if not steps:
        notes.append('No recovered credential could be turned into a policy-legal validation step.')
    return steps, notes


def draft_foothold_plan(loot, footholds, target, authorized_scopes, aggressive=False):
    """Turn a validated credential into a foothold the later phases can use.

    Only a credential the framework has proven (validated) qualifies, and only
    against a service that actually grants remote execution. The step is
    non-interactive by construction: it runs one bounded command and exits, so
    a bad credential costs a timeout, not a hung console.
    """
    steps, notes = [], []
    if not aggressive:
        return [], ['Foothold acquisition from recovered credentials runs only in aggressive lab mode.']
    have_session = {row['host'] for row in footholds if row.get('state') == 'open'}
    candidates = [row for row in loot
                  if row.get('validated') and row.get('host') and row.get('username')
                  and any(name in str(row.get('service') or '').lower() for name in REMOTE_EXEC_SERVICES)]
    if not candidates:
        return [], ['No validated credential for a remote-execution service is available yet.']

    for row in candidates:
        if len(steps) >= MAX_FOOTHOLD_STEPS:
            notes.append('Only the first ' + str(MAX_FOOTHOLD_STEPS) + ' foothold steps were drafted.')
            break
        host, user = row['host'], row['username']
        if host in have_session:
            continue
        secret = _secret_placeholder(row)
        if _secret_flag(row) == '-H':
            command = 'impacket-wmiexec -hashes ' + secret + ' ' + user + '@' + host + ' whoami'
        else:
            command = 'impacket-wmiexec ' + user + ':' + secret + '@' + host + ' whoami'
        valid, _, _ = policy_engine.validate_command(command, authorized_scopes,
                                                     expected_tool='impacket-wmiexec', aggressive=True)
        if valid:
            steps.append(_step('impacket-wmiexec', command,
                               'Open a non-interactive remote execution channel on ' + host + ' as ' + user
                               + ' and prove it with whoami.', 'lateral_movement'))
    if not steps and not notes:
        notes.append('Every host with a validated credential already has an open foothold.')
    return steps, notes


def post_exploitation_steps(footholds, loot, hosts, target, authorized_scopes, aggressive=False):
    """Enumerate through the footholds the exploitation phase opened.

    Metasploit session listing is read-only and always available once the
    letter authorizes exploitation; running a bounded command on a session, and
    the protocol clients that act on a recovered credential, are the
    post-exploitation primitive and stay lab-gated.
    """
    steps, notes = [], []
    if not aggressive:
        return [], ['Post-exploitation enumeration through a foothold runs only in aggressive lab mode.']

    open_footholds = [row for row in footholds if row.get('state') == 'open']
    if open_footholds:
        command = 'msfconsole -q -x "sessions -l; exit"'
        valid, _, _ = policy_engine.validate_command(command, authorized_scopes,
                                                     expected_tool='msfconsole', aggressive=True)
        if valid:
            steps.append(_step('msfconsole', command,
                               'List the Metasploit sessions the exploitation phase opened before '
                               'acting on any of them.', 'post_exploitation'))

    session_commands = list(SESSION_SAFE_COMMANDS) + list(SESSION_AGGRESSIVE_COMMANDS)
    for row in open_footholds:
        if row.get('kind') != 'session' or not str(row.get('remote_id') or '').isdigit():
            continue
        # The session id is not a secret, and the msf script validator needs a
        # literal digit for -i, so it is written concretely rather than masked.
        session = str(row['remote_id'])
        for session_command in session_commands[:MAX_SESSION_COMMANDS]:
            command = ('msfconsole -q -x "sessions -C \'' + session_command + '\' -i ' + session + '; exit"')
            valid, _, _ = policy_engine.validate_command(command, authorized_scopes,
                                                         expected_tool='msfconsole', aggressive=True)
            if valid:
                steps.append(_step('msfconsole', command,
                                   'Run "' + session_command + '" on session ' + str(row.get('remote_id'))
                                   + ' (' + str(row.get('host')) + ') as bounded post-exploitation evidence.',
                                   'post_exploitation'))
            if len(steps) >= MAX_POST_STEPS:
                break
        if len(steps) >= MAX_POST_STEPS:
            break

    for row in _usable_loot(loot):
        if len(steps) >= MAX_POST_STEPS:
            break
        host = row['host']
        protocol = _nxc_protocol(row.get('service'))
        command = ('nxc ' + protocol + ' ' + host + ' -u ' + row['username'] + ' ' + _secret_flag(row)
                   + ' ' + _secret_placeholder(row) + ' --shares')
        valid, _, _ = policy_engine.validate_command(command, authorized_scopes,
                                                     expected_tool='nxc', aggressive=True)
        if valid:
            steps.append(_step('nxc', command,
                               'Enumerate the shares and sessions reachable with the recovered credential for '
                               + row['username'] + ' on ' + host + '.', 'post_exploitation'))

    if not steps:
        notes.append('No open foothold and no recovered credential exist to enumerate through; '
                     'the post-exploitation phase has nothing to act on.')
    return steps, notes


def draft_lateral_plan(footholds, loot, hosts, target, authorized_scopes, aggressive=False):
    """Re-use proven access to reach the other hosts in scope.

    A recovered credential is only lateral movement once it is replayed against
    a host that is not where it was found. Steps prefer the hosts enumeration
    actually discovered, fall back to the credential's own host when nothing
    else is known, and never leave the authorized scopes.
    """
    steps, notes = [], []
    if not aggressive:
        return [], ['Lateral movement runs only in aggressive lab mode.']
    if not footholds and not loot:
        return [], ['No foothold or recovered credential exists to pivot from.']

    steps.extend(draft_foothold_plan(loot, footholds, target, authorized_scopes, aggressive=True)[0])

    known_hosts = [row['address'] for row in hosts if row.get('address')]
    validated = [row for row in loot if row.get('validated') and row.get('username')]
    for row in validated:
        if len(steps) >= MAX_LATERAL_STEPS:
            notes.append('Only the first ' + str(MAX_LATERAL_STEPS) + ' lateral-movement steps were drafted.')
            break
        targets = [host for host in known_hosts if host != row.get('host')]
        if not targets:
            notes.append('No second host was discovered to replay the credential for '
                         + row['username'] + ' against; it was proven on ' + str(row.get('host')) + ' only.')
            continue
        host = targets[0]
        command = ('nxc ' + _nxc_protocol(row.get('service')) + ' ' + host + ' -u ' + row['username']
                   + ' ' + _secret_flag(row) + ' ' + _secret_placeholder(row) + ' --shares --sessions')
        valid, _, _ = policy_engine.validate_command(command, authorized_scopes,
                                                     expected_tool='nxc', aggressive=True)
        if valid:
            steps.append(_step('nxc', command,
                               'Replay the proven credential for ' + row['username'] + ' against ' + host
                               + ' to test whether access extends beyond the original host.', 'lateral_movement'))

    pivots = [row for row in footholds if row.get('state') == 'open' and row.get('pivot_ready')]
    for row in pivots:
        if len(steps) >= MAX_LATERAL_STEPS or not validated or not known_hosts:
            break
        inner = ('nxc smb ' + known_hosts[0] + ' -u ' + validated[0]['username'] + ' '
                 + _secret_flag(validated[0]) + ' ' + _secret_placeholder(validated[0]) + ' --shares')
        command = 'proxychains4 -q ' + inner
        valid, _, _ = policy_engine.validate_command(command, authorized_scopes,
                                                     expected_tool='proxychains4', aggressive=True)
        if valid:
            steps.append(_step('proxychains4', command,
                               'Route the follow-up SMB enumeration through the foothold on '
                               + str(row.get('host')) + ' instead of originating it from the operator host.',
                               'lateral_movement'))

    deduped, seen = [], set()
    for step in steps:
        if step['command'] in seen:
            continue
        seen.add(step['command'])
        deduped.append(step)
    if not deduped:
        notes.append('No in-scope second host and no pivot-ready foothold are available to move through.')
    return deduped[:MAX_LATERAL_STEPS], notes


def draft_impact_plan(footholds, loot, hosts, target, authorized_scopes, aggressive=False):
    """Prove the engagement objective through the access the campaign obtained.

    Impact is stated as evidence, not damage: the objective's data and the
    access that proves control, read once and reported. Every step here is
    read-only or a single bounded command, and every one is still approved by a
    human before it runs.
    """
    steps, notes = [], []
    if not aggressive:
        return [], ['Impact proof runs only in aggressive lab mode.']
    if not footholds and not loot:
        return [], ['No foothold or recovered credential exists to prove impact with.']

    for row in footholds:
        if row.get('state') != 'open' or len(steps) >= MAX_IMPACT_STEPS:
            continue
        if row.get('kind') == 'session' and str(row.get('remote_id') or '').isdigit():
            for module in ('post/linux/gather/enum_system', 'post/windows/gather/enum_system'):
                command = ('msfconsole -q -x "use ' + module + '; set SESSION ' + str(row['remote_id'])
                           + '; run -z; sessions -l; exit"')
                valid, _, _ = policy_engine.validate_command(command, authorized_scopes,
                                                             expected_tool='msfconsole', aggressive=True)
                if valid:
                    steps.append(_step('msfconsole', command,
                                       'Collect the system facts that prove control of ' + str(row.get('host'))
                                       + ' through the open session, as the objective evidence.', 'impact'))
                    break

    for row in [item for item in loot if item.get('validated')][:MAX_IMPACT_STEPS]:
        if len(steps) >= MAX_IMPACT_STEPS:
            break
        host = row['host']
        if _secret_flag(row) == '-H':
            command = ('impacket-secretsdump -hashes ' + _secret_placeholder(row) + ' '
                       + row['username'] + '@' + host)
        else:
            command = ('impacket-secretsdump ' + row['username'] + ':' + _secret_placeholder(row)
                       + '@' + host)
        valid, _, _ = policy_engine.validate_command(command, authorized_scopes,
                                                     expected_tool='impacket-secretsdump', aggressive=True)
        if valid:
            steps.append(_step('impacket-secretsdump', command,
                               'Demonstrate the depth of the compromised access on ' + host + ' by reading '
                               'the credential material the account can reach.', 'impact'))

    for row in _usable_loot(loot):
        if len(steps) >= MAX_IMPACT_STEPS:
            break
        host = row['host']
        command = ('smbclient //' + host + '/C$ -U ' + row['username'] + '%'
                   + _secret_placeholder(row) + ' -c ls')
        valid, _, _ = policy_engine.validate_command(command, authorized_scopes,
                                                     expected_tool='smbclient', aggressive=True)
        if valid:
            steps.append(_step('smbclient', command,
                               'Prove file-level access to the administrative share on ' + host
                               + ' with the recovered credential.', 'impact'))

    if not steps:
        notes.append('No open session and no validated credential exist to build an impact proof from.')
    return steps, notes


def _base_post_exploitation_steps(findings, target, authorized_scopes, aggressive):
    from modules.exploit_planner import draft_post_exploitation_plan
    return draft_post_exploitation_plan(findings, target, authorized_scopes, aggressive=aggressive)


class CampaignPlanner:
    """Stateless facade matching exploit_planner's shape for main.py."""

    def draft_plan(self, phase, findings, target, authorized_scopes,
                   verification_endpoints=(), aggressive=False,
                   loot=(), footholds=(), hosts=()):
        target_address = target if isinstance(target, str) else ''
        if phase == 'post_exploitation':
            steps, notes = _base_post_exploitation_steps(findings, target_address, authorized_scopes, aggressive)
            campaign_steps, campaign_notes = post_exploitation_steps(
                list(footholds), list(loot), list(hosts), target_address, authorized_scopes, aggressive=aggressive)
            return steps + campaign_steps, notes + campaign_notes
        if phase == 'credential_validation':
            return draft_credential_validation_plan(list(loot), target_address, authorized_scopes, aggressive=aggressive)
        if phase == 'lateral_movement':
            return draft_lateral_plan(list(footholds), list(loot), list(hosts), target_address,
                                      authorized_scopes, aggressive=aggressive)
        if phase == 'impact':
            return draft_impact_plan(list(footholds), list(loot), list(hosts), target_address,
                                     authorized_scopes, aggressive=aggressive)
        return [], ['No campaign planner exists for phase ' + str(phase) + '.']

    def required_analysis(self, phase, aggressive=False):
        return preceding_plan_phase(phase, aggressive)


campaign_planner = CampaignPlanner()
