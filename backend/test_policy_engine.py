from modules.policy_engine import PolicyEngine

import pytest


def test_authorized_single_label_host_is_a_valid_target():
    policy = PolicyEngine()

    valid, _, _ = policy.validate_command(
        'nmap -sV juice-shop',
        ['juice-shop:3000'],
    )

    assert valid


def test_declared_tool_must_match_command_executable():
    policy = PolicyEngine()

    valid, reason, _ = policy.validate_command(
        'curl -I http://juice-shop:3000',
        ['juice-shop:3000'],
        expected_tool='nmap',
    )

    assert not valid
    assert 'does not match' in reason


def test_remote_target_list_flags_are_blocked():
    policy = PolicyEngine()

    valid, reason, _ = policy.validate_command(
        'nmap -iR 10',
        ['juice-shop:3000'],
    )

    assert not valid
    assert 'Blocked flag' in reason


def test_attached_output_flag_is_blocked():
    policy = PolicyEngine()

    valid, reason, _ = policy.validate_command(
        'curl -osecrets.txt http://juice-shop:3000',
        ['juice-shop:3000'],
    )

    assert not valid
    assert 'Blocked flag' in reason


# A flag filed under the wrong kind does not fail loudly: a boolean listed as a
# value flag consumes the argument after it (usually the target), and a value
# flag listed as a boolean leaves its value behind as a positional. Both turn a
# legitimate command into a confusing scope or missing-target rejection, so each
# family that has bitten is pinned here.
@pytest.mark.parametrize('command', [
    # The flag sits immediately before the URL on purpose: that is where a
    # boolean misfiled as a value flag eats the target and the command is
    # refused for having none.
    'curl -I --tlsv1 http://juice-shop:3000',
    'curl -I --tlsv1.2 http://juice-shop:3000',
    'curl -I --tlsv1.3 http://juice-shop:3000',
    # --tls-max is the one member of the family that does take a value, so this
    # guards the opposite mistake: filed as a boolean, '1.3' becomes a target.
    'curl -I --tls-max 1.3 http://juice-shop:3000',
    'whatweb --follow-redirect never --open-timeout 5 http://juice-shop:3000',
    'whatweb --follow-redirect never --open-timeout=5 http://juice-shop:3000',
    'sslscan --starttls-smtp juice-shop',
    'sslscan --starttls-imap juice-shop',
])
def test_correctly_classified_flags_keep_their_target(command):
    valid, reason, _ = PolicyEngine().validate_command(command, ['juice-shop:3000'])

    assert valid, reason


def test_flag_sslscan_does_not_have_is_still_blocked():
    """sslscan has no bare --starttls; the protocol is part of the flag name."""
    valid, reason, _ = PolicyEngine().validate_command(
        'sslscan --starttls smtp juice-shop',
        ['juice-shop:3000'],
    )

    assert not valid
    assert 'Blocked flag' in reason


# urlparse reads everything after the first colon of a bare IPv6 literal as a
# port, which discarded the address entirely and normalized '::1' to ''. Every
# IPv6 scope then silently matched nothing.
@pytest.mark.parametrize('command,scopes', [
    ('nmap -sV ::1', ['::1']),
    ('nmap -6 -sV 0:0:0:0:0:0:0:1', ['::1']),
    ('curl -I http://[::1]:3000', ['::1']),
    ('nmap -sV 2001:db8::5', ['2001:db8::/32']),
])
def test_ipv6_scopes_match_their_targets(command, scopes):
    valid, reason, _ = PolicyEngine().validate_command(command, scopes)

    assert valid, reason


def test_ipv6_target_outside_an_authorized_scope_is_still_refused():
    valid, reason, _ = PolicyEngine().validate_command('nmap -sV ::1', ['juice-shop:3000'])

    assert not valid
    assert 'outside the authorized scope' in reason


def test_ipv6_target_outside_an_authorized_network_is_still_refused():
    valid, reason, _ = PolicyEngine().validate_command('nmap -sV 2001:dead::5', ['2001:db8::/32'])

    assert not valid
    assert 'outside the authorized scope' in reason


# A CIDR target sweeps a whole range, so it must fit INSIDE an authorized
# network. normalize_host strips the prefix, and the membership check on the
# base address alone once let a /24 sweep pass against a /25 authorization.
def test_cidr_target_must_be_within_an_authorized_network():
    engine = PolicyEngine()

    valid, reason, _ = engine.validate_command('nmap -sV 192.168.1.0/24', ['192.168.1.0/25'])
    assert not valid
    assert 'outside the authorized scope' in reason

    # Equal or wider authorizations are fine.
    for scope in ('192.168.1.0/24', '192.168.0.0/16'):
        valid, reason, _ = engine.validate_command('nmap -sV 192.168.1.0/24', [scope])
        assert valid, reason


def test_cidr_target_refused_when_only_a_disjoint_range_is_authorized():
    valid, reason, _ = PolicyEngine().validate_command('nmap -sV 192.168.1.0/24', ['10.0.0.0/8'])

    assert not valid
    assert 'outside the authorized scope' in reason


def test_ipv6_cidr_target_authorized_by_a_wider_network():
    valid, reason, _ = PolicyEngine().validate_command('nmap -sV 2001:db8:1::/48', ['2001:db8::/32'])

    assert valid, reason


def test_ipv6_cidr_target_refused_by_a_narrower_network():
    valid, reason, _ = PolicyEngine().validate_command('nmap -sV 2001:db8:1::/48', ['2001:db8:1::/64'])

    assert not valid
    assert 'outside the authorized scope' in reason


# ------------------------------------------------------------------ exploitation

SCOPES = ['192.168.56.10']


def test_exploitation_gate_refuses_sqlmap_without_authorization():
    engine = PolicyEngine()
    command = f'sqlmap -u http://192.168.56.10:3000 --batch --ignore-redirects'
    valid, reason, _ = engine.validate_command(command, SCOPES)
    assert not valid
    assert 'does not authorize controlled exploitation' in reason
    # With the letter's authorization, the same command is allowed.
    valid, reason, _ = engine.validate_command(command, SCOPES, allow_exploitation=True)
    assert valid, reason


def test_curl_payload_flag_requires_exploitation_authorization():
    engine = PolicyEngine()
    benign = 'curl -sSI http://192.168.56.10:3000'
    payload = 'curl -sS -i --data "email=x" http://192.168.56.10:3000/rest/user/login'
    # A header audit is recon and needs no letter authorization.
    valid, reason, _ = engine.validate_command(benign, SCOPES)
    assert valid, reason
    # The same tool carrying a request body is a proof-of-concept.
    valid, reason, _ = engine.validate_command(payload, SCOPES)
    assert not valid
    assert 'does not authorize controlled exploitation' in reason
    valid, reason, _ = engine.validate_command(payload, SCOPES, allow_exploitation=True)
    assert valid, reason


def test_sqlmap_dangerous_flags_are_refused():
    engine = PolicyEngine()
    for forbidden in ('--os-shell', '--dump', '--sql-shell', '--file-read', '--all'):
        command = f'sqlmap -u http://192.168.56.10:3000 {forbidden}'
        valid, _, _ = engine.validate_command(command, SCOPES, allow_exploitation=True)
        assert not valid, forbidden


def test_sqlmap_out_of_scope_target_refused():
    engine = PolicyEngine()
    valid, reason, _ = engine.validate_command('sqlmap -u http://8.8.8.8:3000 --batch', SCOPES, allow_exploitation=True)
    assert not valid
    assert 'outside the authorized scope' in reason


def test_searchsploit_is_offline_and_needs_no_target():
    engine = PolicyEngine()
    valid, reason, _ = engine.validate_command('searchsploit openssh 7.2', SCOPES)
    assert valid, reason
    # Offline capability: no exploitation gate either — an Exploit-DB lookup
    # interacts with no target at all.
    valid, _, _ = engine.validate_command('searchsploit --title nodejs', SCOPES)
    assert valid


def test_searchsploit_browser_and_copy_flags_refused():
    engine = PolicyEngine()
    for forbidden in ('-w', '-p', '-m', '-x', '--nmap'):
        command = f'searchsploit openssh {forbidden}'
        valid, _, _ = engine.validate_command(command, SCOPES)
        assert not valid, forbidden


def test_msfconsole_script_validation():
    engine = PolicyEngine()
    good = ('msfconsole -q -x "use auxiliary/scanner/ssh/ssh_version; '
            'set RHOSTS 192.168.56.10; set RPORT 22; run; exit"')
    valid, reason, _ = engine.validate_command(good, SCOPES, allow_exploitation=True)
    assert valid, reason


def test_msfconsole_gate_and_missing_script():
    engine = PolicyEngine()
    good = ('msfconsole -q -x "use auxiliary/scanner/ssh/ssh_version; '
            'set RHOSTS 192.168.56.10; run; exit"')
    # Letter gate first, like every exploitation-grade tool.
    valid, reason, _ = engine.validate_command(good, SCOPES)
    assert not valid
    assert 'does not authorize controlled exploitation' in reason
    # Without a resource script the console is interactive - refused.
    valid, reason, _ = engine.validate_command('msfconsole -q', SCOPES, allow_exploitation=True)
    assert not valid
    assert 'resource script' in reason


def test_msfconsole_refuses_out_of_scope_rhosts():
    engine = PolicyEngine()
    bad = ('msfconsole -q -x "use auxiliary/scanner/ssh/ssh_version; '
           'set RHOSTS 8.8.8.8; run; exit"')
    valid, reason, _ = engine.validate_command(bad, SCOPES, allow_exploitation=True)
    assert not valid
    assert 'outside the authorized scope' in reason


def test_msfconsole_refuses_payload_and_handler_modules():
    engine = PolicyEngine()
    # The multi/handler module with a payload set key: both the module tree
    # (allowed) and the set key (PAYLOAD, not allowed) are checked — the set
    # key refusal is the deterministic one here.
    bad = ('msfconsole -q -x "use exploit/multi/handler; '
           'set PAYLOAD windows/x64/meterpreter/reverse_tcp; run; exit"')
    valid, reason, _ = engine.validate_command(bad, SCOPES, allow_exploitation=True)
    assert not valid
    assert 'set key' in reason or 'permitted module trees' in reason
    # A module outside every allowed tree is refused on the tree check.
    bad2 = 'msfconsole -q -x "use post/multi/manage/shell; run; exit"'
    valid, reason, _ = engine.validate_command(bad2, SCOPES, allow_exploitation=True)
    assert not valid
    assert 'permitted module trees' in reason


def test_msfconsole_refuses_arbitrary_statements():
    engine = PolicyEngine()
    bad = ('msfconsole -q -x "use auxiliary/scanner/ssh/ssh_version; '
           'set RHOSTS 192.168.56.10; shell; exit"')
    valid, reason, _ = engine.validate_command(bad, SCOPES, allow_exploitation=True)
    assert not valid
    assert 'not a permitted' in reason


def test_msfconsole_rhosts_list_all_must_be_in_scope():
    engine = PolicyEngine()
    command = ('msfconsole -q -x "use auxiliary/scanner/ssh/ssh_version; '
               'set RHOSTS 192.168.56.10,8.8.8.8; run; exit"')
    valid, reason, _ = engine.validate_command(command, SCOPES, allow_exploitation=True)
    assert not valid
    assert '8.8.8.8' in reason
