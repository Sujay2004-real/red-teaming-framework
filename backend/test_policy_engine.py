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
    'whatweb --open-timeout 5 http://juice-shop:3000',
    'whatweb --open-timeout=5 http://juice-shop:3000',
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
