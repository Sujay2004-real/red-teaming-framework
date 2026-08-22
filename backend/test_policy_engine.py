from modules.policy_engine import PolicyEngine


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
