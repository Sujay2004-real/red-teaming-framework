import json
from unittest.mock import Mock, patch

from requests.exceptions import RequestException

from modules.planner import PlannerAgent
from modules.policy_engine import PolicyEngine

# There is no default endpoint or model, so every test that expects the provider
# path to be attempted has to supply all three.
PROVIDER = {'api_key': 'test-key', 'base_url': 'https://provider.example/v1', 'model_name': 'test-model'}


def test_default_plan_separates_host_and_web_port():
    plan = PlannerAgent().default_plan('juice-shop:3000')

    commands = {step['tool']: step['command'] for step in plan}
    # Name resolvers get the bare host and learn the port another way; anything
    # that parses host:port itself keeps it, and the web templates add the
    # http:// scheme exactly once (a re-prefixed target once produced
    # http://http://host).
    assert commands['nmap'] == 'nmap -sV --version-light --max-rate 30 -p 3000 juice-shop'
    assert commands['traceroute'] == 'traceroute juice-shop'
    assert commands['dig'] == 'dig +short juice-shop'
    assert commands['curl'] == 'curl -sSI http://juice-shop:3000'
    assert commands['whatweb'] == 'whatweb -a 3 --color=never http://juice-shop:3000'
    assert commands['sslscan'] == 'sslscan --no-colour juice-shop:3000'
    assert commands['nuclei'] == ('nuclei -u http://juice-shop:3000 '
                                  '-tags cve,exposure,misconfig '
                                  '-severity medium,high,critical -rl 30 -nc -stats -duc -silent')
    # The default plan is deep: a manual tester would need many more commands
    # and hours of correlation to reach the same coverage.
    assert len(plan) >= 7


def test_default_plan_commands_all_pass_policy_review():
    """A default step that policy would refuse is a plan that cannot be run."""
    engine = PolicyEngine()

    for step in PlannerAgent().default_plan('juice-shop:3000'):
        valid, reason, _ = engine.validate_command(
            step['command'], ['juice-shop:3000'], expected_tool=step['tool'])
        assert valid, f"{step['command']} rejected: {reason}"


# The bug this covers: 'nmap juice-shop:3000' and 'dig +short juice-shop:3000'
# fail with "Failed to resolve" *and still exit 0*, so the audit trail showed
# six green steps that had scanned nothing at all.
def test_name_resolving_tools_never_receive_an_endpoint():
    plan = PlannerAgent().default_plan('juice-shop:3000')
    commands = {step['tool']: step['command'] for step in plan}

    assert ':3000' not in commands['dig']
    assert ':3000' not in commands['traceroute']
    # nmap keeps the port the letter named, as a flag it can actually use.
    assert commands['nmap'].endswith('-p 3000 juice-shop')


def test_default_plan_without_a_port_scans_the_default_range():
    commands = {step['tool']: step['command'] for step in PlannerAgent().default_plan('example.test')}

    assert commands['nmap'] == 'nmap -sV --version-light --max-rate 30 example.test'
    assert commands['curl'] == 'curl -sSI http://example.test'


def test_default_plan_accepts_a_url_shaped_target():
    commands = {step['tool']: step['command'] for step in PlannerAgent().default_plan('http://dvwa:8080/login')}

    assert commands['nmap'] == 'nmap -sV --version-light --max-rate 30 -p 8080 dvwa'
    assert commands['curl'] == 'curl -sSI http://dvwa:8080'


def test_ai_plan_filters_mismatched_declared_tool():
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        'choices': [{'message': {'content': json.dumps([
            {
                'tool': 'nmap',
                'command': 'curl -I http://juice-shop:3000',
                'reason': 'Mismatched executable',
            },
        ])}}],
    }

    with patch('requests.post', return_value=response):
        plan, source = PlannerAgent().generate_plan(
            'juice-shop:3000',
            'Inspect the target',
            **PROVIDER,
            policy_engine=PolicyEngine(),
        )

    # A policy rejection must be distinguishable from a provider outage.
    assert source == 'default-policy-rejected'
    assert plan == PlannerAgent().default_plan('juice-shop:3000')


def test_provider_failure_is_reported_separately_from_policy_rejection():
    with patch('requests.post', side_effect=RequestException('boom')):
        plan, source = PlannerAgent().generate_plan(
            'juice-shop:3000',
            'Inspect the target',
            **PROVIDER,
            policy_engine=PolicyEngine(),
        )

    assert source == 'default-provider-error'
    assert plan == PlannerAgent().default_plan('juice-shop:3000')


def test_unconfigured_provider_is_reported_separately():
    plan, source = PlannerAgent().generate_plan('juice-shop:3000', 'Inspect the target')

    assert source == 'default-unconfigured'
    assert plan == PlannerAgent().default_plan('juice-shop:3000')


def test_partial_provider_configuration_never_calls_out():
    """A key with no endpoint or model must not reach any provider."""
    with patch('requests.post') as post:
        plan, source = PlannerAgent().generate_plan(
            'juice-shop:3000',
            'Inspect the target',
            api_key='test-key',
        )

    post.assert_not_called()
    assert source == 'default-unconfigured'
    assert plan == PlannerAgent().default_plan('juice-shop:3000')


def test_secondary_authorized_scopes_survive_policy_review():
    """A step aimed at an authorized secondary scope must not be dropped."""
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        'choices': [{'message': {'content': json.dumps([
            {'tool': 'nmap', 'command': 'nmap -sV 172.18.0.7', 'reason': 'Sweep the lab subnet host'},
        ])}}],
    }

    with patch('requests.post', return_value=response):
        plan, source = PlannerAgent().generate_plan(
            'juice-shop:3000',
            'Inspect the target',
            **PROVIDER,
            policy_engine=PolicyEngine(),
            authorized_scopes=['juice-shop:3000', '172.18.0.0/16'],
        )

    assert source == 'ai-filtered'
    assert plan[0]['command'] == 'nmap -sV 172.18.0.7'
    assert plan[0]['capability'] == 'network_discovery'

