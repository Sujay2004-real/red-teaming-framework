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

    assert plan[0]['command'] == 'nmap -sV juice-shop'
    assert plan[1]['command'] == 'curl -I http://juice-shop:3000'


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

