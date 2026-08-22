import json
from unittest.mock import Mock, patch

from modules.planner import PlannerAgent
from modules.policy_engine import PolicyEngine


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
            api_key='test-key',
            base_url='https://provider.example/v1',
            policy_engine=PolicyEngine(),
        )

    assert source == 'default-fallback'
    assert plan == PlannerAgent().default_plan('juice-shop:3000')
