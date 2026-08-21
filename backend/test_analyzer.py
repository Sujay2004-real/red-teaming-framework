import json
from unittest.mock import Mock, patch

import requests

from modules.analyzer import AnalyzerAgent


RAW_OUTPUTS = [{'tool': 'nmap', 'stdout': '80/tcp open http', 'stderr': ''}]


def test_openai_compatible_analysis_uses_configured_provider():
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        'choices': [{'message': {'content': '```json\n' + json.dumps([{
            'title': 'Exposed HTTP service',
            'description': 'HTTP is reachable.',
            'severity': 'Medium',
            'evidence': '80/tcp open http',
            'remediation': 'Restrict exposure.',
            'endpoint': 'target:80',
            'parameter': '',
            'exploitability': 3,
            'impact': 2,
            'exposure': 4,
            'confidence_score': 90,
            'source_tools': ['nmap'],
        }]) + '\n```'}}],
    }

    with patch('requests.post', return_value=response) as post:
        findings, mode = AnalyzerAgent().analyze_results(
            RAW_OUTPUTS,
            api_key='test-key',
            base_url='https://provider.example/v1/',
            model_name='test-model',
            include_metadata=True,
        )

    assert mode == 'ai-provider'
    assert findings[0]['title'] == 'Exposed HTTP service'
    assert findings[0]['confidence_score'] == 90
    post.assert_called_once()
    assert post.call_args.args[0] == 'https://provider.example/v1/chat/completions'
    assert post.call_args.kwargs['json']['model'] == 'test-model'


def test_provider_failure_uses_deterministic_fallback():
    with patch('requests.post', side_effect=requests.RequestException('provider unavailable')):
        findings, mode = AnalyzerAgent().analyze_results(
            RAW_OUTPUTS,
            api_key='test-key',
            include_metadata=True,
        )

    assert mode == 'deterministic-fallback'
    assert findings[0]['title'] == 'Exposed HTTP service'


def test_invalid_provider_payload_uses_deterministic_fallback():
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        'choices': [{'message': {'content': '{"not": "a list"}'}}],
    }

    with patch('requests.post', return_value=response):
        findings, mode = AnalyzerAgent().analyze_results(
            RAW_OUTPUTS,
            api_key='test-key',
            include_metadata=True,
        )

    assert mode == 'deterministic-fallback'
    assert findings[0]['title'] == 'Exposed HTTP service'


def test_invalid_model_scores_are_normalized_safely():
    agent = AnalyzerAgent()
    with patch.object(agent, '_ai_findings', return_value=[{
        'title': 'Model finding',
        'severity': 'unexpected',
        'exploitability': 'not-a-number',
        'confidence_score': None,
        'source_tools': 'nmap',
    }]):
        findings, mode = agent.analyze_results(
            RAW_OUTPUTS,
            api_key='test-key',
            include_metadata=True,
        )

    assert mode == 'ai-provider'
    assert findings[0]['severity'] == 'Low'
    assert findings[0]['confidence_score'] == 70
    assert findings[0]['source_tools'] == ['nmap']
