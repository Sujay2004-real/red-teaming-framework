import json
from unittest.mock import Mock, patch

import pytest
import requests

from modules.analyzer import (
    DEFAULT_ASSET_CRITICALITY,
    MAX_ANALYSIS_TOTAL_CHARS,
    MAX_FINDINGS,
    MAX_FINDING_TEXT_CHARS,
    AnalyzerAgent,
)


RAW_OUTPUTS = [{'tool': 'nmap', 'stdout': '80/tcp open http', 'stderr': ''}]
# There is no default endpoint or model, so every test that expects the provider
# path to be attempted has to supply all three.
PROVIDER = {'api_key': 'test-key', 'base_url': 'https://provider.example/v1', 'model_name': 'test-model'}


def test_partial_provider_configuration_never_calls_out():
    """A key with no endpoint or model must not reach any provider."""
    with patch('requests.post') as post:
        findings, mode = AnalyzerAgent().analyze_results(
            RAW_OUTPUTS,
            api_key='test-key',
            include_metadata=True,
        )

    post.assert_not_called()
    assert mode == 'deterministic-fallback'
    assert findings[0]['title'] == 'Exposed HTTP service'


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
            **PROVIDER,
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
            **PROVIDER,
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
            **PROVIDER,
            include_metadata=True,
        )

    assert mode == 'ai-provider'
    assert findings[0]['severity'] == 'Low'
    assert findings[0]['confidence_score'] == 70
    assert findings[0]['source_tools'] == ['nmap']


# An unusable asset_criticality from the model has to fall back to *this
# target's* criticality. score_finding only knows the global default, so leaving
# a bad value in place for it to coerce scored a business-critical asset as an
# average one.
@pytest.mark.parametrize('reported,expected', [
    ('not-a-number', 100),
    (None, 100),
    (10, 10),
])
def test_asset_criticality_falls_back_to_the_target(reported, expected):
    agent = AnalyzerAgent()
    item = {'title': 'Model finding', 'severity': 'Medium'}
    if reported is not None:
        item['asset_criticality'] = reported

    with patch.object(agent, '_ai_findings', return_value=[item]):
        findings = agent.analyze_results(RAW_OUTPUTS, **PROVIDER, asset_criticality=100)

    assert findings[0]['asset_criticality'] == expected


def test_asset_criticality_falls_back_to_the_global_default_without_a_target():
    agent = AnalyzerAgent()
    with patch.object(agent, '_ai_findings', return_value=[{'title': 'Model finding'}]):
        findings = agent.analyze_results(RAW_OUTPUTS, **PROVIDER)

    assert findings[0]['asset_criticality'] == DEFAULT_ASSET_CRITICALITY


def test_a_runaway_provider_response_is_bounded():
    """A provider response is untrusted input; every finding becomes a row."""
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {'choices': [{'message': {'content': json.dumps([
        {'title': f'Finding {index}', 'description': 'x' * (MAX_FINDING_TEXT_CHARS + 5_000)}
        for index in range(MAX_FINDINGS + 50)
    ])}}]}

    with patch('requests.post', return_value=response):
        findings, mode = AnalyzerAgent().analyze_results(
            RAW_OUTPUTS,
            **PROVIDER,
            include_metadata=True,
        )

    assert mode == 'ai-provider'
    assert len(findings) == MAX_FINDINGS
    assert all(len(finding['description']) == MAX_FINDING_TEXT_CHARS for finding in findings)


def test_one_chatty_scanner_cannot_crowd_out_the_prompt_budget():
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {'choices': [{'message': {'content': '[]'}}]}
    outputs = [{'tool': f'tool{index}', 'stdout': 'x' * 200_000, 'stderr': ''} for index in range(10)]

    with patch('requests.post', return_value=response) as post:
        AnalyzerAgent().analyze_results(outputs, **PROVIDER)

    prompt = post.call_args.kwargs['json']['messages'][0]['content']
    assert len(prompt) < MAX_ANALYSIS_TOTAL_CHARS + 10_000
    # The last tool is still named in the prompt even though the first ones are
    # far larger than the per-stream cap.
    assert 'tool9' in prompt
