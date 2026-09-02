import json
from unittest.mock import Mock, patch

import pytest
import requests

from modules.analyzer import (
    DEFAULT_ASSET_CRITICALITY,
    MAX_ANALYSIS_TOTAL_CHARS,
    MAX_FINDINGS,
    MAX_FINDING_TEXT_CHARS,
    SECURITY_HEADERS,
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
    assert findings[0]['title'] == 'Exposed http service on port 80'


def test_openai_compatible_analysis_uses_configured_provider():
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        'choices': [{'message': {'content': '```json\n' + json.dumps([{
            'title': 'Exposed http service on port 80',
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
    assert findings[0]['title'] == 'Exposed http service on port 80'
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
    assert findings[0]['title'] == 'Exposed http service on port 80'


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
    assert findings[0]['title'] == 'Exposed http service on port 80'


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


# ---------------------------------------------------------------------------
# The deterministic per-tool parsers. These run whenever no provider is
# configured, which is the demo default, so each one has to produce findings
# with real explanations and distinct scoring drivers - and has to stay silent
# when its tool never actually reached the target.
# ---------------------------------------------------------------------------

NMAP_OUTPUT = """Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for juice-shop (172.18.0.3)
Host is up (0.000090s latency).

PORT     STATE    SERVICE    VERSION
3000/tcp open     http       Node.js Express framework
8080/tcp open     http-proxy
22/tcp   filtered ssh
Service detection performed. Please report any incorrect results.
"""

CURL_OUTPUT = """HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
X-Powered-By: Express
Server: nginx/1.24.0
Content-Type: text/html; charset=utf-8
Set-Cookie: token=eyJhbGciOi; Path=/
"""


def test_nmap_output_files_one_finding_per_service():
    findings = AnalyzerAgent()._finding_nmap(NMAP_OUTPUT, 'nmap')
    by_endpoint = {finding['endpoint']: finding for finding in findings}

    assert set(by_endpoint) == {'3000/tcp', '8080/tcp', '22/tcp'}
    # The version-bearing line names the software and is reported with higher
    # confidence than the bare one.
    assert 'Node.js Express framework' in by_endpoint['3000/tcp']['description']
    assert by_endpoint['3000/tcp']['confidence_score'] == 95
    assert by_endpoint['8080/tcp']['confidence_score'] == 70
    # A filtered port is less exposed than an open one.
    assert by_endpoint['22/tcp']['exposure'] < by_endpoint['3000/tcp']['exposure']
    assert all(finding['remediation'] for finding in findings)


# The bug this covers: the severity was title-cased ('Critical') and then
# compared against lowercase 'critical', so no branch ever matched and every
# nuclei finding scored identically no matter what level nuclei reported.
@pytest.mark.parametrize('level,severity,exploitability,impact', [
    ('critical', 'Critical', 4, 5),
    ('high', 'High', 4, 4),
    ('medium', 'Medium', 3, 3),
    ('low', 'Low', 2, 2),
])
def test_nuclei_severity_drives_distinct_scores(level, severity, exploitability, impact):
    line = f'[CVE-2021-44228:log4j] [{level}] http://juice-shop:3000/api'
    finding = AnalyzerAgent()._finding_nuclei(line, 'nuclei')[0]

    assert finding['severity'] == severity
    assert finding['exploitability'] == exploitability
    assert finding['impact'] == impact
    assert 'CVE-2021-44228' in finding['title']


def test_nuclei_informational_match_is_not_promoted_to_medium():
    """'info' is reconnaissance detail; scoring it Medium inflates the report."""
    finding = AnalyzerAgent()._finding_nuclei(
        '[tech-detect] [info] http://juice-shop:3000/', 'nuclei')[0]

    assert finding['severity'] == 'Low'
    assert finding['impact'] == 1


def test_curl_files_one_finding_per_missing_security_header():
    findings = AnalyzerAgent()._finding_curl(CURL_OUTPUT, 'curl')
    titles = [finding['title'] for finding in findings]

    # nosniff was served, so only the other four headers are reported missing.
    expected_missing = sorted(spec['title'] for name, spec in SECURITY_HEADERS.items()
                              if name != 'x-content-type-options')
    assert sorted(title for title in titles if title.startswith('Missing')) == expected_missing
    assert SECURITY_HEADERS['x-content-type-options']['title'] not in titles
    # Both banners and the flagless session cookie are reported alongside them.
    assert 'Technology disclosed in server header' in titles
    assert 'Technology disclosed in x-powered-by header' in titles
    assert any('HttpOnly' in title for title in titles)
    assert any('Secure' in title for title in titles)
    # Every finding explains itself, cites the response, and says what to do.
    assert all(len(finding['description']) > 100 for finding in findings)
    assert all(finding['evidence'] and finding['remediation'] for finding in findings)


def test_curl_reports_nothing_when_the_request_never_reached_the_target():
    """A failed request must not invent 'missing header' findings.

    curl prints no status line when it cannot connect, and the analyzer is not
    given the exit code, so the absence of a response block is the only signal
    that the headers were never seen. Auditing an empty header map would put
    five remediation items about a host that was never reached in front of the
    client, and would read curl's own 'curl: (7) ...' diagnostic as a header.
    """
    agent = AnalyzerAgent()

    assert agent._finding_curl('', 'curl') == []
    assert agent._finding_curl(
        'curl: (7) Failed to connect to dvwa port 80: Connection refused', 'curl') == []
    assert agent._finding_curl('curl: (6) Could not resolve host: nowhere', 'curl') == []


def test_curl_header_audit_describes_the_final_response_of_a_redirect():
    redirected = ('HTTP/1.1 301 Moved Permanently\r\n'
                  'Location: http://juice-shop:3000/login\r\n'
                  "Content-Security-Policy: default-src 'self'\r\n"
                  '\r\n'
                  'HTTP/1.1 200 OK\r\n'
                  'Content-Type: text/html\r\n')
    titles = [finding['title'] for finding in AnalyzerAgent()._finding_curl(redirected, 'curl')]

    # The CSP belonged to the redirect hop, not to the page the user lands on,
    # so it is still missing from the response that matters.
    assert SECURITY_HEADERS['content-security-policy']['title'] in titles


def test_whatweb_fingerprints_become_findings():
    output = ('http://juice-shop:3000 [200 OK] Country[RESERVED][ZZ], '
              'HTTPServer[nginx/1.24.0], X-Powered-By[Express]')
    titles = [finding['title'] for finding in AnalyzerAgent()._finding_whatweb(output, 'whatweb')]

    assert 'Technology fingerprint: HTTPServer' in titles
    assert 'Technology fingerprint: X-Powered-By' in titles
    # Geolocation is noise, not attack surface.
    assert not any('Country' in title for title in titles)


def test_sslscan_reports_each_deprecated_protocol():
    output = 'SSLv3     enabled\nTLSv1.0   enabled\nTLSv1.2   enabled\n'
    findings = AnalyzerAgent()._finding_sslscan(output, 'sslscan')
    by_title = {finding['title']: finding for finding in findings}

    assert 'Deprecated protocol SSLv3 enabled' in by_title
    assert 'Deprecated protocol TLSv1.0 enabled' in by_title
    # TLSv1.2 is current, so it is not a finding.
    assert not any('TLSv1.2' in title for title in by_title)
    assert by_title['Deprecated protocol SSLv3 enabled']['severity'] == 'High'


# ---------------------------------------------------------------------------
# Real captured output. Every sample below is what the tool actually printed in
# the Docker stack, escape codes and all: these parsers were silently producing
# nothing because the samples they were written against were tidier than
# reality.
# ---------------------------------------------------------------------------

def test_nmap_tentative_service_still_produces_a_finding():
    """'ppp?' is nmap saying it guessed. Dropping the line loses the port."""
    finding = AnalyzerAgent()._finding_nmap('3000/tcp open  ppp?', 'nmap')[0]

    assert finding['endpoint'] == '3000/tcp'
    # The '?' is nmap's uncertainty marker, not part of the service name.
    assert 'ppp?' not in finding['title']
    assert 'tentative' in finding['description']
    # Reported below an unqualified match, since nmap itself is unsure.
    assert finding['confidence_score'] == 55


def test_nuclei_v3_protocol_field_is_parsed():
    """v3 prints '[template] [http] [severity] url'; v2 omitted the protocol."""
    line = '[prometheus-metrics] [http] [medium] http://juice-shop:3000/metrics'
    finding = AnalyzerAgent()._finding_nuclei(line, 'nuclei')[0]

    assert finding['severity'] == 'Medium'
    assert finding['endpoint'] == 'http://juice-shop:3000/metrics'
    assert 'prometheus-metrics' in finding['title']


def test_colourised_scanner_output_is_still_parsed():
    """Scanners colourise even into a pipe, and the escapes land mid-token.

    The plan asks for plain output, but an operator-edited command or a
    different build can still colourise, so parsing must not depend on it.
    """
    outputs = [
        {'tool': 'nuclei', 'stderr': '', 'stdout':
            '[\x1b[92mprometheus-metrics\x1b[0m] [\x1b[94mhttp\x1b[0m] '
            '[\x1b[33mmedium\x1b[0m] http://juice-shop:3000/metrics'},
        {'tool': 'whatweb', 'stderr': '', 'stdout':
            '\x1b[1m\x1b[34mhttp://juice-shop:3000/\x1b[0m [200 OK] '
            '\x1b[1mHTTPServer\x1b[0m[\x1b[22mnginx/1.24.0\x1b[0m], '
            '\x1b[1mX-Frame-Options\x1b[0m[\x1b[22mSAMEORIGIN\x1b[0m]'},
        {'tool': 'sslscan', 'stderr': '', 'stdout':
            'SSLv3     \x1b[32menabled\x1b[0m\nTLSv1.2   disabled\n'},
    ]

    titles = [finding['title'] for finding in AnalyzerAgent().analyze_results(outputs)]

    assert 'Template-driven check matched: prometheus-metrics' in titles
    assert 'Technology fingerprint: HTTPServer' in titles
    # The escape sat between 'SSLv3' and 'enabled', so the protocol audit read
    # a weak protocol as absent.
    assert 'Deprecated protocol SSLv3 enabled' in titles


def test_deterministic_analysis_correlates_tools_and_ranks_findings():
    """The no-provider path has to rank findings, not flatten them."""
    outputs = [
        {'tool': 'nmap', 'stdout': NMAP_OUTPUT, 'stderr': ''},
        {'tool': 'curl', 'stdout': CURL_OUTPUT, 'stderr': ''},
        {'tool': 'nuclei', 'stderr': '', 'stdout': (
            '[CVE-2021-44228:log4j] [critical] http://juice-shop:3000/api\n'
            '[tech-detect] [info] http://juice-shop:3000/')},
    ]

    findings, mode = AnalyzerAgent().analyze_results(
        outputs, include_metadata=True, asset_criticality=90)

    assert mode == 'deterministic-fallback'
    # One run correlates every tool instead of firing one pattern per tool.
    assert len(findings) > 10
    assert {'nmap', 'curl', 'nuclei'} <= {tool for finding in findings
                                          for tool in finding['source_tools']}
    # The critical template match outranks the informational one and the
    # low-severity header findings, and the scores actually spread out.
    ranked = sorted(findings, key=lambda finding: finding['priority_score'], reverse=True)
    assert ranked[0]['severity'] == 'Critical'
    assert len({finding['priority_score'] for finding in findings}) > 3
    assert len({finding['risk_score'] for finding in findings}) > 3
    # The letter's criticality reaches every finding, not just the model path.
    assert all(finding['asset_criticality'] == 90 for finding in findings)
