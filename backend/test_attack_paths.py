"""Attack-path reasoning: correlated findings become explainable chains.

The Phase-1 report (Chapter 3/4) promised correlation across tools - not just
a scored list. These tests pin the three properties that make the derived
paths trustworthy:

  - a path's members provably share a location (origin or parameter), so
    nothing is chained by vibes;
  - non-locational findings (a header audit, a TLS audit) group under the
    target's origin instead of being stranded;
  - an AI narrative is only shown when every finding id it cites exists in
    the path - hallucinated provenance falls back to the deterministic text.
"""
import json
from unittest.mock import MagicMock, patch

from modules.attack_paths import (
    derive_paths, narrate_paths, origin_key, build_finding_graph)


def finding(fid, title, endpoint='http://host:3000/x', severity='Medium',
            priority=50, parameter='', verification='', phase='recon', tools=('curl',)):
    return {'id': fid, 'title': title, 'endpoint': endpoint, 'parameter': parameter,
            'severity': severity, 'priority_score': priority, 'verification': verification,
            'phase': phase, 'source_tools': list(tools)}


class TestGraphAndPaths:
    def test_same_origin_findings_form_one_path(self):
        paths = derive_paths([
            finding(1, 'Missing CSP header', 'http://host:3000/', 'Medium', 55),
            finding(2, 'Template match', 'http://host:3000/', 'High', 70),
        ], target_address='host:3000')
        assert len(paths) == 1
        assert paths[0]['node_count'] == 2
        assert paths[0]['origins'] == ['host:3000']

    def test_endpoint_spellings_normalise_to_one_origin(self):
        # nmap says 'host:3000/tcp', nuclei says 'http://host:3000/': the
        # same service, so the same path.
        paths = derive_paths([
            finding(1, 'Exposed http service', 'host:3000/tcp', 'Medium', 45),
            finding(2, 'Template match', 'http://host:3000/', 'High', 70),
        ], target_address='host:3000')
        assert len(paths) == 1

    def test_disjoint_origins_stay_separate(self):
        paths = derive_paths([
            finding(1, 'Finding on A', 'http://a:3000/', 'Medium', 50),
            finding(2, 'Finding on B', 'http://b:3000/', 'Medium', 50),
        ], target_address='a:3000')
        assert paths == []

    def test_non_locational_findings_group_under_the_target(self):
        # The curl parser reports endpoint 'HTTP response headers'; with the
        # target address supplied it joins the target's origin.
        paths = derive_paths([
            finding(1, 'Missing CSP header', 'HTTP response headers', 'Medium', 55),
            finding(2, 'Exposed http service', 'host:3000/tcp', 'Medium', 45),
        ], target_address='host:3000')
        assert len(paths) == 1
        assert {n['id'] for n in paths[0]['nodes']} == {1, 2}

    def test_shared_parameter_links_findings(self):
        paths = derive_paths([
            finding(1, 'Parameter looks injectable', 'http://host:3000/a', parameter='email'),
            finding(2, 'Different endpoint, same parameter', 'http://host:3000/b', parameter='email'),
        ], target_address='host:3000')
        assert len(paths) == 1

    def test_lone_findings_are_not_paths(self):
        assert derive_paths([finding(1, 'Solo', 'http://host:3000/')], 'host:3000') == []

    def test_verification_counts_surface_in_the_path(self):
        paths = derive_paths([
            finding(1, 'Weak origin', 'http://host:3000/', 'Medium', 50,
                    verification='verified'),
            finding(2, 'Also weak', 'http://host:3000/', 'Medium', 45,
                    verification='attempted'),
        ], target_address='host:3000')
        assert paths[0]['verified'] == 1
        assert paths[0]['attempted'] == 1

    def test_paths_rank_by_combined_priority_and_are_capped(self):
        many = [finding(i, f'F{i}', f'http://host{i % 3}:3000/', priority=i)
                for i in range(1, 31)]
        paths = derive_paths(many, target_address='host:3000')
        assert len(paths) <= 10
        assert all(len(p['nodes']) <= 8 for p in paths)
        priorities = [p['total_priority'] for p in paths]
        assert priorities == sorted(priorities, reverse=True)

    def test_origin_key_variants(self):
        assert origin_key('http://Host:3000/path') == 'host:3000'
        assert origin_key('host:3000/tcp') == 'host:3000'
        assert origin_key('HTTP response headers', 'host:3000') == 'host:3000'
        assert origin_key('') == ''


class TestNarratives:
    def test_no_provider_gives_the_deterministic_narrative(self):
        paths = derive_paths([
            finding(1, 'Missing CSP header', 'http://host:3000/', 'Medium', 55),
            finding(2, 'Exposed service', 'host:3000/tcp', 'Medium', 45),
        ], target_address='host:3000')
        narrated = narrate_paths(paths)
        assert narrated[0]['narrative_source'] == 'deterministic'
        assert 'host:3000' in narrated[0]['narrative']
        assert 'Missing CSP header' in narrated[0]['narrative']

    def _provider_response(self, payload):
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = {'choices': [{'message': {'content': json.dumps(payload)}}]}
        return response

    def test_grounded_ai_narrative_is_used(self):
        paths = derive_paths([
            finding(1, 'Missing CSP header', 'http://host:3000/', 'Medium', 55),
            finding(2, 'Exposed service', 'host:3000/tcp', 'Medium', 45),
        ], target_address='host:3000')
        payload = [{'path_index': 0, 'narrative': 'Finding #1 and finding #2 combine: the missing CSP lets an injected script from #2 run unfiltered.'}]
        with patch('modules.attack_paths.requests.post', return_value=self._provider_response(payload)):
            narrated = narrate_paths(paths, api_key='k', base_url='http://p', model_name='m')
        assert narrated[0]['narrative_source'] == 'ai-provider'
        assert 'CSP' in narrated[0]['narrative']

    def test_hallucinated_citation_falls_back_to_deterministic(self):
        paths = derive_paths([
            finding(1, 'Missing CSP header', 'http://host:3000/', 'Medium', 55),
            finding(2, 'Exposed service', 'host:3000/tcp', 'Medium', 45),
        ], target_address='host:3000')
        # The narrative cites finding #99, which does not exist.
        payload = [{'path_index': 0, 'narrative': 'Finding #99 proves total compromise of the host.'}]
        with patch('modules.attack_paths.requests.post', return_value=self._provider_response(payload)):
            narrated = narrate_paths(paths, api_key='k', base_url='http://p', model_name='m')
        assert narrated[0]['narrative_source'] == 'deterministic'
        assert '#99' not in narrated[0]['narrative']

    def test_provider_outage_falls_back(self):
        paths = derive_paths([
            finding(1, 'Missing CSP header', 'http://host:3000/', 'Medium', 55),
            finding(2, 'Exposed service', 'host:3000/tcp', 'Medium', 45),
        ], target_address='host:3000')
        with patch('modules.attack_paths.requests.post', side_effect=RuntimeError('down')):
            narrated = narrate_paths(paths, api_key='k', base_url='http://p', model_name='m')
        assert narrated[0]['narrative_source'] == 'deterministic'

    def test_no_paths_no_call(self):
        assert narrate_paths([]) == []


class TestReportIntegration:
    def test_report_renders_the_attack_path_section(self, tmp_path):
        from modules.reporter import reporter
        findings = [
            finding(1, 'Missing CSP header', 'http://host:3000/', 'Medium', 55),
            finding(2, 'Exposed service', 'host:3000/tcp', 'Medium', 45),
        ]
        paths = narrate_paths(derive_paths(findings, target_address='host:3000'))
        out = tmp_path / 'report.html'
        reporter.generate_html_report(
            'host:3000', 'Test objective', findings, [], str(out),
            attack_paths=paths)
        html = out.read_text(encoding='utf-8')
        assert 'Attack paths' in html
        assert 'Missing CSP header' in html
        assert 'deterministic' in html
