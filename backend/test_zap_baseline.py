"""The OWASP ZAP baseline integration (passive mode only).

The Phase-1 report's toolchain named OWASP ZAP; it enters the framework as
the baseline wrapper the ZAP project builds for CI: a passive crawl-and-audit
that reports one alert line per rule. These tests pin the two properties that
make the integration safe and useful:

  - the policy engine allows exactly the passive flag surface (the active
    scanner's -a, the config-file options, the daemon escape hatch -z, and
    the report-writing flags are all refused, fail-closed), and
  - the analyzer parses the alert format the wrapper actually prints
    (verified against zap-baseline.py / zap_common.py print statements),
    including the per-URL detail lines, and ignores PASS and summary lines.
"""
import pytest

from modules.analyzer import AnalyzerAgent
from modules.policy_engine import PolicyEngine

policy = PolicyEngine()
SCOPES = ['juice-shop:3000']

# Output shape from zap_common.py's print_rule: '<LEVEL>-NEW: <name> [<id>] x
# <count>' followed by indented per-URL detail lines, and the tab-separated
# summary line zap-baseline.py itself prints at the end.
REALISTIC_BASELINE_OUTPUT = """\
Total of 8 URLs
PASS: CSP Matters [10068]
WARN-NEW: Content Security Policy (CSP) Header Not Set [10038] x 3
\thttp://juice-shop:3000/ (200)
\thttp://juice-shop:3000/search (200)
WARN-NEW: Cookie No HttpOnly Flag [10010] x 1
\thttp://juice-shop:3000/rest/user/login (200)
FAIL-NEW: SQL Injection [40018] x 2
\thttp://juice-shop:3000/search?q=1 (200)
INFO-NEW: User Controllable HTML Element Attribute (Potential XSS) [10031] x 1
\thttp://juice-shop:3000/profile (200)
FAIL-NEW: 1\tFAIL-INPROG: 0\tWARN-NEW: 2\tWARN-INPROG: 0\tINFO: 1\tIGNORE: 0\tPASS: 1"""


class TestZapBaselinePolicy:
    def test_passive_baseline_command_is_allowed(self):
        valid, reason, rules = policy.validate_command(
            'zap-baseline.py -t http://juice-shop:3000 -I', SCOPES)
        assert valid
        assert rules['capability'] == 'web_inspection'
        assert rules['risk'] == 'low'

    def test_active_scanning_is_refused(self):
        """-a turns the passive baseline into an attack-payload scanner."""
        valid, reason, _ = policy.validate_command(
            'zap-baseline.py -t http://juice-shop:3000 -a', SCOPES)
        assert not valid
        assert '-a' in reason

    def test_daemon_options_escape_hatch_is_refused(self):
        valid, reason, _ = policy.validate_command(
            'zap-baseline.py -t http://juice-shop:3000 -z "-config attackStrength=insane"', SCOPES)
        assert not valid

    def test_config_file_options_are_refused(self):
        for flag in ('-c', '-i', '-n', '-u', '-U'):
            valid, _, _ = policy.validate_command(
                f'zap-baseline.py -t http://juice-shop:3000 {flag} /etc/passwd', SCOPES)
            assert not valid, flag

    def test_report_writing_flags_are_refused(self):
        for flag in ('-x', '-w', '-r', '-J'):
            valid, _, _ = policy.validate_command(
                f'zap-baseline.py -t http://juice-shop:3000 {flag} out.xml', SCOPES)
            assert not valid, flag

    def test_out_of_scope_target_is_refused(self):
        valid, reason, _ = policy.validate_command(
            'zap-baseline.py -t http://other-host:3000 -I', SCOPES)
        assert not valid
        assert 'outside the authorized scope' in reason

    def test_tuning_flags_are_allowed(self):
        valid, _, _ = policy.validate_command(
            'zap-baseline.py -t http://juice-shop:3000 -I -m 2 -D 5 -l WARN', SCOPES)
        assert valid

    def test_baseline_is_not_exploitation_gated(self):
        """Passive crawling is recon, not verification: no letter needed."""
        valid, _, _ = policy.validate_command(
            'zap-baseline.py -t http://juice-shop:3000 -I', SCOPES, allow_exploitation=False)
        assert valid


class TestZapBaselineAnalyzer:
    def analyze(self, stdout):
        return AnalyzerAgent._finding_zap_baseline(stdout, 'zap-baseline.py')

    def test_alert_lines_become_findings(self):
        findings = self.analyze(REALISTIC_BASELINE_OUTPUT)
        by_rule = {f['title']: f for f in findings}
        assert len(findings) == 4
        assert 'ZAP passive audit: Content Security Policy (CSP) Header Not Set' in by_rule

    def test_pass_and_summary_lines_are_not_findings(self):
        findings = self.analyze(REALISTIC_BASELINE_OUTPUT)
        assert not any('PASS' in f['title'] for f in findings)
        assert not any('FAIL-NEW:' == f['title'][:9] for f in findings)

    def test_severity_follows_the_baseline_level(self):
        findings = self.analyze(REALISTIC_BASELINE_OUTPUT)
        by_title = {f['title']: f for f in findings}
        # WARN -> Medium, FAIL -> High, INFO -> Low.
        assert by_title['ZAP passive audit: Cookie No HttpOnly Flag']['severity'] == 'Medium'
        assert by_title['ZAP passive audit: User Controllable HTML Element Attribute (Potential XSS)']['severity'] == 'Low'

    def test_sql_injection_rule_is_scored_critical(self):
        findings = self.analyze(REALISTIC_BASELINE_OUTPUT)
        sqli = next(f for f in findings if 'SQL Injection' in f['title'])
        assert sqli['severity'] == 'Critical'
        assert sqli['exploitability'] == 5

    def test_detail_urls_become_the_endpoint(self):
        findings = self.analyze(REALISTIC_BASELINE_OUTPUT)
        sqli = next(f for f in findings if 'SQL Injection' in f['title'])
        assert sqli['endpoint'] == 'http://juice-shop:3000/search?q=1'
        # The observed URLs are part of the evidence.
        assert 'http://juice-shop:3000/search?q=1' in sqli['evidence']

    def test_findings_carry_the_rule_id_for_remediation(self):
        findings = self.analyze(REALISTIC_BASELINE_OUTPUT)
        csp = next(f for f in findings if 'Content Security Policy' in f['title'])
        assert '10038' in csp['description']
        assert '10038' in csp['remediation']

    def test_clean_baseline_reports_nothing(self):
        stdout = 'PASS: CSP Matters [10068]\nFAIL-NEW: 0\tFAIL-INPROG: 0\tWARN-NEW: 0\tWARN-INPROG: 0\tINFO: 0\tIGNORE: 0\tPASS: 1'
        assert self.analyze(stdout) == []

    def test_short_output_without_detail_lines_still_parses(self):
        """-s suppresses the URL lines; alerts still become findings."""
        stdout = 'WARN-NEW: X-Frame-Options Header Not Set [10020] x 1\nFAIL-NEW: 0\tFAIL-INPROG: 0\tWARN-NEW: 1\tWARN-INPROG: 0\tINFO: 0\tIGNORE: 0\tPASS: 0'
        findings = self.analyze(stdout)
        assert len(findings) == 1
        assert findings[0]['endpoint'] == 'ZAP passive crawl'


def test_default_plan_includes_the_passive_zap_step():
    """The Phase-1 toolchain's third tool is wired into the default plan,
    and every command in that plan stays policy-legal (already covered by
    test_planner, asserted here for the ZAP step specifically)."""
    from modules.planner import planner_agent
    plan = planner_agent.default_plan('juice-shop:3000')
    zap_steps = [step for step in plan if step['tool'] == 'zap-baseline.py']
    assert len(zap_steps) == 1
    assert '-a' not in zap_steps[0]['command']
    valid, _, _ = policy.validate_command(zap_steps[0]['command'], SCOPES)
    assert valid
