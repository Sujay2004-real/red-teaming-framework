"""Regression cases for destinations and side effects hidden in option values."""
import pytest

from modules.planner import PlannerAgent
from modules.policy_engine import PolicyEngine


SCOPES = ['allowed.example']


@pytest.mark.parametrize('command', [
    'sqlmap -u http://allowed.example/?id=1 --ignore-redirects --csrf-url http://outside.example/token',
    'sqlmap -u http://allowed.example/?id=1 --ignore-redirects --csrf-url=http://outside.example/token',
    'sqlmap -u http://allowed.example/?id=1 --ignore-redirects --second-order=http://outside.example/',
    'sqlmap -u http://allowed.example/ --ignore-redirects --threads 999',
    'sqlmap -u http://allowed.example/ --ignore-redirects --threads=999',
    'sqlmap -u http://allowed.example/ --ignore-redirects --threads 999 --threads 1',
    'sqlmap -u http://allowed.example/ --ignore-redirects --risk 3',
    'sqlmap -u http://allowed.example/ --ignore-redirects --level=5',
    'sqlmap -u http://allowed.example/ --ignore-redirects --technique T',
    'sqlmap -u http://allowed.example/ --ignore-redirects --tamper /tmp/script.py',
    'curl -L http://allowed.example/',
    'curl -sSL http://allowed.example/',
    'curl --head=true http://allowed.example/',
    'curl --max-time nan http://allowed.example/',
    'curl --max-time=0 http://allowed.example/',
    'curl --retry=-1 http://allowed.example/',
    'curl --data @/tmp/secret http://allowed.example/',
    'curl -sd @/tmp/secret http://allowed.example/',
    'curl --json=@/tmp/secret http://allowed.example/',
    'curl --data-urlencode name@/tmp/secret http://allowed.example/',
    'curl --form name=@/tmp/secret http://allowed.example/',
    'curl file://allowed.example/tmp/secret',
    'curl ftp://allowed.example/',
    'curl http://user:password@allowed.example/',
    'curl http://allowed.example/items/[1-99]',
    'whatweb --follow-redirect always http://allowed.example/',
    'whatweb --follow-redirect=never --max-threads=999 http://allowed.example/',
    'nuclei -u http://allowed.example/ -dr -t /tmp/custom.yaml',
    'nuclei -u http://allowed.example/ -dr -templates=https://outside.example/template.yaml',
    'nuclei -u http://allowed.example/ -dr -fr',
    'nuclei -u http://allowed.example/ -dr -rl=10000',
    'nuclei -u http://allowed.example/ -dr -H "Host: outside.example"',
    'nmap --max-rate=10000 allowed.example',
    'nmap -T5 allowed.example',
    'nmap -A allowed.example',
    'nmap -p0 allowed.example',
    'nmap --host-timeout 100h allowed.example',
    'dig -k /tmp/key allowed.example',
    'dig +time=999 allowed.example',
    'nslookup -retry=999 allowed.example',
    'msfconsole -x "use auxiliary/scanner/ssh/ssh_version; run; exit"',
    'msfconsole -x "use auxiliary/scanner/ssh/ssh_version; set RHOSTS allowed.example; set THREADS 999; run; exit"',
    'msfconsole -x "use auxiliary/scanner/ssh/ssh_version; set RHOSTS allowed.example; run; exit" -x "shell"',
])
def test_rejects_hidden_destinations_files_and_unbounded_load(command):
    valid, reason, _ = PolicyEngine().validate_command(command, SCOPES, allow_exploitation=True)
    assert not valid, command
    assert reason


@pytest.mark.parametrize('command', [
    'curl --data "email=user@example.test" http://allowed.example/',
    'curl --data-raw @literal http://allowed.example/',
    'curl --form-string name=@literal http://allowed.example/',
    'curl --data-urlencode name=value http://allowed.example/',
    'curl -sm 30 http://allowed.example/',
    'nmap -T4 -p22,80,443 --host-timeout 2m --max-rate=30 allowed.example',
    'dig +time=2 +tries=2 allowed.example',
    'whatweb --follow-redirect=never --open-timeout=5 http://allowed.example/',
    'sqlmap --url=http://allowed.example/?id=1 --ignore-redirects --threads=3 --risk=1 --level=1 --technique=B',
    'sqlmap -u http://allowed.example/ --ignore-redirects --csrf-url=http://allowed.example/token',
    'msfconsole --execute-command="use auxiliary/scanner/ssh/ssh_version; set RHOSTS allowed.example; set THREADS 3; run; exit"',
])
def test_preserves_bounded_inline_commands(command):
    valid, reason, _ = PolicyEngine().validate_command(command, SCOPES, allow_exploitation=True)
    assert valid, reason


def test_bundled_curl_payload_still_requires_authorization():
    valid, reason, _ = PolicyEngine().validate_command('curl -sd email=x http://allowed.example/', SCOPES)
    assert not valid
    assert 'does not authorize' in reason


@pytest.mark.parametrize('command', [
    'whatweb http://allowed.example/',
    'nuclei -u http://allowed.example/',
    'sqlmap -u http://allowed.example/ --batch',
])
def test_requires_explicit_redirect_controls(command):
    valid, reason, _ = PolicyEngine().validate_command(command, SCOPES, allow_exploitation=True)
    assert not valid
    assert 'redirect' in reason


def test_all_default_commands_pass_the_stricter_policy():
    for step in PlannerAgent().default_plan('allowed.example:8080'):
        valid, reason, _ = PolicyEngine().validate_command(step['command'], SCOPES)
        assert valid, (step['command'], reason)
