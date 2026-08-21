import ipaddress
import re
import shlex
from urllib.parse import urlparse

class PolicyEngine:
    dangerous_chars = (';', '|', '&', '`', '$', '>', '<', '\n', '\r')
    capabilities = {
        'network_discovery': {
            'tools': {
                'nmap': {'blocked_flags': {'-oG', '-oX', '-oN', '-oA', '--script', '--script-args', '-iL'}, 'risk': 'low'},
                'traceroute': {'blocked_flags': {'-F'}, 'risk': 'low'},
            }
        },
        'dns_enumeration': {
            'tools': {
                'dig': {'blocked_flags': {'-f'}, 'risk': 'low'},
                'nslookup': {'blocked_flags': set(), 'risk': 'low'},
            }
        },
        'web_inspection': {
            'tools': {
                'curl': {'blocked_flags': {'-o', '--output', '-O', '--remote-name', '-T', '--upload-file', '-d', '--data', '--data-raw', '-X', '--request', '--config'}, 'risk': 'low'},
                'whatweb': {'blocked_flags': {'--log-brief', '--log-verbose', '--log-xml', '--log-json', '--log-sql'}, 'risk': 'low'},
                'sslscan': {'blocked_flags': {'--xml'}, 'risk': 'low'},
                'nuclei': {'blocked_flags': {'-o', '-output', '-irr', '-interactsh-server', '-code'}, 'risk': 'moderate'},
            }
        },
    }

    def tool_registry(self):
        return {tool: {'capability': capability, **rules} for capability, group in self.capabilities.items() for tool, rules in group['tools'].items()}

    def public_capabilities(self):
        return [{'id': name, 'tools': [{'name': tool, 'risk': rules['risk']} for tool, rules in group['tools'].items()]} for name, group in self.capabilities.items()]

    def normalize_host(self, value):
        value = (value or '').strip()
        parsed = urlparse(value if '://' in value else f'//{value}')
        return (parsed.hostname or value.split(':')[0]).strip('[]').lower().rstrip('.')

    def validate_target(self, target, authorized_scopes):
        host = self.normalize_host(target)
        for scope in filter(None, authorized_scopes):
            scope_host = self.normalize_host(scope)
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(scope, strict=False): return True
            except ValueError:
                if host == scope_host or host.endswith('.' + scope_host): return True
        return False

    def extract_targets(self, tokens):
        targets = []
        skip_next = False
        value_flags = {'-p', '--port', '-T', '--timeout', '--connect-timeout', '-H', '--header', '-A', '--user-agent', '-t', '-severity'}
        for token in tokens[1:]:
            if skip_next:
                skip_next = False; continue
            if token in value_flags:
                skip_next = True; continue
            if token.startswith('-') or token.isdigit(): continue
            host = self.normalize_host(token)
            if host and ('.' in host or ':' in token or host == 'localhost' or re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host)):
                targets.append(token)
        return targets

    def validate_command(self, command, authorized_scopes):
        if not command or any(char in command for char in self.dangerous_chars):
            return False, 'Shell control characters are not permitted.', None
        try: tokens = shlex.split(command, posix=True)
        except ValueError: return False, 'Command syntax is invalid.', None
        registry = self.tool_registry()
        if not tokens or tokens[0] not in registry:
            return False, f"Executable is not covered by an enabled capability: {', '.join(sorted(registry))}.", None
        rules = registry[tokens[0]]
        normalized_flags = {token.split('=', 1)[0] for token in tokens if token.startswith('-')}
        blocked = normalized_flags & rules['blocked_flags']
        if blocked: return False, f"Blocked flag for {tokens[0]}: {', '.join(sorted(blocked))}.", rules
        targets = self.extract_targets(tokens)
        if not targets: return False, 'The command must contain an explicit target.', rules
        if any(not self.validate_target(target, authorized_scopes) for target in targets):
            return False, 'A command target is outside the authorized scope.', rules
        return True, f"Allowed {rules['capability']} capability ({rules['risk']} risk); HITL approval required.", rules

policy_engine = PolicyEngine()