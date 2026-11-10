"""Versioned technique adapters. Inputs are data; adapters own executable arguments.

Adding an adapter requires a reviewed Python implementation and policy support.
Scenario imports can compose these adapters, never install executable code.
"""
import ipaddress
import re
import shlex
from dataclasses import dataclass
from urllib.parse import urlsplit


def validate_input(kind, value):
    if not isinstance(value, str) or not value.strip() or len(value) > 1000:
        raise ValueError('Technique inputs must be nonempty strings of at most 1000 characters')
    value = value.strip()
    if any(ord(c) < 32 for c in value) or value.startswith('-'):
        raise ValueError('Technique inputs cannot contain control characters or options')
    if kind == 'url':
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise ValueError('Invalid HTTP(S) URL') from exc
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username
                or parsed.password or parsed.fragment or any(c.isspace() for c in value)
                or (port is not None and not 1 <= port <= 65535)):
            raise ValueError('Use an HTTP(S) URL without credentials, fragments, or whitespace')
    elif kind == 'host':
        try:
            ipaddress.ip_address(value)
        except ValueError:
            if len(value) > 253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', part)
                                          for part in value.rstrip('.').split('.')):
                raise ValueError('Use one IP address or hostname')
    elif kind == 'ports':
        if not re.fullmatch(r'\d{1,5}(?:,\d{1,5}){0,31}', value):
            raise ValueError('Use a comma-separated list of at most 32 ports')
        if any(not 1 <= int(port) <= 65535 for port in value.split(',')):
            raise ValueError('Ports must be between 1 and 65535')
    elif kind == 'parameter':
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,120}', value):
            raise ValueError('Use one parameter name')
    else:
        raise ValueError('Unknown technique input type')
    return value


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tool: str
    phase: str
    inputs: tuple
    arguments: tuple
    description: str
    attack: tuple = ()
    version: str = '1.0.0'
    cleanup: str = 'No persistent target changes are requested by this adapter. Review scanner artifacts and target logs.'

    @property
    def key(self):
        return f'{self.id}@{self.version}'

    def compile(self, values):
        if set(values) != {name for name, _ in self.inputs}:
            raise ValueError(f'{self.id} requires exactly: ' + ', '.join(name for name, _ in self.inputs))
        checked = {name: validate_input(kind, values[name]) for name, kind in self.inputs}
        args = [arg.format(**checked) for arg in self.arguments]
        return {'tool': self.tool, 'command': shlex.join([self.tool, *args]), 'phase': self.phase,
                'reason': self.description, 'enabled': True, 'technique': self.key,
                'attack_techniques': list(self.attack)}

    def public(self):
        return {'id': self.id, 'version': self.version, 'key': self.key, 'name': self.name,
                'tool': self.tool, 'phase': self.phase, 'description': self.description,
                'inputs': [{'name': name, 'type': kind} for name, kind in self.inputs],
                'attack_techniques': list(self.attack), 'cleanup': self.cleanup}


_BUILTINS = (
    Technique('http.headers', 'HTTP response headers', 'curl', 'recon', (('url', 'url'),),
              ('-sS', '-I', '--max-time', '20', '{url}'), 'Capture the response and its security headers.', ('T1595',)),
    Technique('http.fingerprint', 'Web technology fingerprint', 'whatweb', 'recon', (('url', 'url'),),
              ('-a', '1', '--follow-redirect', 'never', '--color=never', '{url}'),
              'Identify technologies disclosed by the application.', ('T1592.002',)),
    Technique('network.services', 'TCP service inventory', 'nmap', 'recon', (('host', 'host'), ('ports', 'ports')),
              ('-sT', '-sV', '--version-light', '-Pn', '--max-rate', '10', '-p', '{ports}', '{host}'),
              'Identify services on the explicitly selected TCP ports.', ('T1046',)),
    Technique('web.templates', 'Web exposure checks', 'nuclei', 'recon', (('url', 'url'),),
              ('-u', '{url}', '-tags', 'cve,exposure,misconfig', '-severity', 'medium,high,critical',
               '-rl', '10', '-dr', '-ni', '-nc', '-stats', '-duc', '-silent'),
              'Check the application using the installed exposure and misconfiguration templates.', ('T1595.002',)),
    Technique('web.passive', 'Passive web audit', 'zap-baseline.py', 'recon', (('url', 'url'),),
              ('-t', '{url}', '-I'), 'Crawl the application and audit response content with ZAP.', ('T1595',)),
    Technique('web.sql-injection', 'SQL injection verification', 'sqlmap', 'exploitation',
              (('url', 'url'), ('parameter', 'parameter')),
              ('-u', '{url}', '-p', '{parameter}', '--batch', '--level=1', '--risk=1', '--technique', 'B', '--ignore-redirects'),
              'Verify the designated query parameter under the engagement exploitation permission.', ('T1190',)),
    Technique('web.database-banner', 'Database version evidence', 'sqlmap', 'post_exploitation',
              (('url', 'url'), ('parameter', 'parameter')),
              ('-u', '{url}', '-p', '{parameter}', '--batch', '--level=1', '--risk=1', '--technique', 'B', '--ignore-redirects', '--banner'),
              'Collect bounded database version evidence for a verified injection point.', ('T1082',)),
)
REGISTRY = {item.key: item for item in _BUILTINS}


def technique(key):
    try:
        return REGISTRY[key]
    except KeyError as exc:
        raise ValueError(f'Unsupported technique version: {key}') from exc


def catalog():
    return [item.public() for item in REGISTRY.values()]
