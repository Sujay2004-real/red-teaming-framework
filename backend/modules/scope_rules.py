"""Structured engagement rules enforced again when a queued command starts."""
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlsplit, unquote
import shlex
import re


def command_destinations(command, targets):
    """Include destinations embedded in Metasploit's validated resource script."""
    result = list(targets)
    tokens = shlex.split(command)
    if tokens and tokens[0] == 'msfconsole' and '-x' in tokens:
        script = tokens[tokens.index('-x') + 1]
        for match in re.finditer(r'(?:^|;)\s*set\s+RHOSTS?\s+([^;]+)', script, re.I):
            result.extend(re.split(r'[,\s]+', match.group(1).strip()))
    return result


def scopes_overlap(target, excluded):
    try:
        a, b = ipaddress.ip_network(target, strict=False), ipaddress.ip_network(excluded, strict=False)
        return a.version == b.version and a.overlaps(b)
    except ValueError:
        return scope_contains(target, excluded) or scope_contains(excluded, target)


def scope_contains(target, scope):
    target, scope = str(target).strip(), str(scope).strip()
    try:
        network = ipaddress.ip_network(scope, strict=False)
        try:
            requested = ipaddress.ip_network(target, strict=False)
            return requested.version == network.version and requested.subnet_of(network)
        except ValueError:
            return ipaddress.ip_address(urlsplit(target).hostname) in network
    except (ValueError, TypeError):
        pass
    try:
        candidate = urlsplit(target if '://' in target else '//' + target)
        permitted = urlsplit(scope if '://' in scope else '//' + scope)
        host, allowed = (candidate.hostname or '').lower().rstrip('.'), (permitted.hostname or '').lower().rstrip('.')
        if not host or not allowed:
            return False
        if allowed.startswith('*.'):
            matched = host.endswith('.' + allowed[2:]) and host != allowed[2:]
        else:
            matched = host == allowed
        if not matched:
            return False
        if permitted.scheme:
            if candidate.scheme != permitted.scheme:
                return False
            default = 443 if permitted.scheme == 'https' else 80
            if (candidate.port or default) != (permitted.port or default):
                return False
            prefix = unquote(permitted.path).rstrip('/')
            path = unquote(candidate.path)
            if any(segment in {'.', '..'} for segment in path.split('/')):
                return False
            if prefix and path != prefix and not path.startswith(prefix + '/'):
                return False
        return True
    except (ValueError, TypeError):
        return False


def check_window(policy, now=None):
    now = now or datetime.now(timezone.utc)
    for key, comparison, message in (
        ('starts_at', lambda a, b: a < b, 'The authorized test window has not started'),
        ('ends_at', lambda a, b: a >= b, 'The authorized test window has expired'),
    ):
        if policy.get(key):
            boundary = datetime.fromisoformat(policy[key].replace('Z', '+00:00'))
            if comparison(now, boundary):
                return message
    return None
