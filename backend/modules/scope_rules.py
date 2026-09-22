"""Structured engagement rules enforced again when a queued command starts."""
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlsplit, unquote
import shlex
import re


def command_destinations(command, targets):
    """Include destinations embedded in Metasploit's validated resource script.

    The policy engine accepts the resource script under four equivalent
    spellings (``-x s``, ``-x=s``, ``--execute-command s``, ``--execute-command=s``
    — see policy_engine.validate_command). The exclusion overlap check in
    main.py depends on this function to surface the script's RHOSTS, so it must
    recognize every spelling the policy layer does; otherwise a deliberately
    excluded host could be reached through a spelling this parser missed while
    the policy layer still validated the script against the authorized scopes.
    """
    result = list(targets)
    tokens = shlex.split(command)
    if not (tokens and tokens[0] == 'msfconsole'):
        return result
    scripts = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in ('-x', '--execute-command'):
            if index + 1 < len(tokens):
                scripts.append(tokens[index + 1])
            index += 2
            continue
        for prefix in ('-x=', '--execute-command='):
            if token.startswith(prefix):
                scripts.append(token[len(prefix):])
                break
        index += 1
    for script in scripts:
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
