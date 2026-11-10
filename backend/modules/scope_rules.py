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


def promotion_scope(address, authorized_scopes, excluded_scopes):
    try:
        return _promotion_scope(address, authorized_scopes, excluded_scopes)
    except (ValueError, TypeError):
        return False


def _promotion_scope(address, authorized_scopes, excluded_scopes):
    """Require permission for an entire individual host before promotion.

    A URL, path or port permission cannot authorize a host-wide recon plan.
    Operators can assess those narrower resources through a scoped target.
    No DNS resolution is used to turn an authorized name into a different IP.
    """
    address = str(address).strip()
    if _host_of(address) != address.lower().rstrip('.'):
        return False
    network = _network_of(address)
    if network is not None and network.num_addresses != 1:
        return False
    if any(scopes_overlap(address, excluded) for excluded in excluded_scopes):
        return False
    for scope in authorized_scopes:
        if _network_of(scope) is None:
            parsed = _split(scope)
            if parsed.scheme or parsed.port is not None or parsed.path or parsed.query or parsed.fragment or parsed.username:
                continue
        if scope_contains(address, scope):
            return True
    return False


def _split(value):
    """Parse a scope entry or target, tolerating the forms tools actually use.

    ``//host/share``, ``user:pass@host``, ``smb://host``, ``host:8080`` and a
    bare address must all resolve to the same host. Prefixing an authority-less
    value with ``//`` is what makes urlparse treat the first token as the host
    instead of as a path, and a value that already starts with ``//`` must not
    be prefixed a second time or the authority is lost.
    """
    value = str(value).strip()
    if value.startswith('//'):
        return urlsplit(value)
    return urlsplit(value if '://' in value else '//' + value)


def _host_of(value):
    """The hostname or address a scope entry or target names, or ''."""
    value = str(value).strip()
    if not value:
        return ''
    literal = _address_of(value.strip('[]'))
    if literal is not None:
        return str(literal)
    parsed = _split(value)
    return (parsed.hostname or '').strip('[]').lower().rstrip('.')


def _address_of(host):
    try:
        return ipaddress.ip_address(host)
    except (ValueError, TypeError):
        return None


def _network_of(value):
    try:
        return ipaddress.ip_network(str(value).strip(), strict=False)
    except (ValueError, TypeError):
        return None


def scope_contains(target, scope):
    target, scope = str(target).strip(), str(scope).strip()
    network = _network_of(scope)
    if network is not None:
        # A CIDR target is checked as a network (a /24 must not be accepted by
        # a /25 scope just because its network address lands inside it); a
        # single address - bare or embedded in user@host / //host/share - is
        # checked as an address.
        requested = _network_of(target)
        if requested is not None:
            return requested.version == network.version and requested.subnet_of(network)
        address = _address_of(_host_of(target))
        return (address is not None and address.version == network.version
                and address in network)
    permitted = _split(scope)
    allowed = (permitted.hostname or '').strip('[]').lower().rstrip('.')
    host = _host_of(target)
    if not host or not allowed:
        return False
    if allowed.startswith('*.'):
        matched = host.endswith('.' + allowed[2:]) and host != allowed[2:]
    else:
        matched = host == allowed
    if not matched:
        return False
    candidate = _split(target)
    if permitted.port is not None:
        default_port = {'http': 80, 'https': 443, 'ssh': 22, 'ftp': 21, 'smb': 445}.get(candidate.scheme)
        if (candidate.port or default_port) != permitted.port:
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
