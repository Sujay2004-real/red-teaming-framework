"""Value-level policy for options that affect load, routing, or local files.

Limits are deliberately conservative and apply to every occurrence of an
option, including aliases and --option=value spellings.
"""
import re

PLANNING_RULES = (
    'Use explicit redirect controls: whatweb --follow-redirect never; nuclei -dr; '
    'sqlmap --ignore-redirects. Do not use curl -L or nuclei -fr. '
    'Use nmap --max-rate 30 and nuclei -rl 30 -ni; no custom template files. '
    'SQLmap verification uses --risk 1 --level 1 --threads 3 --technique B; '
    'no tamper scripts, file-reading arguments, or routing override headers. '
    'Every secondary URL, including --csrf-url and --second-order, must be in scope.'
)


def limits(*groups):
    return {flag: (low, high, kind) for flags, low, high, kind in groups
            for flag in flags.split()}


NUMERIC_LIMITS = {
    'nmap': limits(
        ('--min-rate --max-rate', 1, 30, 'number'),
        ('--max-retries', 0, 3, 'integer'),
        ('--top-ports', 1, 1000, 'integer'),
        ('--version-intensity', 0, 9, 'integer'),
        ('--min-hostgroup --max-hostgroup --min-parallelism --max-parallelism', 1, 32, 'integer'),
        ('--host-timeout', 1, 360, 'duration'),
        ('--max-rtt-timeout --min-rtt-timeout --initial-rtt-timeout', .001, 60, 'duration'),
        ('--scan-delay --max-scan-delay', 0, 60, 'duration'),
        ('-g --source-port', 1, 65535, 'integer'),
        ('-T', 0, 4, 'integer')),
    'curl': limits(
        ('-m --max-time --retry-max-time', .001, 360, 'number'),
        ('--connect-timeout', .001, 60, 'number'),
        ('--retry', 0, 3, 'integer'),
        ('--retry-delay', 0, 30, 'number'),
        ('--max-redirs', 0, 0, 'integer')),
    'whatweb': limits(
        ('-a --aggression', 1, 3, 'integer'),
        ('-t --max-threads', 1, 10, 'integer'),
        ('--read-timeout --open-timeout', 1, 60, 'integer'),
        ('--wait', 0, 30, 'number')),
    'sslscan': limits(('--timeout --connect-timeout', 1, 60, 'integer')),
    'nuclei': limits(
        ('-rl -rate-limit', 1, 30, 'integer'),
        ('-c -concurrency -bs -bulk-size', 1, 25, 'integer'),
        ('-timeout', 1, 60, 'integer'),
        ('-retries', 0, 3, 'integer'),
        ('-mhe -max-host-error', 1, 30, 'integer')),
    'sqlmap': limits(
        ('--risk --level', 1, 1, 'integer'),
        ('--threads', 1, 3, 'integer'),
        ('--timeout', 1, 60, 'number'),
        ('--retries', 0, 2, 'integer'),
        ('--delay', 0, 30, 'number'),
        ('--time-sec', 1, 5, 'integer'),
        ('-v --verbose', 0, 6, 'integer'),
        ('--code', 100, 599, 'integer')),
    'zap-baseline.py': limits(
        ('-m', 1, 5, 'integer'), ('-D', 0, 30, 'integer'),
        ('-p', 1024, 65535, 'integer')),
    'traceroute': limits(
        ('-m --max-hops -f --first', 1, 30, 'integer'),
        ('-q --queries', 1, 3, 'integer'),
        ('-N --sim-queries', 1, 16, 'integer'),
        ('-w --wait', .1, 10, 'number'),
        ('-z --sendwait', 0, 10, 'number'),
        ('-p --port', 1, 65535, 'integer')),
    'dig': limits(('-p', 1, 65535, 'integer'),
                  ('+time +timeout', 1, 30, 'integer'),
                  ('+tries +retry', 1, 3, 'integer')),
    'nslookup': limits(('-port', 1, 65535, 'integer'),
                       ('-timeout', 1, 30, 'integer'),
                       ('-retry', 1, 3, 'integer')),
}


def numeric_error(flag, value, rule):
    low, high, kind = rule
    pattern = r'\d+' if kind == 'integer' else r'\d+(?:\.\d+)?'
    if kind == 'duration':
        pattern += r'(?:ms|s|m|h)?'
    if value is None or not re.fullmatch(pattern, value):
        return f'{flag} requires a finite non-negative {kind}'
    suffix = re.search(r'[a-z]+$', value)
    multiplier = {'ms': .001, 's': 1, 'm': 60, 'h': 3600}
    amount = float(value[:suffix.start()] if suffix else value)
    amount *= multiplier[suffix.group()] if suffix else 1
    if not low <= amount <= high:
        return f'{flag} must be between {low:g} and {high:g}' + (' seconds' if kind == 'duration' else '')
    return None


def validate_argument_values(tool, arguments):
    for flag, value in arguments:
        rule = NUMERIC_LIMITS.get(tool, {}).get(flag)
        if rule and (error := numeric_error(flag, value, rule)):
            return error
        if value is None:
            continue
        if tool == 'curl':
            # @file, name@file, and name=@file can read local credentials.
            if flag in {'-d', '--data', '--data-ascii', '--data-binary', '--json'} and value.startswith('@'):
                return f'{flag} accepts inline data only; file reads are not permitted'
            if flag == '--data-urlencode' and '@' in value.split('=', 1)[0]:
                return f'{flag} accepts inline data only; file reads are not permitted'
            if flag == '--tls-max' and value not in {'1.0', '1.1', '1.2', '1.3'}:
                return 'Unsupported TLS version'
        if tool == 'whatweb' and flag == '--follow-redirect' and value != 'never':
            return 'Redirects require separate destination review; use --follow-redirect never'
        if tool == 'sqlmap' and flag == '--technique' and value != 'B':
            return 'Only bounded boolean-based sqlmap verification (--technique B) is permitted'
        if tool in {'whatweb', 'nuclei', 'sqlmap'} and flag in {'-H', '--header', '-header', '--headers'}:
            if value.startswith('@') or not re.match(r'^[A-Za-z0-9-]+\s*:', value):
                return f'{flag} requires an inline HTTP header'
            if value.split(':', 1)[0].strip().lower() in {'host', 'x-forwarded-host', 'forwarded'}:
                return 'Routing override headers are not permitted'
        if tool == 'nmap' and flag in {'-p', '--ports'}:
            if not re.fullmatch(r'\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*', value):
                return f'{flag} requires explicit numeric ports or ranges'
            for part in value.split(','):
                ends = [int(x) for x in part.split('-')]
                if any(x < 1 or x > 65535 for x in ends) or ends[0] > ends[-1]:
                    return f'{flag} contains an invalid port range'
        if tool == 'zap-baseline.py' and flag == '-l' and value not in {'PASS', 'IGNORE', 'INFO', 'WARN', 'FAIL'}:
            return '-l requires a ZAP alert level'
    return None
