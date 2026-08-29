import ipaddress
import re
import shlex
from urllib.parse import urlparse

# Commands run through create_subprocess_exec, never a shell, so shell
# metacharacters carry no injection risk and must stay legal: query strings
# routinely contain '&' and '$'. Only real control characters are refused,
# because they cannot appear in a meaningful argument.
CONTROL_CHARS = ('\n', '\r', '\t', '\x00', '\x0b', '\x0c')

# A DNS query aimed at a resolver is not an assessment action against that
# resolver, so resolvers are validated separately from targets. Restricting
# them to in-scope hosts plus well-known public resolvers keeps the argument
# from doubling as an arbitrary outbound destination.
PUBLIC_RESOLVERS = {
    '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9',
    '149.112.112.112', '208.67.222.222', '208.67.220.220',
    '64.6.64.6', '64.6.65.6', 'dns.google', 'one.one.one.one',
}


class PolicyEngine:
    """Allowlist command policy.

    Every flag a tool may receive is enumerated per tool. Anything not
    enumerated is refused, so a file-write or destination-override flag that
    nobody thought to enumerate fails closed instead of slipping through the
    gaps in a blocklist. Flag semantics are per tool as well: 'nmap -A' takes
    no value while 'curl -A' does, and a single shared table cannot express
    both without swallowing the hostname of one or the other.

    Each spec may define:
      bool_flags        flags taking no value
      value_flags       flags taking a value that is not a target
      target_flags      flags taking a value that IS a target (scope checked)
      resolver_flags    flags taking a value that is a DNS resolver
      attached_patterns regexes for self-contained flags such as -T4 or +short
      resolver_prefix   sigil marking a resolver argument, e.g. dig's '@'
      resolver_positionals  index from which extra positionals are resolvers
    """

    capabilities = {
        'network_discovery': {
            'tools': {
                'nmap': {
                    'risk': 'low',
                    # -sC and --script are deliberately absent: both run NSE.
                    'bool_flags': {
                        '-sV', '-sS', '-sT', '-sU', '-sn', '-sP', '-Pn', '-A', '-O',
                        '-v', '-vv', '-vvv', '-d', '-n', '-R', '-F', '-r', '-6',
                        '--open', '--reason', '--traceroute', '--osscan-limit',
                        '--version-light', '--version-all', '--no-stylesheet',
                    },
                    'value_flags': {
                        '-p', '--ports', '--top-ports', '--exclude', '--max-retries',
                        '--host-timeout', '--max-rtt-timeout', '--min-rtt-timeout',
                        '--initial-rtt-timeout', '--min-rate', '--max-rate',
                        '--scan-delay', '--max-scan-delay', '--version-intensity',
                        '--min-hostgroup', '--max-hostgroup', '--min-parallelism',
                        '--max-parallelism', '-S', '-e', '-g', '--source-port',
                    },
                    'attached_patterns': (r'^-T[0-5]$', r'^-p[\d,\-]+$'),
                },
                'traceroute': {
                    'risk': 'low',
                    'bool_flags': {'-I', '-T', '-U', '-n', '-4', '-6', '-d', '-A', '-e'},
                    'value_flags': {
                        '-m', '--max-hops', '-p', '--port', '-q', '--queries',
                        '-w', '--wait', '-s', '--source', '-f', '--first',
                        '-N', '--sim-queries', '-z', '--sendwait', '-i', '--interface',
                    },
                },
            }
        },
        'dns_enumeration': {
            'tools': {
                'dig': {
                    'risk': 'low',
                    'bool_flags': {'-4', '-6', '-v'},
                    'value_flags': {'-t', '-c', '-p', '-b', '-k', '-y'},
                    'target_flags': {'-q', '-x'},
                    'resolver_prefix': '@',
                    # dig's +options are self-contained switches such as
                    # +short, +noall, +answer, +trace, +time=2.
                    'attached_patterns': (r'^\+[a-z]+(=[A-Za-z0-9_.\-]+)?$',),
                },
                'nslookup': {
                    'risk': 'low',
                    'bool_flags': {'-debug', '-nodebug', '-recurse', '-norecurse', '-vc', '-novc'},
                    'attached_patterns': (
                        r'^-(type|querytype|class|port|timeout|retry|domain)=[A-Za-z0-9_.\-]+$',
                    ),
                    # 'nslookup name server' - the second positional is a resolver.
                    'resolver_positionals': 1,
                },
            }
        },
        'web_inspection': {
            'tools': {
                'curl': {
                    'risk': 'low',
                    # curl is the one tool here that genuinely follows POSIX
                    # bundling (-sSL). nuclei and nslookup use single-dash long
                    # flags, where decomposing would misread '-silent' as '-s'.
                    'bundled_short_flags': True,
                    # Absent by design: -o/-O/--output*/-T/--upload-file/-D/
                    # --dump-header/--trace*/-c/--cookie-jar write files;
                    # -d/--data*/-F/--form*/--json send bodies; -K/--config
                    # can redefine every other option from a file; -x/--proxy*/
                    # --resolve/--connect-to/--unix-socket retarget the
                    # connection; -X/--request changes the method; -H/--header
                    # stays out to preserve the original Host-override control.
                    'bool_flags': {
                        '-I', '--head', '-s', '--silent', '-S', '--show-error',
                        '-L', '--location', '-k', '--insecure', '-i', '--include',
                        '-v', '--verbose', '-f', '--fail', '-4', '--ipv4',
                        '-6', '--ipv6', '-g', '--globoff', '--compressed',
                        '--http1.0', '--http1.1', '--http2', '--path-as-is',
                        '--tcp-nodelay', '--no-keepalive', '-#', '--progress-bar',
                        # Minimum-version switches take no value; only --tls-max
                        # does. Listing one of these as a value flag made it eat
                        # the following argument, which is usually the URL.
                        '--tlsv1', '--tlsv1.0', '--tlsv1.1', '--tlsv1.2', '--tlsv1.3',
                    },
                    'value_flags': {
                        '-A', '--user-agent', '-e', '--referer', '-m', '--max-time',
                        '--connect-timeout', '--max-redirs', '--retry',
                        '--retry-delay', '--retry-max-time', '--limit-rate',
                        '--tls-max',
                    },
                    'target_flags': {'--url'},
                },
                'whatweb': {
                    'risk': 'low',
                    'bool_flags': {
                        '-v', '--verbose', '-q', '--quiet', '--no-errors',
                        '--colour=never', '--color=never',
                    },
                    'value_flags': {
                        '-a', '--aggression', '-U', '--user-agent', '-t',
                        '--max-threads', '--read-timeout', '--follow-redirect',
                        '-H', '--header', '--wait',
                        # Takes a number of seconds. Listed as a boolean it left
                        # that number to be read as a positional target, so a
                        # legitimate command failed the scope check on '5'.
                        '--open-timeout',
                    },
                    'attached_patterns': (
                        r'^-(a|t)=[A-Za-z0-9_.\-]+$',
                        r'^--(aggression|max-threads|read-timeout|follow-redirect|user-agent|wait|open-timeout)=[A-Za-z0-9_.\-]+$',
                    ),
                },
                'sslscan': {
                    'risk': 'low',
                    'bool_flags': {
                        '--no-colour', '--no-color', '--show-certificate',
                        '--no-failed', '--show-ciphers', '--show-times',
                        '--ssl2', '--ssl3', '--tls10', '--tls11', '--tls12',
                        '--tls13', '--tlsall', '--no-cipher-details',
                        '--no-ciphersuites', '--no-heartbleed', '--ipv4', '--ipv6',
                        # sslscan has no bare --starttls; the protocol is part of
                        # the flag name and it takes no value. Listing the bare
                        # form as a value flag accepted a spelling that does not
                        # exist while rejecting every one that does.
                        '--starttls-ftp', '--starttls-imap', '--starttls-irc',
                        '--starttls-ldap', '--starttls-pop3', '--starttls-smtp',
                        '--starttls-mysql', '--starttls-psql', '--starttls-xmpp',
                    },
                    'value_flags': {'--sni-name', '--timeout', '--connect-timeout'},
                    'attached_patterns': (
                        r'^--(sni-name|timeout|connect-timeout)=[A-Za-z0-9_.\-]+$',
                    ),
                },
                'nuclei': {
                    'risk': 'moderate',
                    # Absent by design: -o/-output/-sr/-store-resp and every
                    # *-export flag write files; -irr/-interactsh-server sends
                    # findings out of band; -code/-enable-code-templates runs
                    # arbitrary code; -l/-list/-turl/-template-url load targets
                    # or templates from outside the approved plan.
                    'bool_flags': {
                        '-silent', '-nc', '-no-color', '-v', '-verbose',
                        '-duc', '-disable-update-check', '-ni', '-no-interactsh',
                        '-jsonl', '-json', '-stats', '-fr', '-follow-redirects',
                        '-vv', '-debug',
                    },
                    'value_flags': {
                        '-t', '-templates', '-severity', '-s', '-tags', '-itags',
                        '-etags', '-c', '-concurrency', '-rl', '-rate-limit',
                        '-timeout', '-retries', '-eid', '-exclude-id', '-id',
                        '-template-id', '-et', '-exclude-templates', '-mhe',
                        '-max-host-error', '-H', '-header', '-bs', '-bulk-size',
                    },
                    'target_flags': {'-u', '-target'},
                },
            }
        },
    }

    def tool_registry(self):
        return {
            tool: {'capability': capability, **rules}
            for capability, group in self.capabilities.items()
            for tool, rules in group['tools'].items()
        }

    def public_capabilities(self):
        return [
            {'id': name, 'tools': [{'name': tool, 'risk': rules['risk']} for tool, rules in group['tools'].items()]}
            for name, group in self.capabilities.items()
        ]

    def normalize_host(self, value):
        value = (value or '').strip()
        if not value:
            return ''
        # A bare IPv6 literal carries no brackets, and urlparse reads everything
        # after the first colon as a port, which discards the address entirely
        # and left '::1' normalizing to ''. Every IPv6 scope silently matched
        # nothing as a result, so recognise the literal before parsing.
        literal = self._as_ip(value.strip('[]'))
        if literal is not None:
            return str(literal)
        parsed = urlparse(value if '://' in value else f'//{value}')
        host = (parsed.hostname or value.split(':')[0]).strip('[]').lower().rstrip('.')
        # Canonicalise so '0:0:0:0:0:0:0:1' and '::1' compare equal.
        bracketed = self._as_ip(host)
        return str(bracketed) if bracketed is not None else host

    @staticmethod
    def _as_ip(value):
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            return None

    @staticmethod
    def _as_network(value):
        try:
            return ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None

    def validate_target(self, target, authorized_scopes):
        host = self.normalize_host(target)
        if not host:
            return False
        host_ip = self._as_ip(host)
        for scope in filter(None, authorized_scopes):
            scope_raw = str(scope).strip()
            network = self._as_network(scope_raw)
            if host_ip is not None and network is not None:
                if host_ip in network:
                    return True
                continue
            scope_host = self.normalize_host(scope_raw)
            if scope_host and (host == scope_host or host.endswith('.' + scope_host)):
                return True
        return False

    def validate_resolver(self, resolver, authorized_scopes):
        host = self.normalize_host(resolver)
        return bool(host) and (host in PUBLIC_RESOLVERS or self.validate_target(resolver, authorized_scopes))

    def _is_flag(self, token, spec):
        if token in ('-', '--'):
            return False
        if token.startswith('-'):
            return True
        return token.startswith('+') and bool(spec.get('attached_patterns'))

    def _matches_attached(self, token, spec):
        return any(re.match(pattern, token) for pattern in spec.get('attached_patterns', ()))

    def _expand_bundle(self, token, spec):
        """Resolve a POSIX short-flag bundle such as curl's -sSL.

        Returns (pending_kind, flag) when the bundle resolves, or None when it
        does not. Every character must be a permitted boolean flag; only the
        final character may take a value, so an ambiguous mid-bundle value flag
        fails closed rather than swallowing the rest of the token.
        """
        if not spec.get('bundled_short_flags') or not re.match(r'^-[A-Za-z0-9#]{2,}$', token):
            return None
        bool_flags = spec.get('bool_flags', set())
        value_flags = spec.get('value_flags', set())
        characters = token[1:]
        for index, character in enumerate(characters):
            flag = '-' + character
            if flag in bool_flags:
                continue
            if flag in value_flags and index == len(characters) - 1:
                return 'value', flag
            return None
        return None, token

    def scan_arguments(self, tokens, spec):
        """Split arguments into targets and resolvers using the tool's own spec.

        Returns (targets, resolvers, error). Unknown flags produce an error so
        the caller can fail closed.
        """
        bool_flags = spec.get('bool_flags', set())
        value_flags = spec.get('value_flags', set())
        target_flags = spec.get('target_flags', set())
        resolver_flags = spec.get('resolver_flags', set())
        prefix = spec.get('resolver_prefix')

        targets, resolvers, positionals = [], [], []
        pending = None
        pending_flag = None

        for token in tokens[1:]:
            if pending:
                if pending == 'target':
                    targets.append(token)
                elif pending == 'resolver':
                    resolvers.append(token)
                pending = None
                pending_flag = None
                continue

            if prefix and token.startswith(prefix) and len(token) > len(prefix):
                resolvers.append(token[len(prefix):])
                continue

            if self._is_flag(token, spec):
                base, _, attached = token.partition('=')
                if token in bool_flags:
                    continue
                if token in value_flags:
                    pending, pending_flag = 'value', token
                    continue
                if token in target_flags:
                    pending, pending_flag = 'target', token
                    continue
                if token in resolver_flags:
                    pending, pending_flag = 'resolver', token
                    continue
                if attached:
                    if base in value_flags or base in bool_flags:
                        continue
                    if base in target_flags:
                        targets.append(attached)
                        continue
                    if base in resolver_flags:
                        resolvers.append(attached)
                        continue
                if self._matches_attached(token, spec):
                    continue
                bundle = self._expand_bundle(token, spec)
                if bundle is not None:
                    pending, pending_flag = bundle
                    continue
                return None, None, token
            positionals.append(token)

        if pending:
            return None, None, pending_flag

        cutoff = spec.get('resolver_positionals')
        if cutoff is not None and len(positionals) > cutoff:
            targets.extend(positionals[:cutoff])
            resolvers.extend(positionals[cutoff:])
        else:
            targets.extend(positionals)
        return targets, resolvers, None

    def validate_command(self, command, authorized_scopes, expected_tool=None):
        if not command or not command.strip():
            return False, 'A command is required.', None
        if any(char in command for char in CONTROL_CHARS):
            return False, 'Control characters are not permitted in a command.', None
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError:
            return False, 'Command syntax is invalid.', None
        registry = self.tool_registry()
        if not tokens or tokens[0] not in registry:
            return False, f"Executable is not covered by an enabled capability: {', '.join(sorted(registry))}.", None
        if expected_tool and tokens[0] != expected_tool:
            return False, f'Declared tool {expected_tool} does not match command executable {tokens[0]}.', None

        rules = registry[tokens[0]]
        targets, resolvers, rejected = self.scan_arguments(tokens, rules)
        if rejected is not None:
            return False, f'Blocked flag for {tokens[0]}: {rejected} is not in the permitted flag set for this capability.', rules
        if not targets:
            return False, 'The command must contain an explicit target.', rules
        outside = [target for target in targets if not self.validate_target(target, authorized_scopes)]
        if outside:
            return False, f'A command target is outside the authorized scope: {outside[0]}.', rules
        unapproved = [resolver for resolver in resolvers if not self.validate_resolver(resolver, authorized_scopes)]
        if unapproved:
            return False, f'Resolver {unapproved[0]} is neither in scope nor a well-known public resolver.', rules
        return True, f"Allowed {rules['capability']} capability ({rules['risk']} risk); HITL approval required.", rules


policy_engine = PolicyEngine()
