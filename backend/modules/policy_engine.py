import ipaddress
import re
import shlex
from urllib.parse import urlparse

from modules.phases import EXPLOITATION_GATED_TOOLS, PAYLOAD_FLAGS
from modules.command_values import numeric_error, validate_argument_values

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

# msfconsole -x script validation. The console is driven by a semicolon-
# separated statement list; each statement must be one of these shapes, and
# the module must sit under an allowed tree. Remote-target set keys are
# scope-checked; LHOST/USER/PASS-style keys stay out so a resource script
# cannot quietly become a credential attack or a listener bind.
MSF_ALLOWED_PREFIXES = (
    'auxiliary/scanner/', 'exploit/unix/', 'exploit/linux/',
    'exploit/windows/', 'exploit/multi/',
)
MSF_ALLOWED_SET_KEYS = {
    'RHOST', 'RHOSTS', 'RPORT', 'PORTS', 'THREADS', 'TIMEOUT', 'SSL', 'VERBOSE',
}
MSF_TARGET_KEYS = {'RHOST', 'RHOSTS'}
MSF_ALLOWED_VERBS = ('run', 'exploit', 'exit', 'back')

# Aggressive lab mode ONLY (target.aggressive_lab + exploitation_authorized).
# These keys let a real exploit module carry a payload and a reverse-handler
# back to the attacker VM, and start a backgrounded session. LHOST/SRVHOST are
# the attacker VM's own addresses (the listener side), so they are validated as
# plain addresses rather than scope-checked against the target. RHOSTS is still
# scope-checked in every mode.
MSF_AGGRESSIVE_SET_KEYS = {
    'PAYLOAD', 'LHOST', 'LPORT', 'SRVHOST', 'SRVPORT', 'TARGETURI', 'SESSION',
}
MSF_ATTACKER_SIDE_KEYS = {'LHOST', 'SRVHOST'}
# Non-interactive post-exploitation: `exploit -z`/`run -j` background the
# session; `sessions -C "<cmd>"` runs a command on the session without a TTY;
# `check` probes exploitability without firing. Interactive `sessions -i`
# stays out — it needs a live console the subprocess cannot provide.
MSF_AGGRESSIVE_VERBS = ('run', 'exploit', 'check', 'sessions', 'exit', 'back')
MSF_PAYLOAD_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9/_\-]+$')


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
                    # -sC, --script and -A are absent: all can run NSE.
                    'bool_flags': {
                        '-sV', '-sS', '-sT', '-sU', '-sn', '-sP', '-Pn', '-O',
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
                    'value_flags': {'-t', '-c', '-p', '-b'},
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
                        '-k', '--insecure', '-i', '--include',
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
                        # Request-body flags: legal for curl only when the
                        # letter authorizes controlled exploitation (a body
                        # carrying a payload is a proof-of-concept, not a
                        # header audit) — enforced via PAYLOAD_FLAGS at
                        # validation time, so they are listed here for shape
                        # and gated separately for permission.
                        '-d', '--data', '--data-ascii', '--data-binary',
                        '--data-raw', '--data-urlencode',
                        '--form-string', '--json',
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
                        '-jsonl', '-json', '-stats', '-dr', '-disable-redirects',
                        '-vv', '-debug',
                    },
                    'value_flags': {
                        '-severity', '-s', '-tags', '-itags',
                        '-etags', '-c', '-concurrency', '-rl', '-rate-limit',
                        '-timeout', '-retries', '-eid', '-exclude-id', '-id',
                        '-template-id', '-et', '-exclude-templates', '-mhe',
                        '-max-host-error', '-H', '-header', '-bs', '-bulk-size',
                    },
                    'target_flags': {'-u', '-target'},
                },
                'zap-baseline.py': {
                    'risk': 'low',
                    # The OWASP ZAP baseline: a PASSIVE crawl-and-audit (it
                    # sends no attack payloads), so it sits in the recon
                    # capability beside curl/whatweb, not with the exploit
                    # tools. The flag surface is kept deliberately tiny.
                    # Absent by design: -a enables ACTIVE scanning (attack
                    # payloads - that is exploitation-grade and belongs behind
                    # the letter's authorization, which this spec can never
                    # grant); -c/-i/-n load rule/context CONFIG FILES; -u
                    # fetches a remote config; -z passes arbitrary options
                    # straight to the ZAP daemon (an escape hatch around this
                    # whole table); -U drives authenticated scanning with
                    # credentials; -x/-w/-r/-J write report files to disk.
                    'bool_flags': {'-d', '-s', '-I'},
                    'value_flags': {
                        # -m spider minutes, -D start delay, -p daemon port,
                        # -l minimum level to show (PASS..FAIL).
                        '-m', '-D', '-p', '-l',
                    },
                    'target_flags': {'-t'},
                },
            }
        },
        'exploitation': {
            'tools': {
                'sqlmap': {
                    'risk': 'high',
                    # Controlled verification only. Absent by design:
                    # --os-shell/--os-pwn/--os-cmd* hand over an interactive
                    # shell or spawn listeners; --file-read/--file-write move
                    # arbitrary files; --sql-shell is an interactive prompt;
                    # --dump/--all/--users/--passwords/--privileges/--dbs/
                    # --tables/--columns enumerate data beyond the bounded
                    # single record the letter authorizes; -z and --wizard
                    # take free-form over-rides of everything below.
                    'bool_flags': {
                        '--batch', '--flush-session', '--fresh-queries', '--ignore-redirects',
                        '--no-color', '--colour=never', '--color=never',
                        '--disable-coloring', '--eta',
                        '--smart', '--null-connection', '--no-cast',
                        '--no-escape', '--parse-errors',
                        # The bounded post-exploitation facts: banner, current
                        # user, current database, DBA status, hostname. Each
                        # prints a single line of evidence, which is exactly
                        # the "one verification record" the letter permits.
                        '--banner', '--current-user', '--current-db',
                        '--is-dba', '--hostname',
                    },
                    'value_flags': {
                        '--data', '--cookie', '--user-agent', '-v', '--verbose',
                        '--referer', '--headers', '--timeout', '--retries',
                        '--delay', '--threads', '--risk', '--level',
                        '--technique', '--dbms', '--method', '--time-sec',
                        '--string', '--not-string', '--regexp', '--code',
                        '--csrf-token', '--csrf-method',
                        '--csrf-data', '--charset', '--prefix',
                        '--suffix', '--param-del', '--cookie-del',
                        '--union-cols', '--union-char', '--union-from',
                        '--exclude', '--identify-tags',
                    },
                    'target_flags': {'-u', '--url', '--csrf-url', '--second-order'},
                    'attached_patterns': (
                        r'^--(risk|level|timeout|retries|delay|threads|technique|dbms|method|time-sec)=\S+$',
                    ),
                    # Unlocked ONLY in aggressive lab mode (target.aggressive_lab
                    # + exploitation_authorized). Real data extraction and a
                    # single non-interactive OS command / file read. The
                    # interactive escapes (--os-shell/--sql-shell/--os-pwn) stay
                    # refused everywhere: they need a live TTY and would hang the
                    # non-shell subprocess, and --dump-all/-z/--wizard stay out as
                    # gratuitously broad free-form overrides.
                    'aggressive_bool_flags': {
                        '--dump', '--dbs', '--tables', '--columns', '--schema',
                        '--users', '--passwords', '--privileges', '--roles', '--count',
                    },
                    'aggressive_value_flags': {
                        '-D', '-T', '-C', '--os-cmd', '--file-read', '--dump-format',
                    },
                    'aggressive_attached_patterns': (
                        r'^--dump-format=(CSV|HTML|SQLITE)$',
                    ),
                },
                'msfconsole': {
                    'risk': 'high',
                    # msfconsole runs ONLY on the attacker VM (VM_ONLY_TOOLS);
                    # the local executor refuses it outright. The console is
                    # driven non-interactively with -q (no banner) and -x (the
                    # resource script). The -x payload is validated statement
                    # by statement in _validate_msf_script: only use/set/run/
                    # exploit/exit, an allowed module tree, and RHOSTS/RHOST
                    # values inside the authorized scopes. Anything else — a
                    # shell payload, an arbitrary module, an out-of-scope
                    # target — fails closed here, before HITL approval.
                    'bool_flags': {'-q', '--quiet'},
                    'value_flags': {'-x', '--execute-command'},
                    'attached_patterns': (r'^--execute-command=\S+$',),
                    'msf': True,
                },
                'searchsploit': {
                    'risk': 'low',
                    # Offline Exploit-DB lookup: no network interaction with the
                    # target at all, so positionals are search terms rather
                    # than targets and the explicit-target rule does not apply.
                    # -w/--www (print exploit URLs), -p/--path and -m/--mirror
                    # (copy exploit files), -x/--examine (open in editor),
                    # --nmap (read an nmap XML file) and file-writing/export
                    # flags stay out by design.
                    'risk_note': 'offline database lookup',
                    'offline': True,
                    'bool_flags': {
                        '-t', '--title', '-c', '--case', '--strict', '-j',
                        '--json', '--summary', '-v', '--verbose', '--colour',
                        '--color', '--no-colour', '--no-color', '--id',
                    },
                    'value_flags': {'-e', '--exclude'},
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
        from modules.scope_rules import scope_contains
        return any(scope_contains(target, scope) for scope in authorized_scopes if scope)

    def validate_resolver(self, resolver, authorized_scopes):
        host = self.normalize_host(resolver)
        return bool(host) and (host in PUBLIC_RESOLVERS or self.validate_target(resolver, authorized_scopes))

    def _msf_script_errors(self, script, authorized_scopes, aggressive=False):
        """Validate an msfconsole -x resource script statement by statement.

        Returns a list of human-readable problems; empty means the script is
        policy-legal. Only use/set/<verb> statements are permitted, modules
        must sit under an allowed tree, RHOST/RHOSTS values must be inside the
        authorized scopes, and set keys are restricted to remote-target and
        benign option keys. Everything else — payloads, credentials, listeners
        — has no legal spelling here, so it fails closed.

        In aggressive lab mode the option set widens to let a real exploit
        module carry a payload and a reverse handler back to the attacker VM
        (PAYLOAD/LHOST/LPORT/SRVHOST/SRVPORT/TARGETURI/SESSION) and run a
        backgrounded, non-interactive session command (`sessions -C`). RHOSTS
        is still scope-checked; LHOST/SRVHOST are attacker-side and validated
        as plain addresses; interactive `sessions -i` remains refused.
        """
        errors = []
        used_module = False
        has_target = False
        allowed_keys = MSF_ALLOWED_SET_KEYS | (MSF_AGGRESSIVE_SET_KEYS if aggressive else set())
        allowed_verbs = MSF_AGGRESSIVE_VERBS if aggressive else MSF_ALLOWED_VERBS
        for statement in (script or '').split(';'):
            statement = statement.strip()
            if not statement:
                continue
            lowered = statement.lower()
            if lowered.startswith('use '):
                module = statement[4:].strip()
                used_module = True
                has_target = False
                if not any(module.startswith(prefix) for prefix in MSF_ALLOWED_PREFIXES):
                    errors.append(f'msf module {module} is outside the permitted module trees')
                continue
            if lowered.startswith('set '):
                parts = statement.split(None, 2)
                if len(parts) < 3:
                    errors.append(f'set statement needs a key and a value: {statement!r}')
                    continue
                key, value = parts[1], parts[2]
                if key.upper() not in allowed_keys:
                    errors.append(f'msf set key {key} is not in the permitted option set')
                    continue
                if key.upper() in MSF_TARGET_KEYS:
                    has_target = bool(value.strip())
                    # RHOSTS accepts a space- or comma-separated list; each
                    # entry must itself be an authorized target.
                    for candidate in re.split(r'[ ,]+', value):
                        if candidate and not self.validate_target(candidate, authorized_scopes):
                            errors.append(f'msf {key} value {candidate} is outside the authorized scope')
                numeric = {'RPORT': (1, 65535, 'integer'), 'THREADS': (1, 10, 'integer'),
                           'TIMEOUT': (1, 60, 'integer'), 'LPORT': (1, 65535, 'integer'),
                           'SRVPORT': (1, 65535, 'integer'), 'SESSION': (1, 4096, 'integer')}.get(key.upper())
                if numeric and (error := numeric_error(key, value, numeric)):
                    errors.append(error)
                if key.upper() == 'PORTS':
                    error = validate_argument_values('nmap', [('-p', value)])
                    if error:
                        errors.append(error)
                if key.upper() in {'SSL', 'VERBOSE'} and value.lower() not in {'true', 'false'}:
                    errors.append(f'msf {key} requires true or false')
                # Attacker-side listener addresses are not scope-checked (they
                # are the operator's own VM), but must be plain host tokens.
                if key.upper() in MSF_ATTACKER_SIDE_KEYS and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.:_\-]*', value.strip()):
                    errors.append(f'msf {key} must be a plain host or address')
                if key.upper() == 'PAYLOAD' and not MSF_PAYLOAD_RE.fullmatch(value.strip()):
                    errors.append(f'msf PAYLOAD {value} is not a valid module path')
                if key.upper() == 'TARGETURI' and not re.fullmatch(r'[A-Za-z0-9/_.\-?=&%]+', value.strip()):
                    errors.append('msf TARGETURI must be a plain URI path')
                continue
            verb = lowered.split()[0]
            if verb in allowed_verbs:
                if verb in {'run', 'exploit'} and not (used_module and has_target):
                    errors.append('msf execution requires an explicit in-scope RHOST/RHOSTS for this module')
                # Only the backgrounding switches are allowed after run/exploit;
                # an interactive `sessions -i` or an unknown flag fails closed.
                extra = statement.split()[1:]
                if verb in {'run', 'exploit'} and any(token not in ('-z', '-j') for token in extra):
                    errors.append(f'msf {verb} accepts only -z/-j here: {statement!r}')
                if verb == 'sessions':
                    if not aggressive:
                        errors.append('msf sessions is only available in aggressive lab mode')
                    elif not (extra and extra[0] in ('-C', '-l', '-L')):
                        errors.append("msf sessions accepts only -C '<command>' or -l here (interactive -i is refused)")
                continue
            errors.append(f'msf statement is not a permitted use/set/run/exit form: {statement!r}')
        if not used_module and not errors:
            errors.append('msf script must select a module with "use"')
        return errors

    @staticmethod
    def _command_uses_payload_flag(tokens, spec, tool):
        """True when the command carries a request-body (payload) flag.

        shlex splits '-d' and its value into separate tokens; '--data=x' keeps
        the value attached. Both spellings must count, and only for the tools
        whose PAYLOAD_FLAGS entry names them.
        """
        payload_flags = PAYLOAD_FLAGS.get(tool, ())
        if not payload_flags:
            return False
        for token in tokens[1:]:
            base = token.split('=', 1)[0]
            if base in payload_flags:
                return True
        return False

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

    def scan_arguments(self, tokens, spec, arguments=None):
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
        arguments = arguments if arguments is not None else []

        for token in tokens[1:]:
            if pending:
                arguments.append((pending_flag, token))
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
                    arguments.append((token, None))
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
                    if base in value_flags:
                        arguments.append((base, attached))
                        continue
                    if base in target_flags:
                        arguments.append((base, attached))
                        targets.append(attached)
                        continue
                    if base in resolver_flags:
                        arguments.append((base, attached))
                        resolvers.append(attached)
                        continue
                if self._matches_attached(token, spec):
                    if re.fullmatch(r'-T[0-5]', token):
                        arguments.append(('-T', token[2:]))
                    elif re.fullmatch(r'-p[\d,\-]+', token):
                        arguments.append(('-p', token[2:]))
                    else:
                        arguments.append((base, attached or None))
                    continue
                bundle = self._expand_bundle(token, spec)
                if bundle is not None:
                    pending, pending_flag = bundle
                    # Keep each boolean and the final value-taking flag so
                    # bundles cannot bypass payload gates or numeric bounds.
                    arguments.extend(('-' + ch, None) for ch in token[1:]
                                     if '-' + ch in bool_flags)
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

    def validate_command(self, command, authorized_scopes, expected_tool=None, allow_exploitation=False, aggressive=False):
        # Aggressive lab mode is a superset of controlled exploitation: it can
        # only be reached when the target authorizes exploitation, so it always
        # implies allow_exploitation here.
        if aggressive:
            allow_exploitation = True
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

        tool = tokens[0]
        rules = registry[tool]
        # In aggressive lab mode the tool's aggressive flag sets are folded into
        # the permitted allowlist; otherwise `rules` is used unchanged, so the
        # default (safe) behaviour is byte-for-byte identical.
        if aggressive and (rules.get('aggressive_bool_flags') or rules.get('aggressive_value_flags')):
            rules = {
                **rules,
                'bool_flags': set(rules.get('bool_flags', set())) | set(rules.get('aggressive_bool_flags', set())),
                'value_flags': set(rules.get('value_flags', set())) | set(rules.get('aggressive_value_flags', set())),
                'attached_patterns': tuple(rules.get('attached_patterns', ())) + tuple(rules.get('aggressive_attached_patterns', ())),
            }

        # The exploitation gate: a tool (sqlmap, msfconsole) or a payload
        # (curl with a request body) is exploitation-grade, and the client's
        # engagement letter must authorize controlled exploitation for this
        # target before any of it is even reviewable. Fail closed with the
        # reason, so the refusal reads as the letter's decision, not a glitch.
        exploitation_grade = tool in EXPLOITATION_GATED_TOOLS or self._command_uses_payload_flag(tokens, rules, tool)
        if exploitation_grade and not allow_exploitation:
            return False, ("The client's engagement letter does not authorize controlled exploitation "
                           'against this target, so this command is refused.'), rules

        arguments = []
        targets, resolvers, rejected = self.scan_arguments(tokens, rules, arguments)
        if rejected is not None:
            return False, f'Blocked flag for {tool}: {rejected} is not in the permitted flag set for this capability.', rules
        if not allow_exploitation and any(flag in PAYLOAD_FLAGS.get(tool, ()) for flag, _ in arguments):
            return False, "The client's engagement letter does not authorize controlled exploitation against this target.", rules
        error = validate_argument_values(tool, arguments)
        if error:
            return False, f'Blocked argument for {tool}: {error}.', rules

        # msfconsole's -x value is a script, not a single target: validate it
        # statement by statement (module tree, set keys, RHOSTS scope) after
        # the ordinary flag walk found the flag itself. Scope enforcement
        # lives inside the script check, so success returns here.
        if rules.get('msf'):
            scripts = [value for flag, value in arguments if flag in ('-x', '--execute-command')]
            if len(scripts) != 1:
                return False, 'msfconsole requires a -x resource script (use ...; set ...; run; exit).', rules
            errors = self._msf_script_errors(scripts[0], authorized_scopes, aggressive=aggressive)
            if errors:
                return False, f'Blocked msfconsole resource script: {errors[0]}', rules
            mode = 'aggressive lab' if aggressive else 'controlled verification'
            return True, f'Allowed exploitation capability (high risk, {mode}); resource script scope-checked; HITL approval required.', rules

        if rules.get('offline'):
            # An offline lookup takes search terms as positionals; there is no
            # network destination to scope-check. The command still had to
            # pass the flag walk above, and no targetless exploit path exists
            # because offline tools cannot reach a target at all.
            return True, 'Allowed offline capability (no target interaction).', rules

        if not targets:
            return False, 'The command must contain an explicit target.', rules
        # URL-capable scanners must not reinterpret an allowed hostname as a
        # local-file URL, credential-bearing authority, or curl URL expansion.
        for target in targets:
            if '://' in target:
                try:
                    parsed = urlparse(target)
                    port = parsed.port
                    if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username is not None or parsed.password is not None:
                        raise ValueError('unsupported URL')
                    if port == 0:
                        raise ValueError('invalid port')
                    if tool == 'curl' and any(ch in parsed.path + parsed.query for ch in '{}[]'):
                        raise ValueError('URL expansion')
                except ValueError:
                    return False, 'Targets must be HTTP(S) URLs without credentials or URL expansion.', rules
        outside = [target for target in targets if not self.validate_target(target, authorized_scopes)]
        if outside:
            return False, f'A command target is outside the authorized scope: {outside[0]}.', rules
        unapproved = [resolver for resolver in resolvers if not self.validate_resolver(resolver, authorized_scopes)]
        if unapproved:
            return False, f'Resolver {unapproved[0]} is neither in scope nor a well-known public resolver.', rules
        flags = {flag for flag, _ in arguments}
        required = {'whatweb': {'--follow-redirect'},
                    'sqlmap': {'--ignore-redirects'},
                    'nuclei': {'-dr', '-disable-redirects'}}.get(tool)
        if required and not flags.intersection(required):
            hint = '--follow-redirect never' if tool == 'whatweb' else sorted(required)[0]
            return False, f'{tool} requires {hint}; redirect destinations need separate scope review.', rules
        return True, f"Allowed {rules['capability']} capability ({rules['risk']} risk); HITL approval required.", rules


policy_engine = PolicyEngine()
