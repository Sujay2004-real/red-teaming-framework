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
# Post-exploitation module trees run against an existing session rather than a
# network target, so they are available only in aggressive lab mode, where the
# session that feeds them was itself opened under the letter's authorization.
MSF_AGGRESSIVE_PREFIXES = (
    'post/linux/', 'post/windows/', 'post/multi/', 'post/osx/',
)
MSF_ALLOWED_SET_KEYS = {
    'RHOST', 'RHOSTS', 'RPORT', 'PORTS', 'THREADS', 'TIMEOUT', 'SSL', 'VERBOSE',
}
MSF_TARGET_KEYS = {'RHOST', 'RHOSTS'}
MSF_ALLOWED_VERBS = ('run', 'exploit', 'exit', 'back', 'sessions')

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

# ---------------------------------------------------------------------------
# Post-exploitation and lateral movement.
#
# Every tool in this group exists to act through a foothold the engagement
# already obtained, so all of them are lab_only: refused unless the target is
# in aggressive lab mode, which itself requires the letter to authorize
# controlled exploitation. The default (production-target) allowlist is
# therefore untouched by this section - adding a tool here can never widen what
# a normal engagement permits.
# ---------------------------------------------------------------------------
LAB_ONLY_TOOLS = {
    'nxc', 'smbclient', 'enum4linux-ng', 'hydra', 'ssh', 'proxychains4',
    'impacket-secretsdump', 'impacket-psexec', 'impacket-wmiexec',
    'impacket-GetUserSPNs', 'impacket-GetNPUsers',
}

# Commands that may be typed into an existing Metasploit session with
# `sessions -C '<command>'`. The bounded set is what non-destructive impact
# verification needs; the aggressive set adds the read-only enumeration a lab
# engagement wants. Both are single commands with no shell metacharacters, so a
# session command can never chain into something the allowlist never saw.
SESSION_SAFE_COMMANDS = (
    'id', 'whoami', 'hostname', 'uname -a', 'uname -r', 'cat /etc/os-release',
    'ip addr', 'ip a', 'ip route', 'netstat -rn', 'systeminfo',
)
SESSION_AGGRESSIVE_COMMANDS = (
    'arp -a', 'ip neigh', 'netstat -an', 'ps aux', 'tasklist', 'env',
    'getent passwd', 'ls -la /home', 'cat /etc/hosts', 'head -c 200 /etc/passwd',
    'head -c 200 /etc/shadow', 'net user', 'net localgroup administrators',
)
# Charset deliberately excludes ; | & > < $ ` ' " ( ) { } * ? ! so a session
# command cannot chain, redirect, substitute, or glob its way anywhere.
SESSION_COMMAND_RE = re.compile(r'^[A-Za-z0-9_./%=\- :,\[\]@+]+$')
SESSION_FORBIDDEN_PATTERNS = (
    'rm ', 'rmdir', 'mkfs', 'dd if=', 'dd of=', 'shutdown', 'reboot', 'halt',
    'poweroff', 'iptables', 'ufw ', 'useradd', 'userdel', 'passwd ',
    'chmod 777', 'chown ', 'crontab', 'systemctl', 'service ',
)
SESSION_COMMAND_MAX_CHARS = 200

# The one remote command an SSH foothold step may run. Fixing it exactly keeps
# the foothold proof deterministic: the step either prints the marker (a real
# login) or it does not, and no operator-authored command can ride along.
SSH_FOOTHOLD_COMMAND = 'echo RT-FOOTHOLD; id; hostname'


def split_statements(script):
    """Split a Metasploit resource script on semicolons outside quotes.

    A naive split would cut a quoted ``sessions -C "id; hostname"`` payload in
    half, turning one reviewed statement into two statements the validator then
    judges separately. Respecting quotes keeps the unit of review the same as
    the unit of execution.
    """
    statements, current, quote = [], [], ''
    for character in script or '':
        if quote:
            current.append(character)
            if character == quote:
                quote = ''
            continue
        if character in ('"', "'"):
            quote = character
            current.append(character)
            continue
        if character == ';':
            statements.append(''.join(current).strip())
            current = []
            continue
        current.append(character)
    statements.append(''.join(current).strip())
    return [statement for statement in statements if statement]

def session_command_error(command, aggressive=False):
    """Validate a command destined for an existing Metasploit session.

    Returns a human-readable problem, or '' when the command is legal. This is
    the one place in the policy engine where the *content* of an argument is
    executed on a remote host rather than interpreted locally, so it is checked
    in two layers: a strict character set that makes chaining, redirection and
    substitution impossible, and a command allowlist.
    """
    command = ' '.join((command or '').split())
    if not command:
        return 'msf sessions -C needs a command to run'
    if len(command) > SESSION_COMMAND_MAX_CHARS:
        return f'msf session command exceeds {SESSION_COMMAND_MAX_CHARS} characters'
    if not SESSION_COMMAND_RE.fullmatch(command):
        return ('msf session command may contain only plain command characters; '
                'chaining, redirection and substitution are refused')
    lowered = command.lower()
    for pattern in SESSION_FORBIDDEN_PATTERNS:
        if pattern in lowered:
            return f'msf session command contains a refused operation ({pattern.strip()})'
    allowed = set(SESSION_SAFE_COMMANDS) | (set(SESSION_AGGRESSIVE_COMMANDS) if aggressive else set())
    if command not in allowed:
        return ('msf session command is not in the permitted read-only set for this mode; '
                'aggressive lab mode widens the set')
    return ''

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
        # ------------------------------------------------------------------
        # Post-exploitation and lateral movement (lab_only).
        #
        # These are the tools a red team reaches for once it holds a foothold:
        # protocol clients for share/session enumeration, credential reuse,
        # password auditing against a lab service, SSH pivots, a proxy wrapper
        # for chaining through a foothold, and the Impacket suite for Windows
        # credential access and remote execution. Every one is refused unless
        # the target is in aggressive lab mode, and every one still needs its
        # own human approval before it runs.
        # ------------------------------------------------------------------
        'post_exploitation': {
            'tools': {
                'nxc': {
                    'risk': 'high',
                    'lab_only': True,
                    # netexec: authenticate across SMB/SSH/LDAP/WinRM/MSSQL with
                    # a recovered or supplied secret, and enumerate shares,
                    # sessions and logged-on users. Absent by design: -x/-X (run
                    # a command), -M (arbitrary module), --sam/--lsa/--ntds
                    # (credential dumping) and -o (module options) - they are
                    # free-form execution or bulk credential theft, which this
                    # table cannot bound.
                    'bool_flags': {
                        '--local-auth', '--continue-on-success', '--shares',
                        '--sessions', '--loggedon-users', '--users', '--groups',
                        '--pass-pol', '--no-bruteforce', '--verbose',
                    },
                    'value_flags': {
                        '-u', '--username', '-p', '--password', '-H', '--hash',
                        '-d', '--domain', '--port', '-t', '--threads',
                        '--timeout', '--smb-timeout',
                    },
                    # nxc is `nxc <protocol> <target>`; the protocol token is not
                    # a destination, only the target positional is scope-checked.
                    'positional_targets': (1,),
                },
                'smbclient': {
                    'risk': 'moderate',
                    'lab_only': True,
                    # Share listing and non-interactive share access. Absent by
                    # design: bare interactive mode (no -c) and the put/get
                    # transfer flags, so a share can be listed and read but bulk
                    # exfiltration stays an explicit operator decision outside
                    # the framework's bounded proof.
                    'bool_flags': {'-N', '--no-pass', '-L', '--list', '-g', '--grep', '-d'},
                    'value_flags': {'-U', '--user', '-W', '--workgroup', '-c', '--command',
                                    '-p', '--port', '-m', '--max-protocol', '-A', '--authentication-file'},
                    'positional_targets': (0,),
                },
                'enum4linux-ng': {
                    'risk': 'moderate',
                    'lab_only': True,
                    'bool_flags': {'-A', '-U', '-S', '-G', '-P', '-R', '-o', '-v', '-d'},
                    'value_flags': {'-w', '-u', '-p', '-L'},
                    'attached_patterns': (r'^-o[A-Z]$',),
                    'positional_targets': (0,),
                },
                'hydra': {
                    'risk': 'high',
                    'lab_only': True,
                    # Credential auditing against a lab service. Use the
                    # service://host target form so the destination is one
                    # scope-checkable token. Absent by design: -M (target list
                    # file), -x (password generation), -b (brute variant) and
                    # -R (restore) - they take the destination or the credential
                    # set outside the reviewed plan.
                    'bool_flags': {'-f', '-F', '-e', '-u', '-O', '-V', '-d', '-I', '-q'},
                    'value_flags': {'-l', '-L', '-p', '-P', '-s', '-t', '-S', '-m', '-o', '-w', '-W'},
                    'attached_patterns': (r'^-t\d+$', r'^-s\d+$'),
                    'positional_targets': (0,),
                    'target_uri_schemes': ('ssh', 'ftp', 'smb', 'rdp', 'mssql', 'mysql', 'vnc',
                                           'telnet', 'http', 'https', 'smbnt', 'smtp', 'imap',
                                           'pop3', 'postgres'),
                },
                'ssh': {
                    'risk': 'high',
                    'lab_only': True,
                    # Foothold proof and tunneling: -N with -D/-L opens a pivot
                    # without a shell, and a bounded read-only command proves a
                    # login. Absent by design: -o UserKnownHostsFile/ProxyCommand
                    # and friends are not enumerated, so the option surface
                    # cannot be used to retarget the connection; the remote
                    # command is checked against the session command allowlist.
                    'bool_flags': {'-N', '-f', '-q', '-T', '-4', '-6', '-v', '-C'},
                    'value_flags': {'-p', '-i', '-o', '-D', '-L', '-W', '-l', '-F', '-J'},
                    'attached_patterns': (r'^-p\d+$', r'^-D\d+$'),
                    'positional_targets': (0,),
                    'ssh_remote_command': True,
                },
                'proxychains4': {
                    'risk': 'high',
                    'lab_only': True,
                    # Wraps another allowed command so it egresses through the
                    # pivot. The inner command is validated recursively against
                    # the same scopes, so proxychains cannot smuggle a command
                    # the allowlist would otherwise refuse.
                    'wrapper': True,
                    'bool_flags': {'-q'},
                    'value_flags': {'-f'},
                },
                'impacket-secretsdump': {
                    'risk': 'high',
                    'lab_only': True,
                    # Windows credential extraction. Absent by design: -exec
                    # (run a command through the target's service), -just-dc-ntlm
                    # bulk modes are enumerated but bounded by -history/-user
                    # being off by default; output redirection is the shell's
                    # job, not this table's.
                    'bool_flags': {'-history', '-just-dc', '-use-vss', '-debug'},
                    'value_flags': {'-hashes', '-just-dc-user', '-user-status', '-outputfile', '-dc-ip', '-target-ip'},
                    'positional_targets': (0,),
                },
                'impacket-psexec': {
                    'risk': 'high',
                    'lab_only': True,
                    'bool_flags': {'-debug', '-codec'},
                    'value_flags': {'-hashes', '-dc-ip', '-target-ip', '-port'},
                    'positional_targets': (0,),
                },
                'impacket-wmiexec': {
                    'risk': 'high',
                    'lab_only': True,
                    'bool_flags': {'-debug', '-codec', '-shell-type'},
                    'value_flags': {'-hashes', '-dc-ip', '-target-ip', '-port'},
                    'positional_targets': (0,),
                },
                'impacket-GetUserSPNs': {
                    'risk': 'moderate',
                    'lab_only': True,
                    'bool_flags': {'-request', '-debug'},
                    'value_flags': {'-hashes', '-dc-ip', '-target-ip', '-outputfile', '-usersfile'},
                    'positional_targets': (0,),
                },
                'impacket-GetNPUsers': {
                    'risk': 'moderate',
                    'lab_only': True,
                    'bool_flags': {'-request', '-debug', '-no-pass'},
                    'value_flags': {'-dc-ip', '-format', '-outputfile', '-usersfile'},
                    'positional_targets': (0,),
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
        # A post module acts on an existing session instead of a network host,
        # so "run" needs either an in-scope RHOST/RHOSTS or a SESSION - and the
        # session-scoped path is only reachable in aggressive lab mode.
        has_session = False
        used_execution = False
        allowed_keys = MSF_ALLOWED_SET_KEYS | (MSF_AGGRESSIVE_SET_KEYS if aggressive else set())
        allowed_verbs = MSF_AGGRESSIVE_VERBS if aggressive else MSF_ALLOWED_VERBS
        for statement in split_statements(script):
            if not statement:
                continue
            lowered = statement.lower()
            if lowered.startswith('use '):
                module = statement[4:].strip()
                used_module = True
                has_target = False
                prefixes = MSF_ALLOWED_PREFIXES + (MSF_AGGRESSIVE_PREFIXES if aggressive else ())
                if not any(module.startswith(prefix) for prefix in prefixes):
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
                if key.upper() == 'SESSION':
                    has_session = value.strip().isdigit()
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
                if verb in {'run', 'exploit'}:
                    used_execution = True
                    if not (used_module and (has_target or has_session)):
                        errors.append('msf execution requires an explicit in-scope RHOST/RHOSTS '
                                      'or a SESSION on an existing foothold')
                # Only the backgrounding switches are allowed after run/exploit;
                # an interactive `sessions -i` or an unknown flag fails closed.
                try:
                    extra = shlex.split(statement, posix=True)[1:]
                except ValueError:
                    errors.append(f'msf statement syntax is invalid: {statement!r}')
                    continue
                if verb in {'run', 'exploit'} and any(token not in ('-z', '-j') for token in extra):
                    errors.append(f'msf {verb} accepts only -z/-j here: {statement!r}')
                if verb == 'sessions':
                    # Listing sessions is read-only and available as soon as the
                    # letter authorizes exploitation, because everything after
                    # this point acts on what the list reveals. Running a
                    # command on a session is the post-exploitation primitive
                    # and is validated command-by-command.
                    marker = extra[0] if extra else ''
                    if marker in ('-l', '-L'):
                        if len(extra) > 1:
                            errors.append('msf sessions -l takes no further arguments')
                        continue
                    if marker != '-C':
                        errors.append("msf sessions accepts only -l (list) or -C '<command>' with -i <id> (interactive -i is refused)")
                        continue
                    if len(extra) < 2:
                        errors.append('msf sessions -C needs a command to run on the session')
                        continue
                    if problem := session_command_error(extra[1], aggressive=aggressive):
                        errors.append(problem)
                    # -i <id> targets one session; without it Metasploit runs
                    # the same reviewed command on every open session, which is
                    # the pre-existing documented behaviour and stays legal.
                    remainder = extra[2:]
                    if len(remainder) >= 2 and remainder[0] == '-i' and remainder[1].isdigit():
                        remainder = remainder[2:]
                    if remainder:
                        errors.append(f'msf sessions accepts only -C and -i here: {statement!r}')
                continue
            errors.append(f'msf statement is not a permitted use/set/run/exit form: {statement!r}')
        if used_execution and not used_module and not errors:
            errors.append('msf script must select a module with "use" before run/exploit')
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

    @staticmethod
    def _wrapper_arguments(tokens, spec):
        """The wrapper's own flags, as (flag, value) pairs, before the inner command."""
        pairs, index = [], 1
        bool_flags = spec.get('bool_flags', set())
        value_flags = spec.get('value_flags', set())
        while index < len(tokens):
            token = tokens[index]
            if token in bool_flags:
                pairs.append((token, None))
                index += 1
                continue
            if token in value_flags and index + 1 < len(tokens):
                pairs.append((token, tokens[index + 1]))
                index += 2
                continue
            if '=' in token and token.split('=', 1)[0] in value_flags:
                base, _, value = token.partition('=')
                pairs.append((base, value))
                index += 1
                continue
            break
        return pairs

    @staticmethod
    def _wrapper_inner_command(tokens, spec):
        """The tokens a wrapper such as proxychains4 will actually execute."""
        consumed = len(PolicyEngine._wrapper_arguments(tokens, spec))
        index = 1
        bool_flags = spec.get('bool_flags', set())
        value_flags = spec.get('value_flags', set())
        while index < len(tokens) and consumed > 0:
            token = tokens[index]
            if token in bool_flags:
                consumed -= 1
                index += 1
            elif token in value_flags and index + 1 < len(tokens):
                consumed -= 1
                index += 2
            elif '=' in token and token.split('=', 1)[0] in value_flags:
                consumed -= 1
                index += 1
            else:
                break
        return tokens[index:]
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
            return targets, resolvers, None
        # Some tools put a non-destination token in front of the target
        # (nxc's protocol, hydra's service is embedded in its URI). When a spec
        # names which positional indices are targets, everything else is
        # recorded as a plain argument and must still look like a bare token -
        # it can never be a URL, path or address that skips the scope check.
        roles = spec.get('positional_targets')
        if roles is None:
            targets.extend(positionals)
            return targets, resolvers, None
        allowed = set(roles)
        for index, token in enumerate(positionals):
            if index in allowed:
                targets.append(token)
            elif spec.get('ssh_remote_command') and index == 1:
                # The one place a positional is a command rather than a
                # destination: ssh's optional trailing remote command, pinned
                # to a single reviewed string by validate_command.
                arguments.append(('remote-command', token))
            elif not re.fullmatch(r'[A-Za-z0-9_.\-]+', token):
                return None, None, token
            else:
                arguments.append(('positional', token))
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

        # Lab-only tools act through a foothold on a host the operator owns.
        # They are refused outright unless the engagement is in aggressive lab
        # mode, which itself requires the letter to authorize exploitation, so
        # the default production-target allowlist is unchanged by their
        # existence.
        if rules.get('lab_only') and not aggressive:
            return False, (f'{tool} acts through an obtained foothold and is available only in '
                           'aggressive lab mode for an engagement that authorizes controlled '
                           'exploitation.'), rules

        # The exploitation gate: a tool (sqlmap, msfconsole) or a payload
        # (curl with a request body) is exploitation-grade, and the client's
        # engagement letter must authorize controlled exploitation for this
        # target before any of it is even reviewable. Fail closed with the
        # reason, so the refusal reads as the letter's decision, not a glitch.
        exploitation_grade = tool in EXPLOITATION_GATED_TOOLS or self._command_uses_payload_flag(tokens, rules, tool)
        if exploitation_grade and not allow_exploitation:
            return False, ("The client's engagement letter does not authorize controlled exploitation "
                           'against this target, so this command is refused.'), rules

        # A wrapper (proxychains4) carries an entire command inside it, so it
        # cannot be validated by the ordinary flag walk: the inner command is
        # validated recursively, against the same scopes and the same mode.
        if rules.get('wrapper'):
            inner = self._wrapper_inner_command(tokens, rules)
            if not inner:
                return False, f'{tool} requires a command to run through the pivot.', rules
            for flag, value in self._wrapper_arguments(tokens, rules):
                if flag == '-f' and ('..' in (value or '') or not re.fullmatch(r'/(?:tmp|home|opt|etc)/[\w./\-]*', value or '')):
                    return False, f'{tool} -f must name a configuration file under /tmp, /home, /opt or /etc.', rules
            valid, reason, _ = self.validate_command(
                ' '.join(inner), authorized_scopes,
                allow_exploitation=allow_exploitation, aggressive=aggressive)
            if not valid:
                return False, f'Wrapped command refused: {reason}', rules
            return True, (f'Allowed post-exploitation capability ({rules["risk"]} risk, pivot wrapper); '
                          'the wrapped command was scope-checked; HITL approval required.'), rules

        arguments = []
        targets, resolvers, rejected = self.scan_arguments(tokens, rules, arguments)
        if rejected is not None:
            return False, f'Blocked flag for {tool}: {rejected} is not in the permitted flag set for this capability.', rules
        if not allow_exploitation and any(flag in PAYLOAD_FLAGS.get(tool, ()) for flag, _ in arguments):
            return False, "The client's engagement letter does not authorize controlled exploitation against this target.", rules
        error = validate_argument_values(tool, arguments)
        if error:
            return False, f'Blocked argument for {tool}: {error}.', rules

        # Some tools insist on a URI target (hydra's service://host). Requiring
        # one of the enumerated schemes keeps the destination in a single
        # scope-checkable token instead of a bare service word the scope check
        # would read as a hostname.
        schemes = rules.get('target_uri_schemes')
        if schemes:
            for target in targets:
                scheme = target.split('://', 1)[0].lower() if '://' in target else ''
                if scheme not in schemes:
                    return False, (f'{tool} targets must use one of these URI schemes: '
                                   f'{", ".join(sorted(schemes))}.'), rules

        # An SSH remote command is executed on the target, so it is pinned to
        # the single foothold-proof command rather than left free-form.
        remote = [value for flag, value in arguments if flag == 'remote-command']
        if rules.get('ssh_remote_command') and remote and ' '.join(remote[0].split()) != SSH_FOOTHOLD_COMMAND:
            return False, ('ssh may run only the framework foothold command, or no command at '
                           'all with -N for a tunnel; use a Metasploit session for other commands.'), rules

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
        # Tools that take their own application-protocol URI (hydra's
        # ssh://host) are exempt: their scheme was already pinned above.
        for target in ([] if schemes else targets):
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
