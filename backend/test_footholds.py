# -------------------------------------------------------- evidence parsers
#
# The campaign is only as trustworthy as the parsers that turn tool output into
# footholds, loot and hosts. Each one must extract what the tool genuinely
# printed and nothing else: a parser that does not match produces no row, so
# unknown or crafted output can never invent campaign state.

from modules.footholds import (
    extract_evidence, fingerprint_secret, parse_discovered_hosts, parse_hydra,
    parse_msf_credentials, parse_msf_sessions, parse_netexec, parse_ssh_foothold,
)


def fixed_table(columns, rows):
    """A column-aligned table the way Metasploit prints one."""
    widths = [max(len(column), max(len(str(row[i])) for row in rows)) + 2 for i, column in enumerate(columns)]
    lines = [''.join(column.ljust(widths[i]) for i, column in enumerate(columns)).rstrip(),
             ' '.join('-' * len(column) for column in columns)]
    lines += [''.join(str(value).ljust(widths[i]) for i, value in enumerate(row)).rstrip() for row in rows]
    return '\n'.join(lines)


def test_nmap_report_lines_become_hosts():
    text = ('Nmap scan report for dc01.corp (10.0.0.5)\n'
            'Host is up (0.0010s latency).\n'
            'Nmap scan report for 10.0.0.6\n')
    hosts = parse_discovered_hosts(text)
    assert {'address': '10.0.0.5', 'hostname': 'dc01.corp'} in hosts
    assert {'address': '10.0.0.6', 'hostname': ''} in hosts


def test_msf_sessions_merge_opened_and_listed_rows():
    text = ('[*] Meterpreter session 1 opened (10.10.14.5:4444 -> 10.0.0.5:44552)\n'
            'Id  Name  Type       Information            Connection\n'
            '1   x     meterpreter root @ metasploitable 10.10.14.5:4444 -> 10.0.0.5:44552\n'
            '2         shell      NT AUTHORITY\\SYSTEM @ WIN-DC 10.10.14.5:4445 -> 10.0.0.7:44553\n'
            '[*] Session 2 closed\n')
    parsed = parse_msf_sessions(text)
    opened = {row['remote_id']: row for row in parsed['opened']}
    assert opened['1']['host'] == '10.0.0.5'
    assert opened['1']['kind'] == 'meterpreter'
    assert opened['1']['pivot_ready'] is True
    assert opened['2']['host'] == '10.0.0.7'
    assert opened['2']['username'] == 'NT AUTHORITY\\SYSTEM'
    assert opened['2']['privilege'] == 'nt authority\\system'
    assert parsed['closed'] == ['2']


def test_msf_creds_table_yields_credentials():
    table = fixed_table(('host', 'origin', 'service', 'public', 'private', 'realm', 'private_type'),
                        [('10.0.0.5', '10.0.0.5', '445/tcp (smb)', 'admin',
                          '31d6cfe0d16ae931b73c59d7e0c089c0', '', 'NTLM')])
    creds = parse_msf_credentials(table)
    assert creds == [{'host': '10.0.0.5', 'service': '445/tcp', 'username': 'admin',
                      'secret': '31d6cfe0d16ae931b73c59d7e0c089c0', 'secret_kind': 'hash',
                      'validated': False, 'notes': 'ntlm'}]


def test_hashdump_and_shadow_lines_are_attributed_without_a_host():
    text = ('Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::'
            '\nroot:$6$abcdefghijklmnop$abcdefghijklmnopqrstuvwxyz0123456789ABCDEF:19000:0:99999:7:::\n')
    creds = parse_msf_credentials(text)
    by_user = {row['username']: row for row in creds}
    assert by_user['Administrator']['secret'] == 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0'
    assert by_user['Administrator']['host'] == ''
    assert by_user['root']['service'] == 'shadow'


def test_hydra_success_is_validated_loot():
    text = '[445][smb] host: 10.0.0.5   login: admin   password: Sup3rSecret1\n'
    loot = parse_hydra(text)
    assert loot == [{'host': '10.0.0.5', 'service': 'smb', 'username': 'admin',
                     'secret': 'Sup3rSecret1', 'secret_kind': 'password', 'validated': True,
                     'notes': 'hydra confirmed login on port 445'}]


def test_netexec_pwn3d_is_a_validated_administrator_credential():
    text = 'SMB   10.0.0.5   445   DC01   [+] CORP\\admin:31d6cfe0d16ae931b73c59d7e0c089c0 (Pwn3d!)\n'
    loot = parse_netexec(text)
    assert loot[0]['host'] == '10.0.0.5'
    assert loot[0]['username'] == 'CORP\\admin'
    assert loot[0]['secret_kind'] == 'hash'
    assert loot[0]['validated'] is True


def test_ssh_foothold_requires_the_marker_and_a_zero_exit():
    assert parse_ssh_foothold('ssh root@10.0.0.5 id', 'uid=0(root)\n', 0) is None
    foothold = parse_ssh_foothold('ssh root@10.0.0.5 id', 'RT-FOOTHOLD\nuid=0(root) gid=0(root)\n', 0)
    assert foothold['host'] == '10.0.0.5'
    assert foothold['username'] == 'root'
    assert foothold['privilege'] == 'root'
    assert parse_ssh_foothold('ssh root@10.0.0.5 id', 'RT-FOOTHOLD\nuid=0(root)', 1) is None


def test_unknown_output_never_invents_campaign_state():
    evidence = extract_evidence('curl', 'curl -sS http://10.0.0.5', 'HTTP/1.1 200 OK', '', 0)
    assert evidence == {'footholds': [], 'loot': [], 'hosts': []}
    assert extract_evidence('nxc', 'nxc smb 10.0.0.5', 'garbage with no table', '', 0)['loot'] == []


def test_extract_evidence_dispatches_by_tool():
    msf = extract_evidence('msfconsole', 'msfconsole -q -x "sessions -l; exit"',
                           '[*] Meterpreter session 1 opened (10.10.14.5:4444 -> 10.0.0.5:44552)\n', '', 0)
    assert [row['host'] for row in msf['footholds']] == ['10.0.0.5']
    assert msf['hosts'] == [{'address': '10.0.0.5', 'hostname': ''}]
    nmap = extract_evidence('nmap', 'nmap -sV 10.0.0.5', 'Nmap scan report for 10.0.0.5\n', '', 0)
    assert nmap['hosts'] == [{'address': '10.0.0.5', 'hostname': ''}]


def test_fingerprint_is_stable_and_does_not_reveal_the_secret():
    assert fingerprint_secret('Sup3rSecret1') == fingerprint_secret('Sup3rSecret1')
    assert fingerprint_secret('Sup3rSecret1') != fingerprint_secret('Sup3rSecret2')
    assert 'Sup3rSecret1' not in fingerprint_secret('Sup3rSecret1')
