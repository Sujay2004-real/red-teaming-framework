from pathlib import Path

import pytest

from modules.engagement_parser import parse_engagement

REAL_PDF = Path(__file__).resolve().parent.parent / 'JuiceBox_Security_Assessment_Request.pdf'

# A trimmed stand-in for the client's letter: same labelled tables and the
# same restriction prose shapes, so the parser is tested without needing the
# PDF on disk.
SAMPLE_LETTER = """
JuiceBox Retail Pvt. Ltd.
4th Floor, Orion Tech Park, Whitefield, Bengaluru, Karnataka 560066
Document
Request for Security Assessment Services (RFP and Statement of Work)
Engagement reference
JB/SEC/2026/014
Date of issue
01 September 2026
Test window
02 September 2026 to 06 September 2026 (both days inclusive)
Primary client contact
Ananya Rao — Chief Information Security Officer
System name
Juice Shop pre-release storefront
Authorized target address
juice-shop:3000 (assessment-lab network)
Authorized scope identifiers
juice-shop, juice-shop:3000
Asset criticality (client-declared, 0-100)
85 — customer-facing e-commerce platform
Environment
Isolated laboratory deployment (Docker), mirrors release-candidate build
System name
DVWA internal security-training lab
Authorized target address
dvwa:80 (assessment-lab network)
Authorized scope identifiers
dvwa, dvwa:80
Asset criticality (client-declared, 0-100)
40 — internal training system, no production data
Assessment type
Service discovery and HTTP header baseline only (see Section 5.3)
3.3 Assets explicitly OUT OF SCOPE
The following are strictly out of scope:
• Any host other than the two assets named above.
• JuiceBox corporate network, employee endpoints, VPN concentrators and mail servers.
• Social engineering, phishing, or any testing involving JuiceBox personnel.
4. Assessment objectives
• 4.1 Service discovery: identify the network services and versions exposed by the authorized targets.
• 4.2 Web-attack-surface inspection: enumerate HTTP response headers and missing browser security headers.
5.2 Prohibited techniques (non-exhaustive)
• Denial-of-service, resource exhaustion, or any action intended to degrade availability.
• Brute-force, credential-stuffing, or password attacks against any authentication mechanism.
5.3 Technique restrictions specific to the DVWA training system (Section 3.2)
Because the training system contains intentionally vulnerable code, only service
discovery (nmap -sV on TCP port 80) and HTTP header inspection (curl -I, whatweb)
are authorized against it. Template-driven vulnerability checks (e.g. nuclei) must
not be run against the DVWA lab.
"""


def test_parses_targets_from_labelled_tables():
    brief = parse_engagement(SAMPLE_LETTER)
    addresses = {target['address']: target for target in brief['targets']}
    assert 'juice-shop:3000' in addresses
    assert 'dvwa:80' in addresses

    juice = addresses['juice-shop:3000']
    assert juice['name'] == 'Juice Shop pre-release storefront'
    assert juice['criticality'] == 85
    assert juice['scopes'] == ['juice-shop', 'juice-shop:3000']
    # No restriction prose names this target, so nothing is restricted.
    assert juice['restricted_tools'] == []

    dvwa = addresses['dvwa:80']
    assert dvwa['criticality'] == 40
    assert dvwa['assessment_type'].startswith('Service discovery')


def test_per_target_restrictions_follow_allow_and_deny_sentences():
    brief = parse_engagement(SAMPLE_LETTER)
    addresses = {target['address']: target for target in brief['targets']}
    # The allow-list sentence names nmap, curl and whatweb; nuclei is also
    # denied by name. Everything runnable except those three is restricted -
    # which since the exploitation rework includes sqlmap, searchsploit and
    # msfconsole: an allow-list sentence excludes every tool it does not name.
    assert addresses['dvwa:80']['restricted_tools'] == ['dig', 'msfconsole', 'nslookup', 'nuclei', 'searchsploit', 'sqlmap', 'sslscan', 'traceroute']
    assert addresses['juice-shop:3000']['restricted_tools'] == []


def test_parses_document_level_fields():
    brief = parse_engagement(SAMPLE_LETTER)
    assert brief['client_name'] == 'JuiceBox Retail Pvt. Ltd.'
    assert brief['engagement_ref'] == 'JB/SEC/2026/014'
    assert '02 September 2026' in brief['test_window']
    assert any('Service discovery' in objective for objective in brief['objectives'])
    assert any('corporate network' in item for item in brief['out_of_scope'])
    assert any('Brute-force' in item for item in brief['prohibited'])


@pytest.mark.skipif(not REAL_PDF.exists(), reason='client request PDF is not in the repository')
def test_parses_the_real_client_pdf():
    import io
    from pypdf import PdfReader
    text = '\n'.join(page.extract_text() or '' for page in PdfReader(str(REAL_PDF)).pages)
    brief = parse_engagement(text)
    addresses = {target['address']: target for target in brief['targets']}
    # The letter (v7) assesses a real self-hosted application - the OmniRoute
    # AI gateway on the assessment host - so it names the target by the host's
    # current lab-network address and the gateway's port (20128)
    # (192.168.198.86 at v7 regeneration time).
    assert '192.168.198.86:20128' in addresses
    assert addresses['192.168.198.86:20128']['criticality'] == 90
    # The letter denies traceroute for the gateway while allowing everything
    # else, so the restriction sentence shape is exercised end to end.
    assert addresses['192.168.198.86:20128']['restricted_tools'] == ['traceroute']
    assert brief['engagement_ref'] == 'JB/SEC/2026/026'
    # The v7 letter authorizes controlled verification for the gateway only,
    # and declares its verification endpoint so the exploit planner can draft
    # the curl proof-of-concept deterministically. Against a real application
    # the verification is expected to come back clean - that outcome is a
    # finding, not a failure.
    assert addresses['192.168.198.86:20128']['exploitation_authorized'] is True
    assert addresses['192.168.198.86:20128']['verification_endpoints'] == ['/v1/chat/completions']
    assert addresses['192.168.198.0/24']['exploitation_authorized'] is False
    # The letter's second target authorizes the whole virtualization-lab
    # segment (a real host LAN, not a container bridge).
    assert '192.168.198.0/24' in addresses
    assert addresses['192.168.198.0/24']['criticality'] == 65
    assert addresses['192.168.198.0/24']['restricted_tools'] == ['curl', 'nuclei', 'sslscan', 'whatweb']
    # All objectives survive PDF extraction and parsing (4.7 remains the
    # controlled verification of critical findings).
    assert len(brief['objectives']) == 9
    assert any('security-header audit' in objective for objective in brief['objectives'])
    assert any('segment' in objective.lower() for objective in brief['objectives'])
    assert any('Controlled verification' in objective for objective in brief['objectives'])


# A letter that authorizes a whole segment. The subnet row uses the same
# labelled-table layout as the host rows, with a CIDR as the address.
SUBNET_LETTER = """
JuiceBox Retail Pvt. Ltd.
Engagement reference
JB/SEC/2026/022
System name
Lab container segment
Authorized target address
172.28.0.0/24 (assessment-lab network)
Authorized scope identifiers
172.28.0.0/24
Asset criticality (client-declared, 0-100)
60 — shared laboratory infrastructure, no production data
Assessment type
discovery sweep (baseline)
3.3 Assets explicitly OUT OF SCOPE
The following are strictly out of scope:
• JuiceBox corporate network 10.10.0.0/16 and all employee endpoints.
4. Assessment objectives
• 4.1 Segment sweep: enumerate live hosts and exposed services.
5.5 Technique restrictions specific to the lab segment (Section 3.2)
Application-layer inspection (curl, whatweb, sslscan, nuclei) must not be run
against the 172.28.0.0/24 segment. Deeper assessment of any host found there
requires a separate authorization.
"""


def test_parses_a_subnet_target_from_the_letter():
    brief = parse_engagement(SUBNET_LETTER)
    addresses = {target['address']: target for target in brief['targets']}

    segment = addresses['172.28.0.0/24']
    # The parenthetical qualifier must be stripped, and the CIDR must survive
    # as the address (not be reduced to its base address).
    assert segment['name'] == 'Lab container segment'
    assert segment['criticality'] == 60
    assert segment['scopes'] == ['172.28.0.0/24']


def test_out_of_scope_subnet_is_not_lifted_into_the_targets():
    brief = parse_engagement(SUBNET_LETTER)

    # 10.10.0.0/16 is named in the out-of-scope section; a bare-address
    # fallback must not register it as scannable.
    addresses = {target['address'] for target in brief['targets']}
    assert '10.10.0.0/16' not in addresses
    assert addresses == {'172.28.0.0/24'}


def test_subnet_restriction_binds_by_cidr_mention():
    brief = parse_engagement(SUBNET_LETTER)
    addresses = {target['address']: target for target in brief['targets']}

    assert addresses['172.28.0.0/24']['restricted_tools'] == ['curl', 'nuclei', 'sslscan', 'whatweb']


def test_bare_cidr_line_becomes_a_target_in_a_minimal_letter():
    brief = parse_engagement('Authorized segment: 172.28.0.0/24 for discovery only.')

    assert [target['address'] for target in brief['targets']] == ['172.28.0.0/24']
