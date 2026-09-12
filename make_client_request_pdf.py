# -*- coding: utf-8 -*-
"""Generates the fictional client 'Request for Security Assessment Services' PDF.

Real-application edition (letter v7): the same fictional client, but the
asset under assessment is a real, production self-hosted web application
rather than a deliberately vulnerable lab target — the Company's OmniRoute
AI gateway (an open-source, self-hosted LLM gateway and dashboard),
running as a service on the assessment host on the laboratory network
(192.168.198.0/24 lab segment). The attacker side remains a full Kali
Linux VM, plus a discovery sweep of the segment. The letter is
deliberately parser-compatible (label/value tables, numbered objectives,
both restriction sentence shapes).

The addresses below are LAN-dependent: HOST_IP is the assessment host's IPv4
address on the network shared with the Kali attacker VM (the OmniRoute
gateway listens on TCP 20128 there). If the host's DHCP lease changes,
update HOST_IP and regenerate this letter.
"""
from datetime import date
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether,
                                 PageTemplate, Paragraph, Spacer, Table,
                                 TableStyle)

OUT = Path(__file__).with_name('JuiceBox_Security_Assessment_Request.pdf')

# The assessment host's address on the network shared with the Kali VM.
# Update this if the host's IP changes, then re-run this script.
HOST_IP = '192.168.198.86'
GATEWAY = f'{HOST_IP}:20128'
SEGMENT = '192.168.198.0/24'

COMPANY = 'JuiceBox Retail Pvt. Ltd.'
ADDRESS = '4th Floor, Orion Tech Park, Whitefield, Bengaluru, Karnataka 560066'
ENGAGEMENT_REF = 'JB/SEC/2026/026'
ENGAGEMENT_DATE = date(2026, 9, 10)
TEST_WINDOW = '11 September 2026 to 17 September 2026 (both days inclusive)'
PRIMARY_CONTACT = 'Ananya Rao — Chief Information Security Officer'
PRIMARY_EMAIL = 'ciso.office@juiceboxretail.example'
PRIMARY_PHONE = '+91 80 4XXX 2100 (ext. 401)'
ESCALATION_CONTACT = 'Vikram Shetty — Head of IT Infrastructure'
ESCALATION_PHONE = '+91 98XXXXXXXX (24x7)'
PROVIDER = 'EPCET Security Research Laboratory — Semi-Autonomous Red Teaming Team'

styles = getSampleStyleSheet()

brand_navy = colors.HexColor('#1F3864')
brand_blue = colors.HexColor('#2E74B5')
brand_light = colors.HexColor('#DEEAF6')
rule_grey = colors.HexColor('#BFBFBF')

h1 = ParagraphStyle('H1x', parent=styles['Heading1'], fontName='Helvetica-Bold',
                    fontSize=16, leading=20, textColor=brand_navy, spaceAfter=8)
h2 = ParagraphStyle('H2x', parent=styles['Heading2'], fontName='Helvetica-Bold',
                    fontSize=12, leading=15, textColor=brand_blue, spaceBefore=12,
                    spaceAfter=6)
body = ParagraphStyle('Bodyx', parent=styles['BodyText'], fontName='Helvetica',
                      fontSize=9.5, leading=13.5, alignment=TA_JUSTIFY, spaceAfter=6)
small = ParagraphStyle('Smallx', parent=body, fontSize=8.5, leading=12,
                       textColor=colors.HexColor('#444444'))
cell = ParagraphStyle('Cellx', parent=body, fontSize=9, leading=12, spaceAfter=0)
cellb = ParagraphStyle('CellBx', parent=cell, fontName='Helvetica-Bold')
cellh = ParagraphStyle('CellHx', parent=cell, fontName='Helvetica-Bold',
                       textColor=colors.white)


def info_table(rows, widths):
    data = [[Paragraph(k, cellb), Paragraph(v, cell)] for k, v in rows]
    table = Table(data, colWidths=widths, hAlign='LEFT')
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), brand_light),
        ('GRID', (0, 0), (-1, -1), 0.5, rule_grey),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    return table


def grid_table(header, rows, widths):
    data = [[Paragraph(h, cellh) for h in header]]
    for row in rows:
        data.append([Paragraph(v, cell) for v in row])
    table = Table(data, colWidths=widths, hAlign='LEFT', repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), brand_navy),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F2F6FB')]),
        ('GRID', (0, 0), (-1, -1), 0.5, rule_grey),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    return table


def bullet(text, style=body):
    return Paragraph(f'<bullet>&bull;</bullet>{text}', style)

def on_page(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(brand_navy)
    canvas.setLineWidth(1.5)
    canvas.line(18 * mm, 285 * mm, 192 * mm, 285 * mm)
    canvas.setFont('Helvetica', 7.5)
    canvas.setFillColor(colors.HexColor('#666666'))
    canvas.drawString(18 * mm, 287.5 * mm, f'{COMPANY} — Confidential')
    canvas.drawRightString(192 * mm, 287.5 * mm, f'Engagement {ENGAGEMENT_REF}')
    canvas.setStrokeColor(rule_grey)
    canvas.setLineWidth(0.75)
    canvas.line(18 * mm, 14 * mm, 192 * mm, 14 * mm)
    canvas.drawString(18 * mm, 10.5 * mm, 'Request for Security Assessment Services — Confidential')
    canvas.drawRightString(192 * mm, 10.5 * mm, f'Page {doc.page}')
    canvas.restoreState()


doc = BaseDocTemplate(str(OUT), pagesize=A4, leftMargin=18 * mm,
                      rightMargin=18 * mm, topMargin=16 * mm,
                      bottomMargin=18 * mm,
                      title='Request for Security Assessment Services — Self-Hosted AI Gateway Assessment',
                      author=COMPANY)
frame = Frame(18 * mm, 18 * mm, 174 * mm, 264 * mm, id='main')
doc.addPageTemplates([PageTemplate(id='page', frames=[frame], onPage=on_page)])

story = []

# ------------------------------------------------------------- header block
story.append(Paragraph(
    f'{COMPANY}<br/><font size="9" color="#555555">{ADDRESS}</font>', h1))
story.append(Spacer(1, 4))
story.append(info_table([
    ('Document', 'Request for Security Assessment Services (RFP and Statement of Work)'),
    ('Engagement reference', ENGAGEMENT_REF),
    ('Date of issue', ENGAGEMENT_DATE.strftime('%d %B %Y')),
    ('Issued to', PROVIDER),
    ('Primary client contact',
     f'{PRIMARY_CONTACT}<br/>{PRIMARY_EMAIL}<br/>{PRIMARY_PHONE}'),
    ('Test window', TEST_WINDOW),
    ('Classification', 'Confidential — Client and Assessment Team only'),
], [40 * mm, 134 * mm]))
story.append(Spacer(1, 10))

# ------------------------------------------------------------- cover letter
story.append(Paragraph('1. Cover letter from the client', h2))
story.append(Paragraph(f'Dear {PROVIDER},', body))
story.append(Paragraph(
    f'{COMPANY} ("JuiceBox", "the Company") has deployed a self-hosted AI gateway '
    '(the open-source OmniRoute platform) as shared infrastructure for its engineering '
    'organisation: a single OpenAI-compatible endpoint through which the Company\'s '
    'development tools reach external AI providers, holding provider API keys, per-key '
    'spend quotas and usage-audit records. Under engagement JB/SEC/2026/022 your team '
    'performed the second-pass deep assessment of the container-based laboratory '
    'deployment of the former storefront. For this engagement the Company requires an '
    'assessment of the gateway as it actually runs in production — a real, unmodified '
    'third-party application, not a deliberately weakened training target — because the '
    'gateway is about to be opened to the branch-office engineering teams. The '
    'assessment is conducted from a dedicated attacker virtual machine (a full Kali '
    'Linux system operated by your semi-autonomous framework), directed across the '
    'laboratory network at the gateway host, so that the assessment exercises a real '
    'attacker system, real kernels and real network paths against a real application. '
    'The Company now requires full service and version enumeration, a complete HTTP '
    'security-header audit, technology fingerprinting, cookie and transport review, '
    'and rate-limited template-driven vulnerability checks, all correlated into one '
    'prioritized report. The Company specifically requires that the executed commands '
    'demonstrably originate from the attacker virtual machine, with per-step evidence '
    'of the machine that ran them, as this report is the evidence the CISO office '
    'requires before the widened exposure is approved.', body))
story.append(Paragraph(
    'We request your team to perform a non-destructive external and web-application '
    'security assessment of the assets identified in Section 3 of this document, '
    'strictly within the authorized scope stated therein, during the test window '
    'stated above. We understand that your assessment methodology is semi-autonomous: '
    'automated reconnaissance and scanning steps are proposed by your framework and '
    'must be individually reviewed and approved by your human operator before '
    'execution. This is acceptable to the Company, and we specifically require that '
    'this human approval step remain in force for every command issued against our '
    'assets. The Company also asks that the final report quantify the coverage '
    'achieved relative to the manual effort an unaided tester would have required, '
    'as described in Section 6.', body))
story.append(Paragraph(
    'All systems listed in Section 3 are owned or controlled by the Company. No '
    'third-party, shared-hosting, or cloud-provider infrastructure is included in '
    'scope. Please sign and return the authorization in Section 8 to confirm your '
    'acceptance of these terms.', body))
story.append(Paragraph(
    'Yours sincerely,<br/><br/><b>Ananya Rao</b><br/>Chief Information Security Officer<br/>'
    f'{COMPANY}', body))

# ------------------------------------------------------------- background
story.append(Paragraph('2. Background and business context', h2))
story.append(Paragraph(
    'JuiceBox Retail operates a loyalty and retail platform serving approximately 240,000 '
    'registered customers, and its engineering organisation of 180 developers uses AI '
    'coding assistants and model APIs daily. To keep that usage governed, the Company '
    'self-hosts an AI gateway — the open-source OmniRoute platform, a Node.js/Next.js '
    'web application with a dashboard and an OpenAI-compatible API — so that every '
    'model request flows through one Company-controlled endpoint with provider keys, '
    'per-key spend quotas and an audit trail. The gateway is real production software, '
    'run unmodified exactly as published by its upstream project.', body))
story.append(Paragraph(
    'The gateway currently serves the head-office engineering VLAN. Before it is '
    f'opened to the branch offices, the CISO office requires an independent security '
    'assessment of the deployment as it actually runs. To make that assessment '
    'representative, the Company has built an assessment virtualization laboratory on '
    f'the laboratory network ({SEGMENT}): the production gateway deployment is staged '
    'on the laboratory application host there, and the assessment itself is conducted '
    'from a dedicated attacker virtual machine — a full Kali Linux system whose '
    'terminal the assessment framework operates directly — so the assessment '
    'exercises a genuine attacker platform, real network paths and a real application, '
    'rather than single-purpose training targets. The assessment requested here covers '
    'that deployment and is the evidence the CISO office requires before the widened '
    'exposure is approved.', body))

# ------------------------------------------------------------- scope
story.append(Paragraph('3. Authorized scope of the assessment', h2))
story.append(Paragraph(
    '<b>3.1 Primary asset — self-hosted AI gateway (in scope, deep assessment)</b>', body))
story.append(Paragraph(
    'The following asset is the only application system authorized for this '
    'engagement. All testing activity must be directed exclusively at it.', body))
story.append(grid_table(
    ['Attribute', 'Value'],
    [
        ['System name', 'Self-hosted AI gateway (OmniRoute)'],
        ['Authorized target address', f'{GATEWAY} (virtualization laboratory)'],
        ['Authorized scope identifiers', f'{HOST_IP}, {GATEWAY}'],
        ['Technology',
         'Node.js / Next.js self-hosted AI gateway (OmniRoute) with an '
         'OpenAI-compatible API and a web dashboard, HTTP on TCP port 20128'],
        ['Asset criticality (client-declared, 0-100)',
         '90 — production gateway holding provider API keys, spend quotas and '
         'usage-audit records; compromise would expose provider credentials'],
        ['Assessment type',
         'Deep external and web-application assessment (full framework toolset, '
         'subject to Section 5.3)'],
        ['Verification endpoints',
         '/v1/chat/completions (the gateway\'s OpenAI-compatible completion '
         'endpoint; a bounded proof-of-concept payload is authorized here under '
         'Section 5.2)'],
        ['Environment',
         'The Company\'s production gateway deployment, staged on the laboratory '
         'application host and reachable from the attacker VM across the '
         'laboratory network; the software is run unmodified as published by the '
         'upstream project'],
    ],
    [62 * mm, 112 * mm]))
story.append(Spacer(1, 4))
story.append(Paragraph(
    '<b>3.2 Network segment — laboratory virtualization range (in scope, discovery '
    'sweep only)</b>', body))
story.append(Paragraph(
    'To confirm that no unmanaged service is exposed on the isolated laboratory '
    'network, the Company additionally authorizes a network-level discovery sweep '
    'of the segment below. This authorization is strictly limited to host and '
    'service discovery: application-layer inspection of any system found on the '
    'segment requires a separate authorization naming that system.', body))
story.append(grid_table(
    ['Attribute', 'Value'],
    [
        ['System name', 'Virtualization lab segment'],
        ['Authorized target address', f'{SEGMENT} (laboratory network)'],
        ['Authorized scope identifiers', SEGMENT],
        ['Technology',
         'Laboratory network carrying the attacker VM and the target hosts'],
        ['Asset criticality (client-declared, 0-100)',
         '65 — dedicated laboratory infrastructure, no production data'],
        ['Assessment type',
         'Discovery sweep only (host and service enumeration, see Section 5.4)'],
    ],
    [62 * mm, 112 * mm]))
story.append(Spacer(1, 4))
story.append(Paragraph(
    'The client-declared criticality values above must be supplied to the assessment '
    'framework when each target is registered, because they feed the risk-priority scoring '
    'of the findings in the final report.', body))

story.append(Paragraph('3.3 Assets explicitly OUT OF SCOPE', body))
story.append(Paragraph(
    'The following are <b>strictly out of scope</b>. Any traffic, scanning, probing or '
    'enumeration directed at these systems is a breach of this agreement and must not occur:',
    body))
for item in [
    'Any host other than the two assets named in Sections 3.1 and 3.2, including any '
    'address obtained by DNS enumeration or referenced in application responses. Hosts '
    'discovered by the Section 3.2 sweep are in this category until separately authorized.',
    'The virtualization host machine itself and the assessment team\'s own workstation '
    'connected to the laboratory network.',
    'The AI providers reachable through the gateway (any external model API, its '
    'endpoints, accounts or infrastructure). Only the Company\'s self-hosted OmniRoute '
    'instance is in scope; the upstream project\'s own services are not.',
    'JuiceBox corporate network, employee endpoints, VPN concentrators and mail servers.',
    'Third-party payment gateways, CDN providers, analytics or any externally hosted service.',
    'Any production system of the Company other than the staged gateway deployment named in Section 3.1.',
    'Social engineering, phishing, or any testing involving JuiceBox personnel.',
    'Physical security testing of any JuiceBox premises.',
]:
    story.append(bullet(item))

# ------------------------------------------------------------- objectives
story.append(Paragraph('4. Assessment objectives', h2))
story.append(Paragraph(
    'The Company requests that the assessment pursue the following objectives, in priority '
    'order:', body))
for item in [
    '<b>4.1 Service and version discovery:</b> identify every network service and '
    'software version exposed by the authorized targets, using lightweight active '
    'discovery (nmap service version detection restricted to the listed ports).',
    '<b>4.2 HTTP security-header audit:</b> enumerate the complete set of HTTP response '
    'headers on each web target and report every missing or weakly configured browser '
    'security header (Content-Security-Policy, Strict-Transport-Security where '
    'applicable, X-Frame-Options, X-Content-Type-Options and Referrer-Policy) together '
    'with a per-header explanation and remediation.',
    '<b>4.3 Technology fingerprinting:</b> identify disclosed technology fingerprints '
    '(server banner, framework markers, X-Powered-By style headers) that would assist '
    'an attacker in selecting exploits, using automated fingerprinting tools.',
    '<b>4.4 Cookie and transport review:</b> review the security flags of any session '
    'cookie set by the gateway\'s dashboard, and characterise the transport-security '
    'configuration of each web target where a TLS endpoint exists.',
    '<b>4.5 Rate-limited known-vulnerability checks:</b> where safe template-driven '
    'checks exist (e.g. nuclei with non-invasive templates), identify publicly '
    'documented weaknesses in the web tier without exploiting them, strictly '
    'rate-limited as required by Section 5.1.',
    '<b>4.6 DNS and name characterization:</b> resolve and characterise the name '
    'resolution of the authorized scope identifiers, to confirm addressing and support '
    'exposure analysis.',
    '<b>4.7 Controlled verification of critical findings:</b> for every finding the '
    'Company must remediate before launch, verify its exploitability using the bounded '
    'proof-of-concept techniques authorized in Section 5.2, and record the verification '
    'evidence (which finding was verified, by which technique, and the exact output '
    'that proves it) so that remediation can be prioritized on demonstrated risk.',
    '<b>4.8 Findings correlation and prioritization:</b> consolidate all findings, '
    'remove duplicates, and rank them by severity, risk, business criticality and '
    'confidence, so that the Company can schedule remediation before launch.',
    '<b>4.9 Network segment sweep:</b> enumerate the live hosts and exposed '
    'services on the authorized laboratory segment (Section 3.2), strictly '
    'rate-limited, so that any unmanaged or unexpected service on the shared '
    'range is surfaced and reported per host.',
]:
    story.append(bullet(item))

# ------------------------------------------------------------- rules
story.append(Paragraph('5. Rules of engagement', h2))
story.append(Paragraph('<b>5.1 General conduct</b>', body))
for item in [
    'Testing is restricted to the test window stated on page 1. No activity outside the '
    'window is authorized.',
    'Every individual command must pass the assessment team\'s policy review and receive '
    'explicit human approval before execution. The Company does not authorize unattended or '
    'fully automated execution.',
    'All activity must remain within the authorized scope identifiers listed in Section 3. '
    'Commands whose target resolves outside this scope must be refused by the framework.',
    'All active scanning must be rate-limited to a maximum of 30 packets or requests per '
    'second (e.g. nmap --max-rate 30, nuclei -rl 30), so that no target is saturated.',
    'The assessment team must keep a complete audit trail of every approved command, its '
    'output, exit status, duration, and the fact of human approval. This audit trail forms '
    'part of the required deliverables.',
]:
    story.append(bullet(item))

story.append(Paragraph('<b>5.2 Controlled exploitation and prohibited techniques</b>', body))
story.append(Paragraph(
    'The Company authorizes <b>controlled vulnerability verification</b> against the '
    'gateway (Section 3.1): once the assessment identifies a vulnerability, the team '
    'may verify its exploitability with bounded, non-destructive proof-of-concept '
    'techniques (for example a crafted proof-of-concept request against the '
    'verification endpoint listed in Section 3.1, or scanner-driven parameter '
    'verification), provided that the proof demonstrates the vulnerability exists '
    'and nothing more; data extraction is limited to a single benign verification '
    'record per verified flaw (such as a database banner or software version '
    'string); and every verification command passes the framework\'s policy review '
    'and receives explicit human approval like any other command. No verification '
    'is authorized against the lab segment (Section 3.2). The Company recognizes '
    'that the gateway is a maintained production application, so a verification '
    'attempt that demonstrates <i>no exploitable weakness</i> is a valid and '
    'expected outcome that must be recorded as such in the report.', body))
story.append(Paragraph(
    'The following remain <b>prohibited</b> without exception (non-exhaustive):', body))
for item in [
    'Denial-of-service, resource exhaustion, or any action intended to degrade availability.',
    'Destructive testing, data deletion, or modification of application data or configuration.',
    'Exploitation beyond the controlled verification defined above (no payload '
    'execution beyond the proof, no privilege escalation, no data exfiltration beyond '
    'the single benign verification record per flaw).',
    'Brute-force, credential-stuffing, or password attacks against any authentication '
    'mechanism (a single crafted proof-of-concept credential is not a brute-force attack).',
    'Persistence mechanisms of any kind (web shells, scheduled jobs, modified startup files).',
    'File upload to, or file writing on, the target systems, including scanner flags that '
    'write output files.',
    'Egress of target data to any third-party or out-of-band collection server.',
    'Lateral movement from any authorized target to any other system.',
]:
    story.append(bullet(item))

story.append(Paragraph(
    '<b>5.3 Technique restrictions specific to the gateway (Section 3.1)</b>',
    body))
story.append(Paragraph(
    'The laboratory network is shared with other assessment teams during this window. To '
    'keep packet volume low, traceroute must not be run against the gateway. All '
    'other discovery and inspection tools enumerated by the assessment framework remain '
    'authorized for this target, subject to the rate limit in Section 5.1.', body))

story.append(Paragraph(
    '<b>5.4 Technique restrictions specific to the lab segment (Section 3.2)</b>',
    body))
story.append(Paragraph(
    'The Section 3.2 authorization is for network-level discovery only. '
    f'Application-layer inspection (curl, whatweb, sslscan, nuclei) must not be '
    f'run against the {SEGMENT} segment. A host discovered by the sweep is '
    'not authorized for any further assessment by that fact alone; a separate '
    'authorization naming the host is required first, subject to the rate limit '
    'in Section 5.1.', body))

story.append(Paragraph('<b>5.6 Incidents and escalation</b>', body))
story.append(Paragraph(
    'If any activity causes an unintended service disruption, or if the team discovers '
    'evidence of an actual security compromise, all testing must stop immediately and the '
    'escalation contact must be notified: <b>' + ESCALATION_CONTACT + ', '
    + ESCALATION_PHONE + '</b>. Work may resume only after written confirmation from the '
    'Company.', body))

# ------------------------------------------------------------- deliverables
story.append(Paragraph('6. Expected deliverables and acceptance criteria', h2))
story.append(grid_table(
    ['#', 'Deliverable', 'Acceptance criterion'],
    [
        ['1', 'Assessment report (HTML) covering both authorized targets, produced by the '
              'framework\'s reporting module.',
         'Contains an executive summary, the analysis mode used, and prioritized '
         'findings with severity, risk score, priority score, confidence, affected '
         'endpoint, scoring breakdown, evidence, remediation and the client-declared '
         'asset criticality.'],
        ['2', 'Complete execution audit trail.',
         'Every approved command recorded with its raw output, exit code, duration, '
         'attempt count and human-approval record.'],
        ['3', 'Policy-refusal evidence.',
         'Evidence that out-of-scope and prohibited commands were refused before '
         'execution, with the policy reason shown.'],
        ['4', 'Remediation summary for the self-hosted AI gateway.',
         'Each finding mapped to a concrete remediation action, ordered by priority '
         'score.'],
        ['5', 'Controlled verification evidence.',
         'For each finding verified under Section 5.2: which finding, which technique '
         'verified it, the exact command and output that proves exploitability, and the '
         'single benign verification record extracted (if any), so remediation can be '
         'scheduled on demonstrated risk.'],
        ['6', 'Automation-benefit statement.',
         'A statement of the number of commands executed, the wall-clock duration of '
         'the automated assessment, and the equivalent manual effort an unaided tester '
         'would require to reach the same coverage, so the Company can evaluate the '
         'efficiency of the semi-autonomous methodology.'],
    ],
    [10 * mm, 76 * mm, 88 * mm]))
story.append(Paragraph(
    'The Company requires that the final report clearly state the mode of analysis used '
    '(automated AI-provider analysis or the framework\'s deterministic local analyzer), so '
    'that the Company can weigh the findings accordingly.', body))

# ------------------------------------------------------------- handling
story.append(Paragraph('7. Information handling and confidentiality', h2))
for item in [
    'All findings, reports, and target outputs are classified Confidential and are to be '
    'shared only between the named contacts in this document and the assessment team.',
    'Any API keys or credentials configured during the engagement must be stored encrypted '
    'and must never be returned in cleartext by any interface of the framework.',
    'The assessment team must delete all retained client data within 30 days of report '
    'acceptance, except anonymized, aggregated metrics required for academic publication.',
    'Any academic publication resulting from this engagement must present the environment as '
    'a laboratory deployment and must not disclose the Company\'s name or identifiable '
    'system details. The present document is a fictional scenario prepared for laboratory '
    'demonstration and publication purposes.',
]:
    story.append(bullet(item))

# ------------------------------------------------------------- authorization
story.append(Paragraph('8. Client authorization and acceptance', h2))
story.append(Paragraph(
    'By signing below, the Company confirms that the assets listed in Section 3 are owned or '
    'controlled by the Company and authorizes the assessment team to conduct the activities '
    'described in this document, within the stated scope, rules and time window. The '
    'assessment team accepts the rules of engagement by counter-signing.', body))
signature = grid_table(
    ['', 'For the Company (client authorization)', 'For the assessment team (acceptance)'],
    [
        ['Name', 'Ananya Rao', '________________________'],
        ['Role', 'Chief Information Security Officer', 'Team lead, red teaming framework'],
        ['Signature', '________________________', '________________________'],
        ['Date', ENGAGEMENT_DATE.strftime('%d %B %Y'), '________________________'],
    ],
    [18 * mm, 78 * mm, 78 * mm])
story.append(KeepTogether([signature, Spacer(1, 6)]))
story.append(Paragraph(
    'A signed copy of this authorization must be retained by both parties for the duration '
    'of the engagement and must be produced on request during the assessment.', small))

doc.build(story)
print('Wrote', OUT)
