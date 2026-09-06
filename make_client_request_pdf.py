# -*- coding: utf-8 -*-
"""Generates the fictional client 'Request for Security Assessment Services' PDF.

Virtualization-lab edition (letter v4): the same fictional client, but the
assessment now targets a dedicated virtualization laboratory of real systems
rather than container-only lab machines. Every authorized asset is a virtual
machine (or the segment they live on): the storefront and a deliberately
weakened legacy training server as full VMs on the lab's host-only network
(192.168.56.0/24), plus a discovery sweep of that segment. The letter is
deliberately parser-compatible (label/value tables, numbered objectives, both
restriction sentence shapes).
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

COMPANY = 'JuiceBox Retail Pvt. Ltd.'
ADDRESS = '4th Floor, Orion Tech Park, Whitefield, Bengaluru, Karnataka 560066'
ENGAGEMENT_REF = 'JB/SEC/2026/023'
ENGAGEMENT_DATE = date(2026, 9, 6)
TEST_WINDOW = '08 September 2026 to 14 September 2026 (both days inclusive)'
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
                      title='Request for Security Assessment Services — Virtualization Lab Assessment',
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
    f'{COMPANY} ("JuiceBox", "the Company") is preparing to launch a new customer-facing '
    'e-commerce storefront. Under engagement JB/SEC/2026/022 your team performed the '
    'second-pass deep assessment of the container-based laboratory deployment. For this '
    'final pre-launch review, the Company has commissioned a dedicated assessment '
    'virtualization laboratory: full operating systems running as virtual machines on an '
    'isolated network, rather than shared containers, so that the assessment exercises '
    'real kernels, real network stacks and real multi-service hosts. The Company now '
    'requires the same depth of assessment against this virtualization laboratory: full '
    'service and version enumeration, a complete HTTP security-header audit, technology '
    'fingerprinting, cookie and transport review, and rate-limited template-driven '
    'vulnerability checks, all correlated into one prioritized report.', body))
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
    'registered customers. The pre-release storefront (internally named "Juice Shop") is a '
    'new Node.js-based e-commerce application scheduled to go live at the end of Q3 2026. '
    'The Company is now contractually obliged to its payment partners to evidence a final '
    'pre-launch vulnerability assessment performed against systems that behave as real '
    'production hosts behave.', body))
story.append(Paragraph(
    'To meet that obligation, the Company has built an assessment virtualization '
    'laboratory on an isolated host-only network (192.168.56.0/24). The storefront '
    'deployment to be assessed runs there as a full virtual machine on the '
    'laboratory application host, alongside a deliberately weakened legacy training '
    'host rebuilt as a full virtual machine, so the assessment exercises genuine '
    'multi-service operating systems rather than single-purpose containers. The '
    'assessment requested here covers that laboratory and is the evidence the '
    'payment partners require.', body))

# ------------------------------------------------------------- scope
story.append(Paragraph('3. Authorized scope of the assessment', h2))
story.append(Paragraph(
    '<b>3.1 Primary asset — pre-release storefront (in scope, deep assessment)</b>', body))
story.append(Paragraph(
    'The following asset is the only production-relevant system authorized for this '
    'engagement. All testing activity must be directed exclusively at it.', body))
story.append(grid_table(
    ['Attribute', 'Value'],
    [
        ['System name', 'Juice Shop pre-release storefront'],
        ['Authorized target address', '192.168.56.10:3000 (virtualization laboratory)'],
        ['Authorized scope identifiers', '192.168.56.10, 192.168.56.10:3000'],
        ['Technology', 'Node.js / Express web application, HTTP on TCP port 3000'],
        ['Asset criticality (client-declared, 0-100)',
         '90 — customer-facing e-commerce platform, weeks from launch'],
        ['Assessment type',
         'Deep external and web-application assessment (full framework toolset, '
         'subject to Section 5.3)'],
        ['Environment',
         'Full virtual machine (laboratory application host) on the isolated '
         'laboratory network, mirrors release-candidate build'],
    ],
    [62 * mm, 112 * mm]))
story.append(Spacer(1, 4))
story.append(Paragraph(
    '<b>3.2 Secondary asset — legacy multi-service training server (in scope, '
    'baseline only)</b>', body))
story.append(grid_table(
    ['Attribute', 'Value'],
    [
        ['System name', 'Legacy multi-service training server'],
        ['Authorized target address', '192.168.56.20:80 (virtualization laboratory)'],
        ['Authorized scope identifiers', '192.168.56.20, 192.168.56.20:80'],
        ['Technology',
         'Legacy multi-service Linux server (Apache / PHP / MySQL training '
         'applications), HTTP on TCP port 80'],
        ['Asset criticality (client-declared, 0-100)',
         '50 — deliberately weakened training host, no production data'],
        ['Assessment type',
         'Service discovery and HTTP header baseline only (see Section 5.4)'],
        ['Environment',
         'Full virtual machine on the isolated laboratory network'],
    ],
    [62 * mm, 112 * mm]))
story.append(Spacer(1, 4))
story.append(Paragraph(
    '<b>3.3 Network segment — laboratory virtualization range (in scope, discovery '
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
        ['Authorized target address', '192.168.56.0/24 (isolated laboratory network)'],
        ['Authorized scope identifiers', '192.168.56.0/24'],
        ['Technology',
         'Isolated host-only network carrying the laboratory virtual machines'],
        ['Asset criticality (client-declared, 0-100)',
         '65 — dedicated laboratory infrastructure, no production data'],
        ['Assessment type',
         'Discovery sweep only (host and service enumeration, see Section 5.5)'],
    ],
    [62 * mm, 112 * mm]))
story.append(Spacer(1, 4))
story.append(Paragraph(
    'The client-declared criticality values above must be supplied to the assessment '
    'framework when each target is registered, because they feed the risk-priority scoring '
    'of the findings in the final report.', body))

story.append(Paragraph('3.4 Assets explicitly OUT OF SCOPE', body))
story.append(Paragraph(
    'The following are <b>strictly out of scope</b>. Any traffic, scanning, probing or '
    'enumeration directed at these systems is a breach of this agreement and must not occur:',
    body))
for item in [
    'Any host other than the three assets named in Sections 3.1, 3.2 and 3.3, including any '
    'address obtained by DNS enumeration or referenced in application responses. Hosts '
    'discovered by the Section 3.3 sweep are in this category until separately authorized.',
    'The virtualization host machine itself and the assessment team\'s own workstation '
    'connected to the laboratory network.',
    'JuiceBox corporate network, employee endpoints, VPN concentrators and mail servers.',
    'Third-party payment gateways, CDN providers, analytics or any externally hosted service.',
    'Any production system of the Company, including the currently live legacy storefront.',
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
    'cookie set by the storefront, and characterise the transport-security '
    'configuration of each web target where a TLS endpoint exists.',
    '<b>4.5 Rate-limited known-vulnerability checks:</b> where safe template-driven '
    'checks exist (e.g. nuclei with non-invasive templates), identify publicly '
    'documented weaknesses in the web tier without exploiting them, strictly '
    'rate-limited as required by Section 5.1.',
    '<b>4.6 DNS and name characterization:</b> resolve and characterise the name '
    'resolution of the authorized scope identifiers, to confirm addressing and support '
    'exposure analysis.',
    '<b>4.7 Findings correlation and prioritization:</b> consolidate all findings, '
    'remove duplicates, and rank them by severity, risk, business criticality and '
    'confidence, so that the Company can schedule remediation before launch.',
    '<b>4.8 Network segment sweep:</b> enumerate the live hosts and exposed '
    'services on the authorized laboratory segment (Section 3.3), strictly '
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

story.append(Paragraph('<b>5.2 Prohibited techniques (non-exhaustive)</b>', body))
for item in [
    'Denial-of-service, resource exhaustion, or any action intended to degrade availability.',
    'Destructive testing, data deletion, or modification of application data or configuration.',
    'Exploitation of identified vulnerabilities beyond proof that the vulnerability exists '
    '(no payload execution, no privilege escalation, no data exfiltration beyond a single '
    'benign marker).',
    'Brute-force, credential-stuffing, or password attacks against any authentication '
    'mechanism.',
    'Persistence mechanisms of any kind (web shells, scheduled jobs, modified startup files).',
    'File upload to, or file writing on, the target systems, including scanner flags that '
    'write output files.',
    'Egress of target data to any third-party or out-of-band collection server.',
]:
    story.append(bullet(item))

story.append(Paragraph(
    '<b>5.3 Technique restrictions specific to the storefront (Section 3.1)</b>',
    body))
story.append(Paragraph(
    'The laboratory network is shared with other assessment teams during this window. To '
    'keep packet volume low, traceroute must not be run against the storefront. All '
    'other discovery and inspection tools enumerated by the assessment framework remain '
    'authorized for this target, subject to the rate limit in Section 5.1.', body))

story.append(Paragraph(
    '<b>5.4 Technique restrictions specific to the legacy training server (Section 3.2)</b>',
    body))
story.append(Paragraph(
    'Because the legacy training host contains intentionally vulnerable code, only service '
    'discovery (nmap) and HTTP header inspection (curl, whatweb) are authorized against '
    'it. Template-driven vulnerability checks (e.g. nuclei) and every other tool must '
    'not be run against the legacy server.', body))

story.append(Paragraph(
    '<b>5.5 Technique restrictions specific to the lab segment (Section 3.3)</b>',
    body))
story.append(Paragraph(
    'The Section 3.3 authorization is for network-level discovery only. '
    'Application-layer inspection (curl, whatweb, sslscan, nuclei) must not be '
    'run against the 192.168.56.0/24 segment. A host discovered by the sweep is '
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
        ['4', 'Remediation summary for the pre-release storefront.',
         'Each finding mapped to a concrete remediation action, ordered by priority '
         'score.'],
        ['5', 'Automation-benefit statement.',
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
