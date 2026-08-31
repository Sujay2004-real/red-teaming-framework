# -*- coding: utf-8 -*-
"""Generates the fictional client 'Request for Security Assessment Services' PDF."""
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
ENGAGEMENT_REF = 'JB/SEC/2026/014'
ENGAGEMENT_DATE = date(2026, 9, 1)
TEST_WINDOW = '02 September 2026 to 06 September 2026 (both days inclusive)'
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
                      title='Request for Security Assessment Services', author=COMPANY)
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
    'e-commerce storefront. Before the platform is exposed to production customers, the '
    'Company wishes to obtain an independent, authorized security assessment of the '
    'pre-release deployment, conducted in a controlled laboratory environment that mirrors '
    'the intended production configuration.', body))
story.append(Paragraph(
    'We request your team to perform a non-destructive external and web-application security '
    'assessment of the assets identified in Section 3 of this document, strictly within the '
    'authorized scope stated therein, during the test window stated above. We understand that '
    'your assessment methodology is semi-autonomous: automated reconnaissance and scanning '
    'steps are proposed by your framework and must be individually reviewed and approved by '
    'your human operator before execution. This is acceptable to the Company, and we '
    'specifically require that this human approval step remain in force for every command '
    'issued against our assets.', body))
story.append(Paragraph(
    'All systems listed in Section 3 are owned or controlled by the Company. No third-party, '
    'shared-hosting, or cloud-provider infrastructure is included in scope. Please sign and '
    'return the authorization in Section 8 to confirm your acceptance of these terms.', body))
story.append(Paragraph(
    'Yours sincerely,<br/><br/><b>Ananya Rao</b><br/>Chief Information Security Officer<br/>'
    f'{COMPANY}', body))

# ------------------------------------------------------------- background
story.append(Paragraph('2. Background and business context', h2))
story.append(Paragraph(
    'JuiceBox Retail operates a loyalty and retail platform serving approximately 240,000 '
    'registered customers. The pre-release storefront (internally named "Juice Shop") is a '
    'new Node.js-based e-commerce application scheduled to go live at the end of Q3 2026. '
    'The Company is contractually obliged to its payment partners to evidence a pre-launch '
    'vulnerability assessment. The assessment requested here is that evidence.', body))
story.append(Paragraph(
    'The Company additionally maintains an internal web-application security-training system '
    '(internally named "DVWA Lab") used by the IT team. A baseline assessment of this '
    'training system is requested under the same engagement for calibration purposes, as '
    'described in Section 3.2.', body))

# ------------------------------------------------------------- scope
story.append(Paragraph('3. Authorized scope of the assessment', h2))
story.append(Paragraph(
    '<b>3.1 Primary asset — pre-release storefront (in scope, full assessment)</b>', body))
story.append(Paragraph(
    'The following asset is the only production-relevant system authorized for this '
    'engagement. All testing activity must be directed exclusively at it.', body))
story.append(grid_table(
    ['Attribute', 'Value'],
    [
        ['System name', 'Juice Shop pre-release storefront'],
        ['Authorized target address', 'juice-shop:3000 (assessment-lab network)'],
        ['Authorized scope identifiers', 'juice-shop, juice-shop:3000'],
        ['Technology', 'Node.js / Express web application, HTTP on TCP port 3000'],
        ['Asset criticality (client-declared, 0-100)',
         '85 — customer-facing e-commerce platform'],
        ['Environment',
         'Isolated laboratory deployment (Docker), mirrors release-candidate build'],
    ],
    [62 * mm, 112 * mm]))
story.append(Spacer(1, 4))
story.append(Paragraph(
    '<b>3.2 Secondary asset — internal training system (in scope, baseline only)</b>', body))
story.append(grid_table(
    ['Attribute', 'Value'],
    [
        ['System name', 'DVWA internal security-training lab'],
        ['Authorized target address', 'dvwa:80 (assessment-lab network)'],
        ['Authorized scope identifiers', 'dvwa, dvwa:80'],
        ['Technology', 'Apache / PHP / MySQL training application, HTTP on TCP port 80'],
        ['Asset criticality (client-declared, 0-100)',
         '40 — internal training system, no production data'],
        ['Assessment type',
         'Service discovery and HTTP header baseline only (see Section 5.3)'],
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
    'Any host other than the two assets named in Sections 3.1 and 3.2, including any address '
    'obtained by DNS enumeration or referenced in application responses.',
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
    '<b>4.1 Service discovery:</b> identify the network services and versions exposed by the '
    'authorized targets, using lightweight active discovery (e.g. nmap service version '
    'detection restricted to the listed ports).',
    '<b>4.2 Web-attack-surface inspection:</b> enumerate HTTP response headers, disclosed '
    'technology fingerprints, transport-security configuration, and missing browser security '
    'headers.',
    '<b>4.3 Known-vulnerability identification:</b> where safe template-driven checks exist '
    '(e.g. nuclei with non-invasive templates), identify publicly documented weaknesses in '
    'the web tier without exploiting them.',
    '<b>4.4 Findings correlation and prioritization:</b> consolidate all findings, remove '
    'duplicates, and rank them by severity, risk, business criticality and confidence, so '
    'that the Company can schedule remediation before launch.',
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
    '<b>5.3 Technique restrictions specific to the DVWA training system (Section 3.2)</b>',
    body))
story.append(Paragraph(
    'Because the training system contains intentionally vulnerable code, only service '
    'discovery (nmap -sV on TCP port 80) and HTTP header inspection (curl -I, whatweb) are '
    'authorized against it. Template-driven vulnerability checks (e.g. nuclei) must not be '
    'run against the DVWA lab.', body))

story.append(Paragraph('<b>5.4 Incidents and escalation</b>', body))
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
         'Contains prioritized findings with severity, risk score, priority score, '
         'confidence, evidence, remediation and the client-declared asset criticality.'],
        ['2', 'Complete execution audit trail.',
         'Every approved command recorded with its raw output, exit code, duration, attempt '
         'count and human-approval record.'],
        ['3', 'Policy-refusal evidence.',
         'Evidence that out-of-scope and prohibited commands were refused before execution, '
         'with the policy reason shown.'],
        ['4', 'Remediation summary for the pre-release storefront.',
         'Each finding mapped to a concrete remediation action, ordered by priority score.'],
    ],
    [10 * mm, 82 * mm, 82 * mm]))
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
