# -*- coding: utf-8 -*-
"""Compile docs/backend_algorithms_reference.pdf - a formal reference to the
algorithms and formulae used by the Red Teaming Framework backend.

This is the technical/mathematical companion to
docs/backend_technical_reference.md (which explains the same components in
plain language). Every formula, mapping table, bound and pseudocode block in the
generated PDF is transcribed from the live backend source:

    backend/modules/analyzer.py
    backend/modules/planner.py
    backend/modules/policy_engine.py
    backend/modules/engagement_parser.py
    backend/modules/executor.py
    backend/modules/secret_store.py
    backend/main.py
    backend/models.py

Equations are typeset with Unicode maths (DejaVu Sans / Sans Mono are embedded
so the PDF is self-contained); pseudocode blocks are rendered in a dark
monospace panel. The layout, brand colours and header/footer rules mirror
make_backend_reference_pdf.py.

Run from the project root (any interpreter with reportlab):
    python make_algorithms_reference_pdf.py

Fonts are read from build/fonts (cached from a matplotlib install on first
run); if they are missing the script falls back to the built-in Helvetica /
Courier faces and warns - the maths still renders, but less cleanly.
"""
import re
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether, PageBreak,
                                PageTemplate, Paragraph, Spacer, Table, TableStyle)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'docs' / 'backend_algorithms_reference.pdf'
FONT_DIR = ROOT / 'build' / 'fonts'

TEXT_W = 174 * mm

# --------------------------------------------------------------------- fonts
# DejaVu gives us a single family that carries every glyph the maths needs
# (Greek, set operators, arithmetic, arrows) in normal, bold, oblique and a
# monospaced code face. A TTF is subset-embedded into the PDF, so the deliverable
# never depends on the host having these fonts later.

FONT_FILES = ('DejaVuSans.ttf', 'DejaVuSans-Bold.ttf', 'DejaVuSans-Oblique.ttf',
              'DejaVuSansMono.ttf', 'DejaVuSansMono-Bold.ttf')

# Fallback search paths used when build/fonts has not been populated yet: any
# matplotlib install ships this exact set under mpl-data/fonts/ttf.
_FONT_CANDIDATES = []
for base in (Path(sys.prefix), ROOT.parent, Path.home()):
    p = base / 'Lib' / 'site-packages' / 'matplotlib' / 'mpl-data' / 'fonts' / 'ttf'
    if p.is_dir():
        _FONT_CANDIDATES.append(p)
    p = base / 'Library' / 'lib' / 'python' / 'site-packages' / 'matplotlib' / 'mpl-data' / 'fonts' / 'ttf'
    if p.is_dir():
        _FONT_CANDIDATES.append(p)
_FONT_CANDIDATES.append(Path(sys.prefix) / 'mpl-data' / 'fonts' / 'ttf')


def _prepare_fonts():
    """Return True when the DejaVu TTFs are available (copying them into
    build/fonts on first use), else False so the caller can fall back."""
    for name in FONT_FILES:
        if (FONT_DIR / name).exists():
            continue
        source = next((d / name for d in _FONT_CANDIDATES if (d / name).exists()), None)
        if source is None:
            return False
        FONT_DIR.mkdir(parents=True, exist_ok=True)
        FONT_DIR.joinpath(name).write_bytes(source.read_bytes())
    return True


if _prepare_fonts():
    pdfmetrics.registerFont(TTFont('DVSans', str(FONT_DIR / 'DejaVuSans.ttf')))
    pdfmetrics.registerFont(TTFont('DVSans-Bold', str(FONT_DIR / 'DejaVuSans-Bold.ttf')))
    pdfmetrics.registerFont(TTFont('DVSans-Oblique', str(FONT_DIR / 'DejaVuSans-Oblique.ttf')))
    pdfmetrics.registerFont(TTFont('DVSansMono', str(FONT_DIR / 'DejaVuSansMono.ttf')))
    pdfmetrics.registerFont(TTFont('DVSansMono-Bold', str(FONT_DIR / 'DejaVuSansMono-Bold.ttf')))
    pdfmetrics.registerFontFamily('DVSans', normal='DVSans', bold='DVSans-Bold',
                                  italic='DVSans-Oblique', boldItalic='DVSans-Bold')
    pdfmetrics.registerFontFamily('DVSansMono', normal='DVSansMono',
                                  bold='DVSansMono-Bold', italic='DVSansMono',
                                  boldItalic='DVSansMono-Bold')
    BODY_FONT = 'DVSans'
    CODE_FONT = 'DVSansMono'
    FONT_OK = True
else:
    print('WARNING: DejaVu fonts not found under build/fonts or any matplotlib '
          'install; falling back to Helvetica/Courier (math glyphs may degrade).')
    BODY_FONT = 'Helvetica'
    CODE_FONT = 'Courier'
    FONT_OK = False

# ------------------------------------------------------------------- palette
brand_navy = colors.HexColor('#1F3864')
brand_blue = colors.HexColor('#2E74B5')
brand_light = colors.HexColor('#DEEAF6')
rule_grey = colors.HexColor('#BFBFBF')
code_bg = colors.HexColor('#101828')
note_bg = colors.HexColor('#F2F6FB')
ink = colors.HexColor('#222222')

base = getSampleStyleSheet()

h1 = ParagraphStyle('H1x', fontName=BODY_FONT + '-Bold', fontSize=15, leading=19,
                    textColor=brand_navy, spaceBefore=4, spaceAfter=6)
h2 = ParagraphStyle('H2x', fontName=BODY_FONT + '-Bold', fontSize=11.5, leading=15,
                    textColor=brand_blue, spaceBefore=12, spaceAfter=4)
h3 = ParagraphStyle('H3x', fontName=BODY_FONT + '-Bold', fontSize=10, leading=13,
                    textColor=brand_navy, spaceBefore=9, spaceAfter=3)
body = ParagraphStyle('Bodyx', fontName=BODY_FONT, fontSize=9, leading=12.6,
                      textColor=ink, alignment=TA_JUSTIFY, spaceAfter=5)
bullet = ParagraphStyle('Bulletx', parent=body, leftIndent=12, bulletIndent=4,
                        spaceAfter=2.5)
eq = ParagraphStyle('Eqx', fontName=BODY_FONT, fontSize=10, leading=14,
                    textColor=ink, alignment=TA_CENTER, spaceAfter=0)
eqnum = ParagraphStyle('EqNumx', fontName=BODY_FONT + '-Bold', fontSize=9,
                       leading=14, textColor=brand_navy, alignment=2, spaceAfter=0)
code = ParagraphStyle('Codex', fontName=CODE_FONT, fontSize=7.4, leading=9.6,
                      textColor=colors.HexColor('#EAECF0'), spaceAfter=0)
codeh = ParagraphStyle('CodeHx', fontName=CODE_FONT + '-Bold', fontSize=7.6,
                       leading=10, textColor=colors.HexColor('#F2C94C'),
                       spaceAfter=0)
cell = ParagraphStyle('Cellx', parent=body, fontSize=8, leading=10.6,
                      alignment=0, spaceAfter=0)
cellh = ParagraphStyle('CellHx', parent=cell, fontName=BODY_FONT + '-Bold',
                       textColor=colors.white)
note = ParagraphStyle('Notex', fontName=BODY_FONT, fontSize=8, leading=11,
                      textColor=colors.HexColor('#333333'), alignment=TA_JUSTIFY,
                      spaceAfter=0)
label = ParagraphStyle('Labx', fontName=BODY_FONT + '-Bold', fontSize=8,
                       leading=10.6, textColor=brand_navy, spaceAfter=0)

# ------------------------------------------------------------- small helpers
def c(text):
    """Inline code span."""
    return f'<font face="{CODE_FONT}" size="7.5">{text}</font>'


def esc(text):
    return (text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'))


def P(text, style=None):
    return Paragraph(text, style or body)


def B(text):
    return Paragraph('<bullet>&bull;</bullet> ' + text, bullet)


def code_panel(header, lines):
    """Dark panel: a small amber caption line then monospaced body."""
    rows = []
    if header:
        rows.append([Paragraph(esc(header), codeh)])
    body_lines = '<br/>'.join(esc(line).replace(' ', '&nbsp;') for line in lines)
    rows.append([Paragraph(body_lines, code)])
    panel = Table(rows, colWidths=[TEXT_W])
    panel.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), code_bg),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, 0), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 1), (-1, -1), 2),
    ]))
    return panel


def alg(header, lines):
    flow = [code_panel(header, lines), Spacer(1, 6)]
    return KeepTogether(flow)


def eqn(label, formula):
    """Numbered display equation centred across the text column."""
    eq_par = Paragraph(formula, eq)
    num_par = Paragraph(f'({label})', eqnum)
    t = Table([['', eq_par, num_par]], colWidths=[24 * mm, 126 * mm, 24 * mm],
              hAlign='CENTER')
    t.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    return KeepTogether([t, Spacer(1, 2)])


def md_table(headers, rows, widths=None, note_rows=()):
    """Table with a brand-navy header row and zebra body rows."""
    widths = widths or [TEXT_W / len(headers)] * len(headers)
    data = [[Paragraph(esc(h), cellh) for h in headers]]
    for row in rows:
        data.append([Paragraph(esc(str(v)), cell) if not str(v).startswith('<') else Paragraph(str(v), cell) for v in row])
    t = Table(data, colWidths=widths, hAlign='LEFT', repeatRows=1)
    style = [
        ('BACKGROUND', (0, 0), (-1, 0), brand_navy),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F2F6FB')]),
        ('GRID', (0, 0), (-1, -1), 0.5, rule_grey),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
    ]
    t.setStyle(TableStyle(style))
    return t


def notes_table(rows):
    """Unstyled key/value rows used for symbol glossaries (Symbol | meaning)."""
    data = [[Paragraph(rows[i][0], label), Paragraph(rows[i][1], note)] for i in range(len(rows))]
    t = Table(data, colWidths=[46 * mm, TEXT_W - 46 * mm], hAlign='LEFT')
    t.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 2),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 1),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
    ]))
    return t


def note_para(text):
    box = Table([[Paragraph(text, note)]], colWidths=[TEXT_W])
    box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), note_bg),
        ('BOX', (0, 0), (-1, -1), 0.4, brand_light),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    return box


story = []
_ = None  # (reserved)


def chapter_no(num, title):
    story.append(Paragraph(f'{num}&nbsp;&nbsp;{title}', h1))


def sub_no(title):
    story.append(Paragraph(title, h2))


def sub3(title):
    story.append(Paragraph(title, h3))


# =========================================================================
# COVER band
# =========================================================================
cover = Table([[Paragraph('SEMI-AUTONOMOUS RED TEAMING FRAMEWORK',
                          ParagraphStyle('CoverTag', parent=base['Normal'], fontName=BODY_FONT,
                                         fontSize=10, leading=13, textColor=brand_blue,
                                         alignment=TA_CENTER)),
                ]], colWidths=[TEXT_W])
cover.setStyle(TableStyle([('BOTTOMPADDING', (0, 0), (-1, -1), 4)]))
story.append(Spacer(1, 2))
story.append(cover)
title_line = Paragraph('Backend Algorithms &amp; Formulae Reference',
                       ParagraphStyle('CoverTitle', parent=base['Normal'], fontName=BODY_FONT + '-Bold',
                                      fontSize=21, leading=25, textColor=brand_navy,
                                      alignment=TA_CENTER, spaceAfter=4))
story.append(title_line)
subtitle = Paragraph('The scoring, planning, policy, parsing, execution and '
                     'cryptography mathematics of the assessment engine, stated precisely',
                     ParagraphStyle('CoverSub', parent=base['Normal'], fontName=BODY_FONT,
                                    fontSize=10.5, leading=14, textColor=colors.HexColor('#555555'),
                                    alignment=TA_CENTER, spaceAfter=6))
story.append(subtitle)
story.append(Spacer(1, 6))

# ------------------------------------------------------------------- TOC
toc = TableOfContents()
toc.levelStyles = [
    ParagraphStyle('TOC1', parent=base['Normal'], fontName=BODY_FONT, fontSize=9.5,
                   leading=15, textColor=ink, leftIndent=0, firstLineIndent=0,
                   spaceBefore=1),
    ParagraphStyle('TOC2', parent=base['Normal'], fontName=BODY_FONT, fontSize=8.5,
                   leading=13, textColor=colors.HexColor('#444444'), leftIndent=14),
]
story.append(Paragraph('Contents', h2))
story.append(Spacer(1, 2))
story.append(toc)
story.append(PageBreak())

# =========================================================================
# 1  Scope, notation, conventions
# =========================================================================
chapter_no(1, 'Scope, Notation &amp; Conventions')

P('This document is the formal companion to the plain-language '
  '<i>Backend Technical Reference</i>. It states, in mathematical notation and '
  'structured pseudocode, every algorithm, scoring formula, mapping table and '
  'resource bound implemented by the backend. Each formula is transcribed '
  'directly from the module named beside it; where a heuristic is described in '
  'prose in the code, that prose is captured here as an explicit rule.')

P('One design constraint colours most of the mathematics: the framework must '
  'produce a defensible, fully explainable result even when no AI provider is '
  'configured. The deterministic fallback therefore defines concrete numeric '
  'formulae for severity, risk, priority and confidence; an AI path may supply '
  'the <i>inputs</i> to those same formulae, but never bypasses them. All '
  'four quantities are recomputed by one shared scoring routine after any '
  'merge, so a Critical duplicate can never be filed under whatever severity '
  'arrived first.')

sub_no('1.1&nbsp;&nbsp;Bounding convention')
P('Drivers arrive from two untrusted sources &mdash; a model response and '
  'scanner output &mdash; so every numeric field is coerced through a '
  'single clamp. For a field with range [<i>lo</i>, <i>hi</i>] and default '
  '<i>d</i>:')
eqn('1.1', 'x\' = d, &nbsp;if x is not a number;&nbsp;&nbsp;&nbsp;'
           'x\' = max(lo, min(hi, x)),&nbsp; otherwise')
P('Applied as <font face="' + CODE_FONT + '" size="7.5">bounded_int(value, default, lo, hi)</font> in '
  '<i>analyzer.py</i>. Whenever a value is absent or unusable, the field takes '
  'its default <i>d</i> rather than failing the whole finding.')

sub_no('1.2&nbsp;&nbsp;Symbol glossary')
story.append(notes_table([
    ('σ', 'severity label, σ ∈ {Low, Medium, High, Critical}'),
    ('S(σ)', 'severity score S: Low 25, Medium 50, High 75, Critical 100'),
    ('ρ(σ)', 'severity rank ρ: Low 1, Medium 2, High 3, Critical 4'),
    ('e, i, x', 'exploitability, impact, exposure — each in [1, 5] (default 3)'),
    ('c', 'confidence score, c ∈ [0, 100] (default 70)'),
    ('a', 'asset criticality, a ∈ [0, 100] (default 70)'),
    ('R', 'risk score (dimensionless product, [1, 125])'),
    ('P', 'priority score ([15, 100])'),
    ('A, D', 'A = enabled plan-step indices; D = indices already executed'),
    ('T', 'set of tools known to the framework (8 tools)'),
    ('τ', 'execution timeout, 360 s'),
    ('N', 'a CIDR network; |N| = its address count'),
    ('round(·)', 'Python round — banker’s rounding (half rounds to even)'),
    ('x ∥ y', 'string concatenation'),
    ('SHA-256(·)[0:24]', 'full SHA-256 digest, kept as the first 24 hex digits'),
]))
story.append(Spacer(1, 4))

# =========================================================================
# 2  Finding scoring
# =========================================================================
chapter_no(2, 'Finding Scoring (<i>backend/modules/analyzer.py</i>)')

sub_no('2.1&nbsp;&nbsp;Severity normalisation and score')
P('Every finding carries a categorical severity. Anything outside the four '
  'labels collapses to Low, so a model emitting an invented level cannot '
  'inflate a score:')
eqn('2.1', 'σ* = normalize(σ) = σ &nbsp;if σ ∈ {Low, Medium, High, Critical}, else Low')

story.append(md_table(
    ['Severity σ', 'Score S(σ)', 'Rank ρ(σ)', 'Meaning'],
    [['Low', '25', '1', 'Minor hardening gap or information exposure'],
     ['Medium', '50', '2', 'Real but bounded weakness'],
     ['High', '75', '3', 'Likely-exploitable weakness'],
     ['Critical', '100', '4', 'Direct, high-impact compromise']],
    widths=[30 * mm, 24 * mm, 22 * mm, 98 * mm]))

sub_no('2.2&nbsp;&nbsp;Drivers and their bounds')
story.append(md_table(
    ['Driver', 'Symbol', 'Range', 'Default', 'Persisted'],
    [['Exploitability', 'e', '1 – 5', '3', 'exploitability'],
     ['Impact', 'i', '1 – 5', '3', 'impact'],
     ['Exposure', 'x', '1 – 5', '3', 'exposure'],
     ['Confidence', 'c', '0 – 100', '70', 'confidence_score'],
     ['Asset criticality', 'a', '0 – 100', '70', 'asset_criticality']],
    widths=[34 * mm, 20 * mm, 24 * mm, 22 * mm, 74 * mm]))

sub_no('2.3&nbsp;&nbsp;Risk score')
P('Risk is the product of the three reachability drivers. It is deliberately '
  'multiplicative: a weakness that is easy to exploit, damages a core '
  'function and is reachable from the whole internet should dominate a '
  'single-driver weakness.')
eqn('2.2', 'R = e · i · x ,&nbsp;&nbsp;&nbsp;R ∈ [1, 125]')
P('Because every driver is an integer in [1, 5], R takes the 125 discrete '
  'values 1 = 1·1·1 up to 125 = 5·5·5. Risk is independent of the severity '
  'label: the drivers are evidence about the concrete instance, while σ is a '
  'categorical judgement.')

sub_no('2.4&nbsp;&nbsp;Priority score')
P('Priority is a convex combination of four normalised quantities, each '
  'scaled to the range 0&ndash;100, so no single driver can dominate. The '
  'severity score contributes its full 25&ndash;100 scale; the exploitability '
  'driver is re-scaled 20·e so that e = 5 maps to 100.')
eqn('2.3', 'P = round ( 0.40·S(σ*) + 0.25·20e + 0.20·a + 0.15·c )')
P('The weights are (0.40, 0.25, 0.20, 0.15), summing to 1. Substituting the '
  'extreme values gives the full range:')
eqn('2.4', 'P<sub>min</sub> = round(0.40·25 + 0.25·20 + 0.20·0 + 0.15·0) = 15')
eqn('2.5', 'P<sub>max</sub> = round(0.40·100 + 0.25·100 + 0.20·100 + 0.15·100) = 100')
P('<font face="' + CODE_FONT + '" size="7.5">round(·)</font> is Python’s '
  'round, i.e. banker’s rounding to the nearest even integer. Findings are '
  'ranked and presented in descending P order throughout the API and the '
  'report.')

sub_no('2.5&nbsp;&nbsp;Scoring algorithm')
story.append(alg('Algorithm 1 — score_finding(f): compute (σ, R, P, c)', [
    'input   : f  a finding dict with optional severity and driver fields',
    'output  : σ  normalised severity label',
    '          R  risk score, P  priority score, c  confidence',
    '',
    '1   σ  ← normalize(f.severity)                 // §2.1; unknown → Low',
    '2   e  ← clamp(f.exploitability, lo=1, hi=5, default=3)',
    '3   i  ← clamp(f.impact,          lo=1, hi=5, default=3)',
    '4   x  ← clamp(f.exposure,        lo=1, hi=5, default=3)',
    '5   c  ← clamp(f.confidence_score, lo=0, hi=100, default=70)',
    '6   a  ← clamp(f.asset_criticality, lo=0, hi=100, default=70)',
    '7   R  ← e · i · x                               // §2.3',
    '8   P  ← round(0.40·S(σ) + 0.25·20e + 0.20·a + 0.15·c)   // §2.4',
    '9   return (σ, R, P, c)',
]))

sub_no('2.6&nbsp;&nbsp;Worked example')
P('A nuclei <i>critical</i> template match has the driver profile '
  '(e, i, x) = (4, 5, 4). Against an asset declared criticality a = 90 with the '
  'parser’s fixed confidence c = 80 for a template match:')
eqn('2.6', 'R = 4 · 5 · 4 = 80')
eqn('2.7', 'P = round(0.40·100 + 0.25·20·4 + 0.20·90 + 0.15·80) = round(92) = 92')

# =========================================================================
# 3  Deduplication and evidence merging
# =========================================================================
chapter_no(3, 'Deduplication &amp; Evidence Merging')

P('The same weakness is routinely reported by several tools, several scanners, '
  'or the model twice. Findings are merged into equivalence classes keyed by a '
  'content fingerprint; each class then emits exactly one scored finding. The '
  'fingerprint uses only fields that <i>identify the issue</i> — not the '
  'description or severity — so a Critical and a Low copy of the same '
  'vulnerability collide correctly.')

sub_no('3.1&nbsp;&nbsp;Fingerprint')
P('Each of the three identity fields is lower-cased and outer-whitespace '
  'trimmed; missing fields act as the empty string. The pieces are joined with '
  'the pipe separator and hashed.')
eqn('3.1', 'fp = SHA-256 ( trim↓(title) ∥ “|” ∥ trim↓(endpoint) ∥ “|” ∥ trim↓(parameter) )  [first 24 hex]')
P('24 hex digits = 96 bits of the digest is kept. Collision risk over ≤ 200 '
  'findings is negligible; the truncation also keeps the key short in the '
  'database and in logs.')

sub_no('3.2&nbsp;&nbsp;Merge operator')
P('When a new instance of a known fingerprint arrives, the strongest '
  'evidence is kept <i>field by field</i>, then the whole class is rescored by '
  'Algorithm 1 — so the persisted severity, risk and priority always agree '
  'with the confidence actually reported. Formally, for the existing record '
  '<i>f</i> and the incoming <i>g</i>:')
story.append(notes_table([
    ('severity', 'σ ← g.σ if ρ(g.σ) &gt; ρ(f.σ), else f.σ  (higher rank wins)'),
    ('drivers', 'for each driver δ ∈ {e, i, x, c, a}:  δ ← max(clamp(f.δ), clamp(g.δ))'),
    ('source_tools', 'f.tools ← sorted(f.tools ∪ g.tools)'),
    ('evidence', 'f.evidence ← f.evidence + “\\n” + g.evidence if g.evidence non-empty and not already present — then truncated to 20,000 chars'),
    ('text fields', 'description, remediation, endpoint, parameter: the longer of the two is kept'),
]))

sub_no('3.3&nbsp;&nbsp;Pseudocode')
story.append(alg('Algorithm 2 — combine(current, incoming) and the dedupe loop', [
    'combine(current, incoming):',
    '    if rank(incoming.σ) > rank(current.σ):      current.σ ← incoming.σ',
    '    for δ in (e, i, x, c, a):                    // element-wise strongest',
    '        current.δ ← max(clamp(current.δ), clamp(incoming.δ))',
    '    current.tools ← sorted(current.tools ∪ incoming.tools)',
    '    if incoming.evidence ≠ “” and incoming.evidence ∉ current.evidence:',
    '        current.evidence ← (current.evidence + “\\n” + incoming.evidence)',
    '                             truncated to L_text = 20 000 characters',
    '    for text in (description, remediation, endpoint, parameter):',
    '        if |incoming.text| > |current.text|:   current.text ← incoming.text',
    '    return current',
    '',
    'merge(raw findings):',
    '    classes ← { }                              // key fp → record',
    '    for item in raw:',
    '        n ← normalize(item)                     // clamp + cap field lengths',
    '        key ← fingerprint(n)                    // §3.1',
    '        classes[key] ← combine(classes[key], n) if key in classes else n',
    '    return [ score_finding(f) for f in classes.values() ]',
]))

# =========================================================================
# 4  Deterministic per-tool analyzers
# =========================================================================
chapter_no(4, 'Finding Extraction — Deterministic Per-tool Parsers')

P('With no AI provider, each scanner’s stdout/stderr is parsed by a dedicated '
  'recogniser so the no-provider report is still actionable. Scanner output is '
  'treated as <i>evidence, not instructions</i>: it is matched by grammar '
  'rules, and embedded directives are never followed. All parsers consume the '
  'ANSI-stripped stream.')

sub_no('4.1&nbsp;&nbsp;Common preprocessing')
P('Scanner output is colourised even when piped. Before parsing, the stream is '
  'stripped of all ANSI escape sequences via the rule')
eqn('4.1', 'strip(s) = s with every match of  \\x1b\\[[0-9;?]*[ -/]*[@-~]  removed')

sub_no('4.2&nbsp;&nbsp;nmap — live hosts and open services')
P('The output is walked line by line. A host-report header '
  '(<font face="' + CODE_FONT + '" size="7.5">Nmap scan report for HOST</font>, where HOST may be '
  '“name (ip)”) re-arms the current host — the IP inside the parentheses is '
  'preferred so the endpoint is an address an operator can act on. Service '
  'lines then match the grammar')
eqn('4.2', '&lt;port&gt;/&lt;proto&gt; &lt;state&gt; &lt;service&gt;?  [&lt;version&gt;]')
P('A trailing ‘?’ on the service name (nmap’s “tentative match”) is recorded '
  'and reported. Confidence is derived from how much of the banner nmap could '
  'identify:')
story.append(md_table(
    ['Evidence quality', 'Condition', 'Confidence c'],
    [['Version identified', 'version field non-empty', '95'],
     ['Service only, confident', 'version empty, no ‘?’', '70'],
     ['Tentative service match', 'service ends with ‘?’', '55']],
    widths=[56 * mm, 72 * mm, 46 * mm]))
P('Each exposed service yields one finding with endpoint '
  '<font face="' + CODE_FONT + '" size="7.5">host:port/proto</font> (or just '
  '<font face="' + CODE_FONT + '" size="7.5">port/proto</font> when no host header preceded it) and the '
  'fixed driver profile e = 2, i = 3 and x = 4 when the port is open, else '
  'x = 2. An http/https service is Low severity; anything else is Medium.')

sub_no('4.3&nbsp;&nbsp;nuclei — template matches and severity folding')
P('nuclei reports five levels but the framework scores four. Informational '
  'matches are reconnaissance evidence, not Medium risks, so they fold down '
  'rather than taking the default:')
story.append(md_table(
    ['Reported level', 'Folded severity σ', 'Drivers (e, i, x)', 'Confidence c'],
    [['critical', 'Critical', '(4, 5, 4)', '80'],
     ['high', 'High', '(4, 4, 4)', '80'],
     ['medium', 'Medium', '(3, 3, 4)', '80'],
     ['low', 'Low', '(2, 2, 4)', '80'],
     ['info', 'Low', '(1, 1, 3)', '80']],
    widths=[32 * mm, 36 * mm, 46 * mm, 60 * mm]))
P('A template match is signature evidence that the response is consistent with '
  'a documented issue — exposure is steady (the match is remotely reachable) '
  'and what varies with the level is damage and weaponisation.')

sub_no('4.4&nbsp;&nbsp;curl — security-header audit, banners, cookies')
P('Headers are collected only inside a response block, delimited by an HTTP '
  'status line (<font face="' + CODE_FONT + '" size="7.5">HTTP/1.1 200 OK</font>, '
  '<font face="' + CODE_FONT + '" size="7.5">HTTP/2 200</font>). Each redirect resets the block, so '
  'the audit describes the response the client finally lands on. If no status '
  'line is ever seen the connection failed and <i>no</i> header findings are '
  'invented.')

P('A finding is filed for every required header absent from the response set. '
  'The required set and profiles:')
story.append(md_table(
    ['Required header', 'Severity', '(e, i, x)', 'c', 'Rationale'],
    [['content-security-policy', 'Medium', '(3, 4, 4)', '90', 'primary XSS / injection defence'],
     ['strict-transport-security', 'Medium', '(3, 3, 3)', '90', 'prevents protocol downgrade'],
     ['x-frame-options', 'Low', '(2, 3, 4)', '90', 'anti-clickjacking'],
     ['x-content-type-options', 'Low', '(2, 3, 4)', '90', 'anti MIME-sniffing'],
     ['referrer-policy', 'Low', '(2, 2, 4)', '90', 'leak of tokens in Referer']],
    widths=[44 * mm, 20 * mm, 22 * mm, 14 * mm, 74 * mm]))
P('Technology disclosure is audited from the <font face="' + CODE_FONT + '" size="7.5">server</font> '
  'and <font face="' + CODE_FONT + '" size="7.5">x-powered-by</font> headers (Low, e = 2, i = 2, '
  'x = 5, c = 95). Finally each raw <font face="' + CODE_FONT + '" size="7.5">set-cookie</font> line '
  'is scanned; for each flag f ∈ {httponly, secure}, absence of f in the '
  'lower-cased value yields a Medium finding with profile (3, 4, 3) and '
  'c = 90.')

sub_no('4.5&nbsp;&nbsp;whatweb — technology fingerprints')
P('The plugin summary is matched for blocks of the form '
  '<font face="' + CODE_FONT + '" size="7.5">Name[value]</font>. Report furniture plugins '
  '(Country, IP, Title, HTML5, Script, Email, RedirectLocation) are ignored; '
  'every other disclosed technology is a Low finding with profile (2, 2, 5) '
  'and c = 85.')

sub_no('4.6&nbsp;&nbsp;sslscan — deprecated protocol detection')
P('For each deprecated protocol p ∈ {SSLv2, SSLv3, TLSv1.0, TLSv1.1}, the rule '
  '“p enabled” is searched case-insensitively. SSLv2/SSLv3 are High, '
  'TLSv1.0/TLSv1.1 Medium; profile (3, 4, 4), c = 95.')

sub_no('4.7&nbsp;&nbsp;Normalisation guards')
P('Every finding emitted by any parser or model passes one normaliser before '
  'scoring: title ≤ 500 chars, description/evidence/remediation each ≤ 20,000, '
  'endpoint/parameter ≤ 500, severity normalised (Eq. 2.1), drivers clamped to '
  'their ranges, <font face="' + CODE_FONT + '" size="7.5">source_tools</font> deduplicated into a '
  'sorted set. Crucially, an unusable asset criticality from the model falls '
  'back to <i>this target’s</i> criticality — not to the global default 70 — '
  'so a business-critical asset is never silently re-scored as average. The '
  'whole pipeline is bounded to ≤ 200 findings per assessment.')

# =========================================================================
# 5  Provider analysis and budgeting
# =========================================================================
chapter_no(5, 'Provider Analysis &amp; Token Budgeting')

P('When a provider is configured (API key, base URL and model name all '
  'present), raw output is sent for analysis; any failure — network, malformed '
  'JSON, non-list shape — falls back to the deterministic parsers of §4. The '
  'output given to the model is the same untrusted evidence, capped by a '
  'two-level budget so the prompt cannot grow without bound as plans grow.')

story.append(md_table(
    ['Bound', 'Symbol', 'Value'],
    [['per-stream output cap', 'C_stream', '120,000 characters'],
     ['whole-batch budget', 'C_total', '400,000 characters'],
     ['max findings accepted', 'M', '200'],
     ['max text per text field', 'L_text', '20,000 characters']],
    widths=[70 * mm, 40 * mm, 64 * mm]))

sub_no('5.1&nbsp;&nbsp;Budget allocation')
P('Outputs are consumed in order. For each output, stdout and then stderr are '
  'each truncated to min(C_stream, remaining-budget) characters and the used '
  'amount is subtracted — so one very chatty scanner can exhaust the shared '
  'budget but never exceeds its own stream cap and never starves later tools '
  'of the whole budget at once.')
story.append(alg('Algorithm 3 — budgeted prompt construction', [
    'budget ← C_total',
    'for each scanner output o in plan order:',
    '    avail ← max(budget, 0)',
    '    o.stdout ← first min(C_stream, avail) chars of o.stdout',
    '    budget ← budget − |o.stdout|',
    '    avail ← max(budget, 0)',
    '    o.stderr ← first min(C_stream, avail) chars of o.stderr',
    '    budget ← budget − |o.stderr|',
    'prompt ← instructions + JSON(truncated outputs)   // model told output',
    '                                          is evidence, not instructions',
]))
P('The response is parsed as a JSON list; anything else is treated as a '
  'provider failure and the deterministic path runs. Findings are then '
  'normalised and merged exactly as §3 describes.')

# =========================================================================
# 6  Planning
# =========================================================================
chapter_no(6, 'Assessment Planning (<i>backend/modules/planner.py</i>)')

sub_no('6.1&nbsp;&nbsp;Target classification and endpoint derivation')
P('A target string is classified to decide which tools may be aimed at it and '
  'what form each command’s target argument takes. A CIDR target is detected '
  'first: if the string contains “/” and parses as an IP network, it is a '
  'segment and receives the two-step subnet plan of §6.3. Otherwise the '
  'target is a host, optionally with a port:')
eqn('6.1', 'host = parsed.hostname;   port = parsed.port (if present)')
eqn('6.2', 'endpoint = host:port  if port,  else host')
P('Only some tools understand <font face="' + CODE_FONT + '" size="7.5">host:port</font>. '
  '<font face="' + CODE_FONT + '" size="7.5">nmap</font>, <font face="' + CODE_FONT + '" size="7.5">traceroute</font>, '
  '<font face="' + CODE_FONT + '" size="7.5">dig</font> and <font face="' + CODE_FONT + '" size="7.5">nslookup</font> take '
  'a bare host — <font face="' + CODE_FONT + '" size="7.5">nmap</font> learns the port through '
  '<font face="' + CODE_FONT + '" size="7.5">-p</font>, the DNS tools ignore it — while the web tools '
  'parse <font face="' + CODE_FONT + '" size="7.5">host:port</font> themselves. Web templates already '
  'carry the scheme, so the endpoint is never re-prefixed with '
  '<font face="' + CODE_FONT + '" size="7.5">http://</font>.')

sub_no('6.2&nbsp;&nbsp;Default host plan')
P('With no provider, a host target receives a fixed, policy-legal plan of '
  'seven steps: nmap version scan, traceroute, dig, curl header audit, whatweb '
  'fingerprint, sslscan TLS audit, and a rate-limited nuclei template pass. '
  'Target restrictions from the engagement letter remove restricted steps at '
  'plan time (§6.4).')

sub_no('6.3&nbsp;&nbsp;Subnet discovery and sweep sizing')
P('A CIDR target is swept in two steps: a live-host sweep '
  '(<font face="' + CODE_FONT + '" size="7.5">nmap -sn</font>) followed by a service sweep over '
  'k = 17 common ports on the live segment. The engineering estimate for the '
  'service sweep at the letter-mandated rate r = 30 packets/s is')
eqn('6.3', 't_sweep ≈ k · |N| / r', )
P('with |N| ≈ 254 for a /24. That is ≈ 17 × 254 / 30 ≈ 144 s — comfortably '
  'inside the τ = 360 s execution cap. A /16 (|N| = 65,534) would need '
  '≈ 37,000 s, which is why sweep size is separately bounded at the model '
  'layer to |N| ≤ 256 addresses (§11) — a hard ceiling chosen so a sweep '
  'always completes within τ.')

sub_no('6.4&nbsp;&nbsp;Plan sources and policy filtering')
P('Four plan sources exist; the choice is surfaced to the UI because a policy '
  'rejection and a provider outage need different follow-up.')
story.append(md_table(
    ['Source', 'When returned', 'Note'],
    [['ai-filtered', 'model plan survived policy review', 'every surviving step carries capability + risk'],
     ['default-unconfigured', 'provider key / URL / model missing', 'safe default plan used'],
     ['default-provider-error', 'provider call or response failed', 'same safe default'],
     ['default-policy-rejected', 'every model step failed policy review', 'default plan is used']],
    widths=[52 * mm, 70 * mm, 52 * mm]))
P('Each model step must name a non-empty tool and command and — critically — '
  'must survive <font face="' + CODE_FONT + '" size="7.5">policy_engine.validate_command</font> '
  '(§7) against the same scopes the execute endpoint will use, with the model’s '
  'declared tool matching the command’s executable. Steps are accepted up to '
  'MAX_PLAN_STEPS = 50. After filtering, client-letter restrictions drop any '
  'remaining step whose tool is restricted for the target.')
story.append(alg('Algorithm 4 — default_plan(target)', [
    'if target contains “/” and parses as IP network N:',
    '    return subnet plan:                         // §6.3',
    '        nmap -sn --max-rate 30 N',
    '        nmap -sV --version-light --open --max-rate 30',
    '             -p 22,25,53,80,110,143,443,445,3000,3306,3389,5432,',
    '             5900,6379,8000,8080,8443 N',
    '(host, port) ← urlparse(target)                 // §6.1',
    'endpoint ← host:port if port else host',
    'for step in DEFAULT_PLAN (7 fixed steps):',
    '    target_arg ← host if step.tool ∈ {nmap, traceroute, dig, nslookup}',
    '                          else endpoint',
    '    ports      ← “-p “ + port + “ ” if port and step.tool == nmap',
    '    step.command ← step.command.format(target=target_arg, ports=ports)',
    'return steps',
]))

# =========================================================================
# 7  Policy engine
# =========================================================================
chapter_no(7, 'Policy Engine &amp; Scope Validation (<i>policy_engine.py</i>)')

sub_no('7.1&nbsp;&nbsp;Design: allowlist over blocklist')
P('Commands run through <font face="' + CODE_FONT + '" size="7.5">create_subprocess_exec</font>, '
  'never a shell, so shell metacharacters carry no injection risk; only '
  'genuine control characters are refused (newline, CR, tab, NUL, VT, FF). '
  'Policy is an <i>allowlist</i>: every flag a tool may receive is enumerated '
  'per tool, and anything not enumerated fails closed — a file-write or '
  'destination-override flag nobody thought to list cannot slip through the '
  'gaps in a blocklist. Semantics are per tool: <font face="' + CODE_FONT + '" size="7.5">nmap -A</font> '
  'takes no value while <font face="' + CODE_FONT + '" size="7.5">curl -A</font> does.')

sub_no('7.2&nbsp;&nbsp;Argument grammar')
P('The tool registry groups eight tools into three capabilities. Each tool '
  'spec defines flag classes and how to treat positionals:')
story.append(md_table(
    ['Flag class', 'Meaning', 'Example'],
    [['bool_flags', 'self-contained switch, no value', 'nmap -sV, curl -I'],
     ['value_flags', 'takes a value that is not a target', '--max-rate 30'],
     ['target_flags', 'takes a value that IS a target (scope-checked)', 'dig -q host, nuclei -u url'],
     ['resolver_flags / prefix', 'value is a DNS resolver', "dig @8.8.8.8"],
     ['attached_patterns', 'self-contained flag regexes (-T4, +short, -p80)', 'nmap -T4'],
     ['bundled_short_flags', 'POSIX bundle allowed; final char may take value', 'curl -sSL'],
     ['resolver_positionals', 'positionals after this index are resolvers', 'nslookup name server']],
    widths=[40 * mm, 88 * mm, 46 * mm]))
P('Arguments are scanned left to right as a small state machine. When a value- '
  'or target-flag is seen, the <i>next</i> token is consumed as its argument. '
  'Tokens that are not flags are positionals. A flag that belongs to no class, '
  'matches no attached pattern and does not expand as a bundle is rejected — '
  'and any rejection invalidates the whole command.')
story.append(alg('Algorithm 5 — scan_arguments(tokens, spec)', [
    'targets ← []; resolvers ← []; positionals ← []; pending ← none',
    'for token in tokens after the executable:',
    '    if pending:',
    '        file token under targets or resolvers per pending kind; pending ← none',
    '        continue',
    '    if token starts with resolver prefix “@”:  resolvers ← token[1:]; continue',
    '    if token is not a flag:                    positionals ← token; continue',
    '    classify token:',
    '        bool flag               → nothing to do',
    '        value / target / resolver flag → pending ← class (next token consumed)',
    '        base=value forms:       accepted when base is a known flag (--x=v)',
    '        attached pattern match  → accepted (self-contained)',
    '        POSIX bundle expansion  → accepted iff every char is bool, last may be value',
    '        otherwise               → REJECT (fail closed, report the token)',
    'if pending is still set:  REJECT (a required value was missing)',
    'cutoff ← spec.resolver_positionals            // e.g. nslookup = 1',
    'targets += positionals[:cutoff];  resolvers += positionals[cutoff:]',
    'return (targets, resolvers)',
]))

sub_no('7.3&nbsp;&nbsp;Host normalisation')
P('Targets and scopes are compared in a canonical form: brackets stripped '
  'from an IPv6 literal (so “::1” is recognised before urlparse misreads the '
  'colons as a port), DNS names lower-cased and trailing-dot stripped, and IPs '
  'rewritten to their canonical text so <font face="' + CODE_FONT + '" size="7.5">0:0:0:0:0:0:0:1</font> '
  'and <font face="' + CODE_FONT + '" size="7.5">::1</font> compare equal.')

sub_no('7.4&nbsp;&nbsp;Scope membership')
P('A requested CIDR must fit <i>inside</i> an authorised network — checking '
  'only the base address would let a /24 sweep pass against a /25 '
  'authorisation. For a network target Q and authorised networks A<sub>i</sub>:')
eqn('7.1', 'Q valid ⇔ ∃ A<sub>i</sub> : version(Q) = version(A<sub>i</sub>)  and  Q ⊆ A<sub>i</sub> (Q is a subnet of A<sub>i</sub>)')
P('For a host target h:')
eqn('7.2', 'h valid ⇔ ( h is an IP and ∃ A<sub>i</sub> : h ∈ A<sub>i</sub> )  or  h = scope  or  h is a subdomain of scope  (h ends with “.” + scope)')
P('DNS names are matched by exact equality or subdomain suffix, so '
  '<font face="' + CODE_FONT + '" size="7.5">api.juice-shop</font> is inside the scope '
  '<font face="' + CODE_FONT + '" size="7.5">juice-shop</font> but a sibling host is not.')

sub_no('7.5&nbsp;&nbsp;Resolver policy')
P('A DNS query aimed at a resolver is not an assessment action against that '
  'resolver, so resolvers are validated separately: they must be either '
  'in-scope hosts or members of a fixed well-known set of public resolvers '
  '(8.8.8.8, 1.1.1.1, 9.9.9.9, …). This stops the resolver argument doubling '
  'as an arbitrary outbound destination.')

sub_no('7.6&nbsp;&nbsp;Decision procedure')
story.append(alg('Algorithm 6 — validate_command(command, scopes, expected_tool)', [
    '1  if command empty → refuse',
    '2  if any control character in command → refuse',
    '3  tokens ← shlex.split(command)              // shell-free; syntax error → refuse',
    '4  if tokens[0] not in tool registry → refuse  // executable not enabled',
    '5  if expected_tool and tokens[0] ≠ expected_tool → refuse',
    '6  (targets, resolvers) ← scan_arguments(tokens, spec)   // Alg. 5',
    '7  if scan rejected a token → refuse',
    '8  if targets is empty → refuse                 // explicit target required',
    '9  if any target not valid under Eq. 7.1 / 7.2 → refuse',
    '10 if any resolver neither public nor in scope → refuse',
    '11 allow:  record capability and risk for the audit trail',
]))

# =========================================================================
# 8  Engagement letter parsing
# =========================================================================
chapter_no(8, 'Engagement Letter Parsing (<i>engagement_parser.py</i>)')

sub_no('8.1&nbsp;&nbsp;Pipeline')
P('A client letter (PDF / DOCX / Markdown / text, already extracted to plain '
  'text) is converted to structured facts the planner, policy engine and '
  'report can act on — deterministically, with no AI provider required. The '
  'pipeline is:')
eqn('8.1', 'text → clean lines → targets (+ restrictions) + document fields + objectives + out-of-scope + prohibited')

sub_no('8.2&nbsp;&nbsp;Cleaning and furniture removal')
P('Lines that are blank, or that match repeated reportlab page furniture '
  '(“— Confidential”, “Engagement ABC/123”, “Page 4”, “Request for Security '
  'Assessment Services — Confidential”) are dropped before anything is parsed, '
  'so footers spliced between PDF pages never become content.')

sub_no('8.3&nbsp;&nbsp;Target-table extraction and the fallback scan')
P('Label/value rows are matched case-insensitively by whole-line prefix. The '
  'known labels map “System name”, “Authorized target address”, “Authorized '
  'scope identifiers”, “Asset criticality”, “Assessment type”, “Technology” '
  'and “Environment”. A criticality value is the leading integer on its line. '
  'An address is recovered by the CIDR grammar first (so a subnet row is not '
  'mangled into its base address), then host:port, else the raw value:')
eqn('8.2', 'NETWORK:  (\\d{1,3}\\.){3}\\d{1,3}/\\d{1,2}      HOST:PORT:  host:[1-9]\\d{0,4}')
P('Because two-column PDF tables extract inconsistently, a fallback pass then '
  'scans every line not inside the out-of-scope section for host:port or '
  'subnet addresses and promotes any not already captured to a target. The '
  'out-of-scope exclusion matters: “out of scope: the corporate network '
  '10.10.0.0/16” must not register the corporate network for scanning.')

sub_no('8.4&nbsp;&nbsp;Restriction extraction — set algebra')
P('Restrictions bind tools to targets that the section names (host or '
  'meaningful name words appear as whole words). Two sentence shapes carry a '
  'restriction. Let T be the framework’s eight known tools and N ⊆ T the '
  'tools named in the sentence; let R(t) be the restricted set for target t. '
  'For every target t mentioned in a section:')
story.append(notes_table([
    ('allow-list', '“…only service discovery (nmap …) and header inspection (curl, whatweb) are authorized against it” →  R(t) ← R(t) ∪ (T ∖ N)   (everything not named becomes restricted)'),
    ('deny-list', '“…nuclei … must not be run against the DVWA lab” →  R(t) ← R(t) ∪ N'),
]))
P('Restrictions name only tools the framework can actually run (a restriction '
  'naming anything else is already refused by the policy engine).')

sub_no('8.5&nbsp;&nbsp;Objectives and ruled-out lists')
P('Objectives are numbered sub-items (<font face="' + CODE_FONT + '" size="7.5">4.1 Service '
  'discovery: …</font>); the colon in the second group filters out section '
  'headings that number but never title-and-describe. Wrapped continuation '
  'lines are merged back into their item unless the prior text already ends a '
  'sentence. Out-of-scope and prohibited-technique lists start at their '
  'heading and run to the next numbered heading; items begin only on a bullet '
  'glyph line (several extraction spellings of the bullet are accepted), and a '
  'non-bullet line only continues the previous item — keeping the section’s '
  'own intro sentence out of the list.')

# =========================================================================
# 9  Execution and lifecycle
# =========================================================================
chapter_no(9, 'Command Execution &amp; Assessment Lifecycle (<i>executor.py</i>, <i>main.py</i>)')

sub_no('9.1&nbsp;&nbsp;Streaming, caps and truncation')
P('stdout and stderr are drained concurrently in 64 KiB chunks. Retained '
  'bytes are capped, then the decoded text is capped again:')
story.append(md_table(
    ['Quantity', 'Symbol', 'Value'],
    [['byte cap while draining', 'B_exec', '800,000 bytes (= 4 × 200,000 chars)'],
     ['char cap after decode', 'C_exec', '200,000 characters'],
     ['read chunk', '—', '65,536 bytes'],
     ['truncation marker', '—', '“[stdout truncated]” / “[stderr truncated]”']],
    widths=[70 * mm, 36 * mm, 68 * mm]))
P('If the decoded text exceeds C_exec it is cut at C_exec and the marker is '
  'appended, so downstream consumers (analyser, report) can tell truncated '
  'output apart from complete output.')
story.append(alg('Algorithm 7 — drain and truncate', [
    'retained ← 0; chunks ← [ ]',
    'while pipe open:',
    '    chunk ← read 65 536 bytes',
    '    if retained < B_exec:                       // stop accumulating in time',
    '        chunks += chunk limited to (B_exec − retained); retained += |chunk|',
    '    append decoded chunk to live buffer (§9.2) if this is a live run',
    'text ← decode(concat(chunks))',
    'if |text| > C_exec:   text ← text[:C_exec] + “\\n[label truncated]”',
    'return text',
]))

sub_no('9.2&nbsp;&nbsp;Live terminal registry')
P('An execution is registered before its command starts. While it runs, every '
  'decoded chunk is appended to an in-memory tail window that keeps only the '
  'last C_live = 200,000 characters — enough for the UI terminal to stream '
  'from the first chunk, capped so a chatty scanner cannot balloon memory. The '
  'entry is removed however the command ends (success, timeout, disconnect), '
  'and the database row remains the authoritative audit record.')

sub_no('9.3&nbsp;&nbsp;Timeout and process-group kill')
P('Each command runs under a τ = 360 s deadline. On timeout the whole process '
  '<i>group</i> is killed with SIGKILL on POSIX — nmap and nuclei spawn '
  'children — and a timeout notice is prepended to stderr so partial output is '
  'labelled partial. The finally block guarantees the group is killed even if '
  'the request coroutine is cancelled (a client disconnect), so no scanner '
  'keeps hammering the target after nobody is left to read its output.')

sub_no('9.4&nbsp;&nbsp;Retry, staleness and uniqueness')
P('An execution row is written before its command starts, so '
  '<font face="' + CODE_FONT + '" size="7.5">return_code = NULL</font> after the command could '
  'not possibly still be running is the residue of a crash or disconnect and '
  'may be reclaimed. A row is <i>stale</i> when')
eqn('9.1', 'stale(exec) ⇔ exec.rc = NULL  and  (exec.started is NULL  or  now − started &gt; τ + 60 s)')
P('(τ + 60 = 420 s). A step is retryable exactly when its last attempt ended '
  'badly — rc ≠ 0, or rc still NULL but stale:')
eqn('9.2', 'retryable(exec) ⇔ exec.rc ≠ 0  and  (exec.rc is not NULL  or  stale(exec))')
P('The pair (assessment, step_index) is unique, which guards concurrent '
  're-approvals: a step that already succeeded cannot run twice, and a failed '
  'or abandoned step is re-run by reusing its row with attempt incremented. '
  'Re-running a step (or editing the plan) invalidates any analysis and '
  'rendered report derived from the old output.')

sub_no('9.5&nbsp;&nbsp;Assessment status automaton')
P('Status is a small deterministic automaton over the enabled steps A and the '
  'executed steps D:')
story.append(md_table(
    ['Status', 'Entered when'],
    [['awaiting_approval', 'assessment created; after any step finishes while D ⊊ A'],
     ['running', 'an approved step is executing (start of execute_step)'],
     ['ready_for_analysis', 'A non-empty and every enabled step has run:  D ⊇ A'],
     ['analyzed', 'analysis completed over all enabled steps'],
     ['reported', 'HTML report generated from the analyzed findings']],
    widths=[48 * mm, 126 * mm]))
P('Analysis itself is gated on the same set relation: the endpoint refuses '
  'unless D ⊇ A (every enabled step executed). This is exactly the rule that '
  'prevents a partial run from being presented as a complete assessment. '
  'Findings are ordered and displayed by priority score P descending '
  '(Eq. 2.3), with risk and confidence persisted alongside so the report can '
  'explain <i>why</i> each finding scored as it did.')

# =========================================================================
# 10  Secrets and proxy composition
# =========================================================================
chapter_no(10, 'Credential Encryption &amp; Proxy Composition (<i>secret_store.py</i>)')

P('Provider keys and proxy passwords are stored in an ordinary SQLite file '
  'that gets copied into backups and containers; the two secret columns are '
  'therefore encrypted at rest with Fernet (AES-128-CBC + HMAC-SHA256), a '
  'sign-then-encrypt authenticated envelope.')

sub_no('10.1&nbsp;&nbsp;Fernet envelope')
P('A Fernet master key K is 32 random bytes, split into a 16-byte signing key '
  'and a 16-byte AES-128-CBC key. Each ciphertext token is')
eqn('10.1', 'token = base64url( 0x80 ∥ t<sub>0</sub>(8B) ∥ IV(16B) ∥ AES-CBC(m)(pad) ∥ HMAC-SHA256(sig-key, header ∥ IV ∥ ct) )')
P('Stored values carry the marker <font face="' + CODE_FONT + '" size="7.5">enc:v1:</font> so a '
  'credential written before encryption existed is recognised as plaintext '
  'instead of being fed to Fernet (which would reject it and silently discard '
  'a key the user had already configured). Decryption failure degrades to '
  '“not configured” (empty string) rather than raising, so a rotated or lost '
  'key lets the user re-enter the credential instead of failing every settings '
  'read.')

sub_no('10.2&nbsp;&nbsp;Key hierarchy')
eqn('10.2', 'K = env REDTEAM_SECRET_KEY    if set,  else  key file data/.secret_key,  else freshly generated Fernet key (chmod 0600)')
P('Supplying K through the environment keeps it off the same volume as the '
  'database; the file fallback still defends against the database being copied '
  'on its own.')

sub_no('10.3&nbsp;&nbsp;Proxy environment composition')
P('When a proxy is configured, credentials are URL-encoded and spliced into '
  'the URL before the standard proxy variables are set for the child '
  'environment:')
eqn('10.3', 'proxy_url\' = scheme :// quote(username) : quote(password) @ rest   (when username and password are both present)')
P('Only the keys a scanner needs are inherited from the parent environment '
  '(PATH, HOME, temp/system locations, …) — a subprocess never receives '
  'GEMINI_API_KEY or DATABASE_URL.')

# =========================================================================
# 11  Constants and bounds
# =========================================================================
chapter_no(11, 'Tunable Constants &amp; Bounds — Summary')

P('All bounds are stated as constants in the modules, most overridable by '
  'environment variables. They exist so an unbounded or hostile input can '
  'never grow the database, the prompt or a subprocess without limit.')

story.append(md_table(
    ['Constant', 'Value', 'Module', 'Guards'],
    [['DEFAULT_ASSET_CRITICALITY', '70', 'analyzer.py', 'default a when a target declares none'],
     ['MAX_ANALYSIS_OUTPUT_CHARS', '120,000', 'analyzer.py', 'per-stream output into the prompt'],
     ['MAX_ANALYSIS_TOTAL_CHARS', '400,000', 'analyzer.py', 'whole-batch prompt budget'],
     ['MAX_FINDINGS', '200', 'analyzer.py', 'findings accepted per assessment'],
     ['MAX_FINDING_TEXT_CHARS', '20,000', 'analyzer.py', 'evidence / description length'],
     ['MAX_PLAN_STEPS', '50', 'planner.py', 'steps in one plan'],
     ['EXECUTION_TIMEOUT_SECONDS', '360', 'executor.py', 'τ: subprocess deadline'],
     ['MAX_OUTPUT_CHARS', '200,000', 'executor.py', 'C_exec after decode'],
     ['MAX_OUTPUT_BYTES', '800,000', 'executor.py', 'B_exec retained while draining'],
     ['LIVE_BUFFER_CHARS', '200,000', 'executor.py', 'in-memory live tail window'],
     ['MAX_REQUIREMENT_BYTES', '5 MiB', 'main.py', 'uploaded requirement files'],
     ['MAX_PLAN_FIELD_CHARS', '100 / 4000 / 2000', 'main.py', 'tool / command / reason lengths'],
     ['MAX_SUBNET_ADDRESSES', '256', 'models.py', '|N| for a CIDR target (env)'],
     ['MAX_AUTHORIZED_SCOPES', '50', 'models.py', 'scopes per target'],
     ['MAX_RESTRICTED_TOOLS', '20', 'models.py', 'restricted tools per target'],
     ['MAX_BRIEF_ITEMS / MAX_BRIEF_CHARS', '100 / 20,000', 'models.py', 'engagement-brief bound']],
    widths=[52 * mm, 34 * mm, 26 * mm, 62 * mm]))

story.append(Spacer(1, 6))
story.append(note_para('Rounding: every round() call is Python’s banker’s '
                       'rounding (half rounds to the nearest even integer). '
                       'All four severity labels, three reachability drivers, '
                       'confidence and criticality are persisted next to every '
                       'finding so every score in this document can be '
                       're-derived by a reader from the raw evidence alone.'))

# ------------------------------------------------------------------- build
class RefDoc(BaseDocTemplate):
    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and flowable.style.name in ('H1x', 'H2x'):
            style_name = flowable.style.name
            level = 0 if style_name == 'H1x' else 1
            text = flowable.getPlainText()
            key = f'{style_name}-{text}'
            self.canv.bookmarkPage(key)
            self.notify('TOCEntry', (level, text, self.page, key))


def on_page(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(brand_navy)
    canvas.setLineWidth(1.5)
    canvas.line(18 * mm, 285 * mm, 192 * mm, 285 * mm)
    canvas.setFont(BODY_FONT, 7.5)
    canvas.setFillColor(colors.HexColor('#666666'))
    canvas.drawString(18 * mm, 287.5 * mm,
                      'Red Teaming Framework — Backend Algorithms & Formulae Reference')
    canvas.drawRightString(192 * mm, 287.5 * mm, 'Confidential')
    canvas.setStrokeColor(rule_grey)
    canvas.setLineWidth(0.75)
    canvas.line(18 * mm, 14 * mm, 192 * mm, 14 * mm)
    canvas.setFont(BODY_FONT, 7.5)
    canvas.drawString(18 * mm, 10.5 * mm,
                      'Semi-Autonomous Red Teaming Framework — algorithms & formulae')
    canvas.drawRightString(192 * mm, 10.5 * mm, f'Page {doc.page}')
    canvas.restoreState()


def build():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    doc = RefDoc(str(OUT), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                 topMargin=16 * mm, bottomMargin=18 * mm,
                 title='Red Teaming Framework — Backend Algorithms & Formulae Reference',
                 author='EPCET Security Research Laboratory',
                 subject='Algorithms, formulae and bounds of the red teaming assessment backend')
    frame = Frame(18 * mm, 18 * mm, TEXT_W, 264 * mm, id='main')
    doc.addPageTemplates([PageTemplate(id='page', frames=[frame], onPage=on_page)])
    doc.multiBuild(story)
    print('Wrote', OUT)


if __name__ == '__main__':
    build()
