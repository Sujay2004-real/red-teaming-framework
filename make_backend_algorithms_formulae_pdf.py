# -*- coding: utf-8 -*-
"""Compile docs/backend_algorithms_formulae_reference.pdf — the mathematical
and algorithmic reference for the Red Teaming Framework backend.

Every formula, mapping, bound and pseudocode block below is transcribed from the
live backend source:

    backend/modules/analyzer.py
    backend/modules/planner.py
    backend/modules/policy_engine.py
    backend/modules/engagement_parser.py
    backend/modules/executor.py
    backend/modules/secret_store.py
    backend/modules/reporter.py
    backend/main.py
    backend/models.py
    backend/database.py

Typesetting notes
-----------------
Mathematical notation is composed directly in reportlab rich text using the
embedded DejaVu family: identifiers are set in the oblique face, operators and
numbers upright, sub/superscripts via <sub>/<super>, and the needed set of
Unicode operators (· − ≤ ≥ ∈ ⊆ ⊂ ∩ ∪ → ⇒ ⌊ ⌋ …) is carried by DejaVu Sans.  This
keeps every equation as *selectable text* (no rasterisation) and requires only
reportlab — no LaTeX, no matplotlib.

Pseudocode is set in a dark monospace panel mirroring make_backend_reference_pdf.py.
Brand colours / header / footer rules follow the existing documentation set.

Run from the project root with the interpreter that carries reportlab
(backend/venv has it):  backend\\venv\\Scripts\\python.exe make_backend_algorithms_formulae_pdf.py

Fonts are read from build/fonts (DejaVu Sans family); when absent the script
falls back to Helvetica / Courier and the maths still renders, less cleanly.
"""
import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether, PageBreak,
                                PageTemplate, Paragraph, Spacer, Table, TableStyle)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'docs' / 'backend_algorithms_formulae_reference.pdf'
FONT_DIR = ROOT / 'build' / 'fonts'

TEXT_W = 174 * mm

# --------------------------------------------------------------------- fonts
FONT_FILES = ('DejaVuSans.ttf', 'DejaVuSans-Bold.ttf', 'DejaVuSans-Oblique.ttf',
              'DejaVuSansMono.ttf', 'DejaVuSansMono-Bold.ttf')
_FONT_CANDIDATES = []
for base in (Path(__file__).resolve().parent, Path.home()):
    for p in (base / 'build' / 'fonts',
              base / 'Lib' / 'site-packages' / 'matplotlib' / 'mpl-data' / 'fonts' / 'ttf'):
        if p.is_dir():
            _FONT_CANDIDATES.append(p)


def _prepare_fonts():
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
warn_bg = colors.HexColor('#FDF3E3')
warn_border = colors.HexColor('#E8B24A')
ok_bg = colors.HexColor('#EAF4EA')
ok_border = colors.HexColor('#5DA25D')
ink = colors.HexColor('#222222')

base = getSampleStyleSheet()

h1 = ParagraphStyle('H1x', fontName=BODY_FONT + '-Bold', fontSize=15, leading=19,
                    textColor=brand_navy, spaceBefore=4, spaceAfter=6)
h2 = ParagraphStyle('H2x', fontName=BODY_FONT + '-Bold', fontSize=11.5, leading=15,
                    textColor=brand_blue, spaceBefore=11, spaceAfter=4)
h3 = ParagraphStyle('H3x', fontName=BODY_FONT + '-Bold', fontSize=9.8, leading=13,
                    textColor=brand_navy, spaceBefore=8, spaceAfter=3)
body = ParagraphStyle('Bodyx', fontName=BODY_FONT, fontSize=8.8, leading=12.4,
                      textColor=ink, alignment=TA_JUSTIFY, spaceAfter=5)
bullet = ParagraphStyle('Bulletx', parent=body, leftIndent=12, bulletIndent=3,
                        spaceAfter=2.4)
eq = ParagraphStyle('Eqx', fontName=BODY_FONT, fontSize=9.6, leading=13.5,
                    textColor=brand_navy, alignment=TA_CENTER, spaceAfter=0)
eqnum = ParagraphStyle('EqNumx', fontName=BODY_FONT + '-Bold', fontSize=8.6,
                       leading=13.5, textColor=brand_navy, alignment=2, spaceAfter=0)
code = ParagraphStyle('Codex', fontName=CODE_FONT, fontSize=7.0, leading=9.2,
                      textColor=colors.HexColor('#E6E8EE'), spaceAfter=0)
codeh = ParagraphStyle('CodeHx', fontName=CODE_FONT + '-Bold', fontSize=7.2,
                       leading=9.6, textColor=colors.HexColor('#F2C94C'),
                       spaceAfter=0)
cell = ParagraphStyle('Cellx', parent=body, fontSize=7.6, leading=10.2,
                      alignment=TA_LEFT, spaceAfter=0)
cellh = ParagraphStyle('CellHx', parent=cell, fontName=BODY_FONT + '-Bold',
                       textColor=colors.white)
note = ParagraphStyle('Notex', fontName=BODY_FONT, fontSize=7.8, leading=10.8,
                      textColor=colors.HexColor('#333333'), alignment=TA_JUSTIFY,
                      spaceAfter=0)
label = ParagraphStyle('Labx', fontName=BODY_FONT + '-Bold', fontSize=7.8,
                       leading=10.6, textColor=brand_navy, spaceAfter=0)

story = []


# ------------------------------------------------------------- small helpers
def c(text):
    """Inline monospace (a code / constant span)."""
    return f'<font face="{CODE_FONT}" size="7">{esc(text)}</font>'


def esc(text):
    return (text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'))


def it(text):
    """Oblique identifier span (math variable)."""
    return f'<i>{text}</i>'


def P(text, style=None):
    return Paragraph(text, style or body)


def B(text):
    return Paragraph('<bullet>&bull;</bullet> ' + text, bullet)


def lead(text):
    """An unnumbered intro paragraph with a light left rule."""
    box = Table([[Paragraph(text, body)]], colWidths=[TEXT_W])
    box.setStyle(TableStyle([
        ('LINEBEFORE', (0, 0), (-1, -1), 2, brand_blue),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    return box


def code_panel(header, lines):
    """Dark panel: amber caption line then monospaced body."""
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
        ('TOPPADDING', (0, 0), (-1, 0), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 1), (-1, -1), 3),
    ]))
    return panel


def alg(header, lines):
    return KeepTogether([code_panel(header, lines), Spacer(1, 6)])


def eqn(label, formula):
    """Numbered display equation centred across the text column."""
    eq_par = Paragraph(formula, eq)
    num_par = Paragraph(f'({label})', eqnum)
    t = Table([['', eq_par, num_par]], colWidths=[23 * mm, 128 * mm, 23 * mm],
              hAlign='CENTER')
    t.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    return KeepTogether([t, Spacer(1, 2)])


def md_table(headers, rows, widths=None):
    """Table with a brand-navy header row and zebra body rows."""
    widths = widths or [TEXT_W / len(headers)] * len(headers)
    data = [[Paragraph(esc(h), cellh) for h in headers]]
    for row in rows:
        out = []
        for v in row:
            if isinstance(v, str) and v.startswith('<'):
                out.append(Paragraph(v, cell))
            else:
                out.append(Paragraph(esc(str(v)), cell))
        data.append(out)
    t = Table(data, colWidths=widths, hAlign='LEFT', repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), brand_navy),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F2F6FB')]),
        ('GRID', (0, 0), (-1, -1), 0.5, rule_grey),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 4.5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4.5),
        ('TOPPADDING', (0, 0), (-1, -1), 2.2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.2),
    ]))
    return t


def notes_table(rows, col_w=46 * mm):
    """Symbol glossary: mono/italic key column, definition column."""
    data = [[Paragraph(rows[i][0], label), Paragraph(rows[i][1], note)]
            for i in range(len(rows))]
    t = Table(data, colWidths=[col_w, TEXT_W - col_w], hAlign='LEFT')
    t.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 2),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 0.8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0.8),
    ]))
    return t


def note_para(text, bg=None, border=None):
    box = Table([[Paragraph(text, note)]], colWidths=[TEXT_W])
    style = [
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 3.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
    ]
    if bg:
        style.append(('BACKGROUND', (0, 0), (-1, -1), bg))
    if border:
        style.append(('BOX', (0, 0), (-1, -1), 0.5, border))
    box.setStyle(TableStyle(style))
    return box


def chapter_no(num, title):
    story.append(Paragraph(f'{num}&nbsp;&nbsp;{title}', h1))


def sub_no(title):
    story.append(Paragraph(title, h2))


def sub3(title):
    story.append(Paragraph(title, h3))


def space(h=4):
    story.append(Spacer(1, h))


# =========================================================================
# COVER
# =========================================================================
space(2)
cover = Table([[Paragraph('SEMI-AUTONOMOUS RED TEAMING FRAMEWORK',
                          ParagraphStyle('CoverTag', parent=base['Normal'], fontName=BODY_FONT,
                                         fontSize=10, leading=13, textColor=brand_blue,
                                         alignment=TA_CENTER)),
                ]], colWidths=[TEXT_W])
cover.setStyle(TableStyle([('BOTTOMPADDING', (0, 0), (-1, -1), 4)]))
story.append(cover)
story.append(Paragraph('Backend Algorithms &amp; Formulae Reference',
                       ParagraphStyle('CoverTitle', parent=base['Normal'], fontName=BODY_FONT + '-Bold',
                                      fontSize=21, leading=25, textColor=brand_navy,
                                      alignment=TA_CENTER, spaceAfter=4)))
story.append(Paragraph('The scoring, planning, policy, parsing, execution, lifecycle and '
                       'cryptography mathematics of the assessment engine — stated precisely',
                       ParagraphStyle('CoverSub', parent=base['Normal'], fontName=BODY_FONT,
                                      fontSize=10.2, leading=14, textColor=colors.HexColor('#555555'),
                                      alignment=TA_CENTER, spaceAfter=6)))
story.append(Spacer(1, 4))

# ------------------------------------------------------------------- TOC
toc = TableOfContents()
toc.levelStyles = [
    ParagraphStyle('TOC1', parent=base['Normal'], fontName=BODY_FONT, fontSize=9.2,
                   leading=14.4, textColor=ink, leftIndent=0, firstLineIndent=0,
                   spaceBefore=1),
    ParagraphStyle('TOC2', parent=base['Normal'], fontName=BODY_FONT, fontSize=8.2,
                   leading=12, textColor=colors.HexColor('#444444'), leftIndent=12,
                   firstLineIndent=0),
]
story.append(Paragraph('Contents', h2))
story.append(toc)
story.append(PageBreak())

# =========================================================================
# CHAPTER 1 — Scope, notation & conventions
# =========================================================================
chapter_no(1, 'Scope, Notation &amp; Conventions')

sub_no('1.1&nbsp;&nbsp;Scope and reading guide')
story.append(P('This reference is the mathematical companion to '
               + c('docs/backend_technical_reference.md') + ', which explains the same '
               'components in plain language. Each chapter transcribes one part of the '
               'backend: the formula or algorithm as implemented, the bounds the code '
               'enforces, and short pseudocode where the logic is procedural rather than '
               'arithmetical. All identifiers that appear below are defined in the symbol '
               'glossary (&#167;1.3) the first time the reader needs them.'))
story.append(P('Notation is deliberately faithful to the source: a formula such as '
               '<i>P</i>&nbsp;=&nbsp;round(0.40·<i>S</i>(σ)&nbsp;+&nbsp;5·<i>e</i>&nbsp;+&nbsp;'
               '0.20·κ&nbsp;+&nbsp;0.15·γ) is exactly the expression evaluated in '
               + c('analyzer.score_finding') + ', with the same coefficients. Greek lower-case '
               'letters are reserved for unitless drivers and scores; upright symbols mark '
               'constants.'))
sub_no('1.2&nbsp;&nbsp;Bounding convention')
story.append(P('Every driver read from (or produced by) an external component is passed '
               'through the same bounded cast before it is used in arithmetic. Given a value '
               '<i>v</i>, a lower bound <i>L</i>, an upper bound <i>U</i> and a default <i>d</i>, '
               'the function maps'))
eqn('1.1', '<i>bounded_int</i>(<i>v</i>, <i>d</i>, <i>L</i>, <i>U</i>)&nbsp;='
            '&nbsp;{ <i>d</i>&nbsp;&nbsp;if <i>v</i> cannot be read as an integer;<br/>'
            '&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
            'min(<i>U</i>,&nbsp;max(<i>L</i>,&nbsp;int(<i>v</i>)))&nbsp;&nbsp;otherwise&nbsp;}')
story.append(P('so a malformed or missing driver degrades to the declared default rather than '
               'crashing the scorer, and any out-of-range value is clamped, never allowed to '
               'pull the aggregate off its scale.'))
story.append(note_para('Cast semantics: ' + c('int(v)') + ' truncates toward zero when <i>v</i> is '
                       'a floating-point number (e.g. int(3.9)&nbsp;=&nbsp;3), and raises when it '
                       'is not numeric. Only the failure branch returns <i>d</i>; a parseable but '
                       'out-of-range integer is clamped. All bounds below are inclusive.'))
space(2)
story.append(P('Throughout this document rounding means Python’s '
               + c('round(x)') + ' — round-half-to-even (banker’s rounding) — not the '
               'round-half-away-from-zero taught in schools. The distinction matters at ties: '
               'round(62.5)&nbsp;=&nbsp;62.'))

sub_no('1.3&nbsp;&nbsp;Symbol glossary')
space(1)
story.append(notes_table([
    ['<i>e</i>', 'exploitability driver, an integer in [1, 5]; how readily the issue can be weaponised (5 = trivially).'],
    ['<i>i</i>', 'impact driver, an integer in [1, 5]; the harm a successful exploit does (5 = catastrophic).'],
    ['<i>x</i>', 'exposure driver, an integer in [1, 5]; how reachable / internet-facing the affected surface is (5 = public).'],
    ['<i>R</i>', 'raw risk score R = e·i·x, an integer in [1, 125].'],
    ['σ', 'severity label drawn from the set {Low, Medium, High, Critical}.'],
    ['<i>S</i>(σ)', 'severity base score: Low 25, Medium 50, High 75, Critical 100.'],
    ['<i>rank</i>(σ)', 'severity order: Low 1, Medium 2, High 3, Critical 4.'],
    ['κ', 'asset criticality, an integer in [0, 100]; how business-critical the affected asset appears (default 70).'],
    ['γ', 'confidence score, an integer in [0, 100]; how sure the evidence is (default 70).'],
    ['<i>P</i>', 'priority score, an integer in [15, 100]; the finding sort key used by the UI and report.'],
    ['fp', 'deduplication fingerprint (24 hexadecimal characters, see §3.1).'],
    ['<i>N</i>(h)', 'host normalisation function (§7.3): a canonical lower-case hostname or IP literal.'],
    ['⊆', 'subnet-of relation between IPv4/IPv6 networks (ipaddress.subnet_of).'],
    ['‖', 'string concatenation used when building a fingerprint.'],
    ['⊗', 'merge operator that folds a duplicate finding into the already-held one (§3.2).'],
]))
space(3)

sub_no('1.4&nbsp;&nbsp;Driver bounds and defaults')
space(1)
story.append(md_table(
    ['Driver', 'Symbol', 'Bounds', 'Default (fallback)', 'Meaning when high'],
    [
        ['exploitability', '<i>e</i>', '[1, 5]', '3', 'a public exploit or trivial trigger exists'],
        ['impact', '<i>i</i>', '[1, 5]', '3', 'confidentiality / integrity / availability loss is severe'],
        ['exposure', '<i>x</i>', '[1, 5]', '3', 'surface is reachable from the untrusted network'],
        ['confidence', 'γ', '[0, 100]', '70', 'the evidence unambiguously supports the finding'],
        ['asset criticality', 'κ', '[0, 100]', '70', 'asset is business-critical'],
    ],
    widths=[34 * mm, 15 * mm, 22 * mm, 24 * mm, 79 * mm]))
space(2)
story.append(notes_table([
    ['severity set', 'The four labels and their numeric scores S(σ) = {Low:25, Medium:50, High:75, Critical:100}.'],
    ['severity rank', 'rank(σ) is the total order used to merge two reports of the same finding (§3.2).'],
    ['score drivers', 'A finding may carry all five drivers; SCORE_DRIVERS fixes the default used if one is absent.'],
    ['rounding', 'All aggregates round with round-half-to-even; see the worked examples in §2.6.'],
]))
space(2)

# =========================================================================
# CHAPTER 2 — Finding scoring model
# =========================================================================
chapter_no(2, 'Finding Scoring Model')
story.append(P('Source: ' + c('backend/modules/analyzer.py') + ' (constants ' + c('SEVERITY') + ', '
               + c('SCORE_DRIVERS') + ', ' + c('DEFAULT_ASSET_CRITICALITY') + ', and functions '
               + c('bounded_int()') + ', ' + c('score_finding()') + ').'))

sub_no('2.1&nbsp;&nbsp;Severity normalisation')
story.append(P('An incoming label is title-cased and accepted only if it is one of the four '
               'known levels; anything else collapses to Low. This is a validation, not a '
               'mapping: a typo such as <i>critical</i> becomes Critical after '
               + c('str.title()') + ', while an invented label (' + c('"urgent"') + ') degrades '
               'to the least severe level.'))
eqn('2.1', '<i>σ</i>*&nbsp;=&nbsp;<i>normalize</i>(<i>v</i>)&nbsp;='
            '&nbsp;<i>title</i>(str(<i>v</i>))&nbsp;∩&nbsp;{Low,&nbsp;Medium,&nbsp;High,&nbsp;Critical},'
            '&nbsp;else&nbsp;Low')
space(1)
story.append(P('The four levels map to a base score used in the priority aggregate and to a '
               'rank used when duplicates merge:'))
space(1)
story.append(md_table(
    ['Level σ', 'Score S(σ)', 'rank(σ)', 'Intended meaning'],
    [
        ['Low', '25', '1', 'defence-in-depth weakness; no direct compromise path'],
        ['Medium', '50', '2', 'exploitable under conditions; e.g. a missing security header'],
        ['High', '75', '3', 'serious weakness, often directly exploitable'],
        ['Critical', '100', '4', 'remote, unauthenticated compromise of a valuable asset'],
    ],
    widths=[24 * mm, 24 * mm, 24 * mm, 102 * mm]))
space(2)

sub_no('2.2&nbsp;&nbsp;Driver intake')
story.append(P('Each driver is read through the bounded cast of Eq.&nbsp;(1.1) with the bounds '
               'and defaults of §1.4, so arithmetic below always sees integers inside the '
               'declared ranges:'))
eqn('2.2', '<i>e</i>&nbsp;=&nbsp;<i>bounded_int</i>(<i>e</i>&#8242;, 3, 1, 5),&nbsp;'
            '<i>i</i>&nbsp;=&nbsp;<i>bounded_int</i>(<i>i</i>&#8242;, 3, 1, 5),&nbsp;'
            '<i>x</i>&nbsp;=&nbsp;<i>bounded_int</i>(<i>x</i>&#8242;, 3, 1, 5)')
eqn('2.3', 'κ&nbsp;=&nbsp;<i>bounded_int</i>(κ&#8242;, 70, 0, 100),&nbsp;'
            'γ&nbsp;=&nbsp;<i>bounded_int</i>(γ&#8242;, 70, 0, 100)')
space(1)
story.append(P('where the primed values are the raw fields reported by a parser or by the AI '
               'provider. Note that a per-target asset criticality replaces the global default '
               '70 at intake (see §4.7): the value passed in is the target row’s '
               + c('criticality') + ' column, so a business-critical host is never scored with '
               'the average 70 by accident.'))

sub_no('2.3&nbsp;&nbsp;Risk score')
story.append(P('The risk score is the product of the three unitless drivers. It is the finding’s '
               'quantitative footprint — how damaging the issue is (<i>i</i>) adjusted for how '
               'easy it is to trigger (<i>e</i>) and how reachable it is (<i>x</i>):'))
eqn('2.4', '<i>R</i>&nbsp;=&nbsp;<i>e</i>&#8202;·&#8202;<i>i</i>&#8202;·&#8202;<i>x</i>,'
            '&nbsp;&nbsp;with&nbsp;&nbsp;<i>e</i>,<i>i</i>,<i>x</i>&nbsp;&#8712;&nbsp;{1,…,5}')
space(1)
story.append(P('The product is stored as ' + c('risk_score') + '. Range: 1·1·1 = 1 (benign, '
               'rarely reached) to 5·5·5 = 125. The single multiplicative score keeps '
               'correlation simple — an issue that is moderately easy, moderately damaging and '
               'moderately exposed scores 27, while one that is trivial, catastrophic and '
               'internet-facing scores the full 125.'))

sub_no('2.4&nbsp;&nbsp;Priority score')
story.append(P('The priority score is the weighted blend used to rank findings in the UI and the '
               'report. Written as implemented:'))
eqn('2.5', '<i>P</i>&nbsp;=&nbsp;round( 0.40·<i>S</i>(σ)&nbsp;+&nbsp;0.25·20·<i>e</i>'
            '&nbsp;+&nbsp;0.20·κ&nbsp;+&nbsp;0.15·γ )')
story.append(P('Because 0.25·20 = 5 the second term collapses to five times the exploitability '
               'driver, which is the form used below. The severity contributes at 40%, the '
               'exploitability (scaled to a 0–100 axis) at 25%, asset criticality at 20% and '
               'confidence at 15% — the four sum to 100%:'))
eqn('2.6', '<i>P</i>&nbsp;=&nbsp;round( 0.40·<i>S</i>(σ)&nbsp;+&nbsp;5·<i>e</i>'
            '&nbsp;+&nbsp;0.20·κ&nbsp;+&nbsp;0.15·γ )')
space(1)
story.append(note_para('Scale bounds. The extremes are S = 25 (Low), e = 1, κ = 0, γ = 0 giving '
                       'P = 10 + 5 = 15, and S = 100, e = 5, κ = 100, γ = 100 giving '
                       'P = 40 + 25 + 20 + 15 = 100. So P ∈ [15, 100]. A purely Low finding can '
                       'never outrank a Critical one unless its exploitability, criticality and '
                       'confidence are each also at their ceilings — the four drivers pull in the '
                       'same direction by design.', bg=note_bg))

sub_no('2.5&nbsp;&nbsp;Scoring procedure')
space(1)
story.append(alg('Algorithm 1 — score_finding(f): severity σ, risk R, priority P, confidence γ', [
    'Input : raw finding record f',
    'Output: (σ, R, P, γ) with every driver bounded',
    '',
    '1  σ       <- normalize_severity(f.severity)        // §2.1, else Low',
    '2  S       <- SEVERITY[σ]                            // 25 | 50 | 75 | 100',
    '3  e       <- bounded_int(f.exploitability, 3, 1, 5)',
    '4  i       <- bounded_int(f.impact,         3, 1, 5)',
    '5  x       <- bounded_int(f.exposure,       3, 1, 5)',
    '6  γ       <- bounded_int(f.confidence_score, 70, 0, 100)',
    '7  κ       <- bounded_int(f.asset_criticality, 70, 0, 100)',
    '8  R       <- e · i · x                              // Eq. (2.4)',
    '9  P       <- round(0.40·S + 0.25·(20·e) + 0.20·κ + 0.15·γ)   // Eq. (2.5)',
    '10 return (σ, R, P, γ)',
]))
space(2)

sub_no('2.6&nbsp;&nbsp;Worked examples')
story.append(P('Three findings produced by the deterministic parsers (§4) scored with the '
               'target asset criticality κ = 70, illustrating the formula and the rounding rule.'))
space(1)
story.append(md_table(
    ['Finding (parser)', 'σ', 'e · i · x', 'γ', 'S(σ)', 'R = e·i·x', 'P  (step sums)'],
    [
        ['Exposed http service, port 3000 (nmap)', 'Low', '2 · 3 · 4', '95', '25',
         '24', 'round(10 + 10 + 14 + 14.25) = 48'],
        ['Template-driven check matched, critical CVE (nuclei)', 'Critical', '4 · 5 · 4', '80',
         '100', '80', 'round(40 + 20 + 14 + 12) = 86'],
        ['Session cookie set without the Secure flag (curl)', 'Medium', '3 · 4 · 3', '90',
         '50', '36', 'round(20 + 15 + 14 + 13.5) = 62  ← half-to-even'],
    ],
    widths=[64 * mm, 18 * mm, 14 * mm, 10 * mm, 14 * mm, 16 * mm, 38 * mm]))
space(1)
story.append(note_para('The third row is the rounding tie: 0.40·50 + 5·3 + 0.20·70 + 0.15·90 '
                       '= 20 + 15 + 14 + 13.5 = 62.5, and round(62.5) = 62 under round-half-to-'
                       'even. A reader summing by hand with the school rule would expect 63.', bg=note_bg))
space(2)

# =========================================================================
# CHAPTER 3 — Deduplication and evidence merging
# =========================================================================
chapter_no(3, 'Deduplication &amp; Evidence Merging')
story.append(P('Source: ' + c('backend/modules/analyzer.py') + ' — ' + c('fingerprint()') + ', '
               + c('_normalize()') + ', ' + c('_combine()') + ', ' + c('analyze_results()') + '.'))

sub_no('3.1&nbsp;&nbsp;Canonical fingerprint')
story.append(P('Two findings describe the same defect when their title, endpoint and parameter '
               'agree after lower-casing and trimming. Those three fields are joined with '
               'vertical bars, hashed, and truncated to 24 hex characters so the key stays short '
               'enough for a database index:'))
eqn('3.1', 'fp&nbsp;=&nbsp;hex( SHA-256( <i>m</i> ) )[0&nbsp;:&nbsp;24],&nbsp;&nbsp;where&nbsp;'
            '<i>m</i>&nbsp;=&nbsp;low(trim(title))&nbsp;‖&nbsp;&#39;|&#39;&nbsp;‖&nbsp;'
            'low(trim(endpoint))&nbsp;‖&nbsp;&#39;|&#39;&nbsp;‖&nbsp;low(trim(parameter))')
space(1)
story.append(notes_table([
    ['<i>m</i>', 'the material string: the finding’s title, endpoint and parameter, each stripped and lower-cased before hashing.'],
    ['&#39;|&#39; separator', 'literal bar joins the fields, so (title&nbsp;=&nbsp;&#39;a|b&#39;, endpoint&nbsp;=&nbsp;&#39;&#39;) hashes differently from (title&nbsp;=&nbsp;&#39;a&#39;, endpoint&nbsp;=&nbsp;&#39;b&#39;).'],
    ['truncation', 'SHA-256 emits 64 hex characters; only the first 24 (96 bits) are kept as the database key.'],
]))
space(2)

sub_no('3.2&nbsp;&nbsp;Merge operator ⊗')
story.append(P('When a duplicate arrives (same fp), the held finding absorbs it by taking, per '
               'driver, the strongest value observed across the two reports. Severity follows '
               'the higher rank; the merge then lets ' + c('score_finding') + ' recompute '
               'R and P so a Critical duplicate can never be filed under the severity of the '
               'copy that arrived first.'))
eqn('3.2', 'current&nbsp;←&nbsp;current&nbsp;⊗&nbsp;incoming,&nbsp;where per field&nbsp;'
            '<i>g</i>&nbsp;∈&nbsp;{e,&nbsp;i,&nbsp;x,&nbsp;γ,&nbsp;κ}:')
eqn('3.3', '<i>g</i>&nbsp;←&nbsp;max( <i>bounded</i>(<i>g</i><sub>cur</sub>),&nbsp;'
            '<i>bounded</i>(<i>g</i><sub>new</sub>) )&nbsp;,&nbsp;&nbsp;and&nbsp;&nbsp;'
            'σ&nbsp;←&nbsp;argmax<sub>σ</sub>&nbsp;rank(σ)')
space(1)
story.append(notes_table([
    ['text fields', 'description, remediation, endpoint and parameter keep the longer of the two values; a blank never overwrites a real one.'],
    ['evidence', 'concatenated with a newline and re-bounded to MAX_FINDING_TEXT_CHARS (20,000) so 50 reports cannot bloat one row.'],
    ['source_tools', 'union of the two tool sets, sorted and de-duplicated.'],
]))
space(1)

sub_no('3.3&nbsp;&nbsp;Analysis pipeline')
space(1)
story.append(alg('Algorithm 2 — analyze_results(raw): normalise, dedupe, rescore', [
    'Input : raw_outputs, optional provider credentials, asset_criticality',
    'Output: ranked, de-duplicated finding list (mode = deterministic-fallback | ai-provider)',
    '',
    '1  if provider fully configured then',
    '2      findings <- _ai_findings(raw)          // §5, else _fallback(raw) on any error',
    '3      mode     <- ai-provider',
    '4  else findings <- _fallback(raw); mode <- deterministic-fallback',
    '5',
    '6  merged <- {}',
    '7  for each item in findings:',
    '8      n      <- _normalize(item, asset_criticality)   // §2.2 intake, truncation, fp',
    '9      fp     <- n.fingerprint',
    '10     if fp in merged: merged[fp] <- merged[fp] ⊗ n   // §3.2 strongest-wins',
    '11     else:            merged[fp] <- n',
    '12',
    '13 return [ score_finding(v) for v in merged.values() ]   // §2.5 recompute on merged',
]))
space(2)

# =========================================================================
# CHAPTER 4 — Deterministic per-tool extraction
# =========================================================================
chapter_no(4, 'Finding Extraction — Deterministic Per-tool Parsers')
story.append(P('Source: ' + c('backend/modules/analyzer.py') + '. When no AI provider is '
               'configured (or the provider call fails), ' + c('_fallback()') + ' dispatches '
               'each tool’s captured stdout+stderr to a dedicated recogniser. Every parser emits '
               'findings that already carry the five scoring drivers, a confidence γ, evidence '
               'and remediation, so the downstream scorer needs no provider.'))

sub_no('4.1&nbsp;&nbsp;Shared preprocessing')
story.append(P('Scanners colourise their output even into a pipe, and the escapes land inside '
               'the very tokens the regexes match (' + c('"SSLv3 \\x1b[32menabled"') + '). Every '
               'stream is therefore de-colourised first, and the plans also pass colour-off '
               'flags, but parsing never relies on them:'))
space(1)
story.append(alg('Algorithm 3 — strip_ansi(text)', [
    '1  return text with every CSI sequence removed',
    '2          // pattern: \\x1b [ 0-9;?]*  ( [ -/]* )?  [@-~]',
]))
space(2)
story.append(md_table(
    ['Recogniser', 'Trigger pattern (excerpt)', 'Acts per'],
    [
        ['nmap services', '^port/proto open service (version)?', 'host block opened by "Nmap scan report for …"'],
        ['nuclei', '^[template] [protocol?] [severity] url', 'matching line'],
        ['curl headers', '^Header: value inside a block opened by "HTTP/… nnn"', 'response block'],
        ['whatweb plugins', 'Name[Value] tokens after "[200 OK]"', 'plugin token'],
        ['sslscan protocols', '"SSLv2|SSLv3|TLSv1.0|TLSv1.1 … enabled"', 'protocol name'],
    ],
    widths=[26 * mm, 84 * mm, 64 * mm]))
space(2)

sub_no('4.2&nbsp;&nbsp;nmap — host tracking and services')
story.append(P('A subnet sweep emits one host block per live host. The parser tracks the '
               'current host from ' + c('"Nmap scan report for"') + ' headers (preferring the '
               'parenthesised IP) so a per-port finding carries the host-qualified endpoint '
               + c('host:port/proto') + '; otherwise every host block would collide on the same '
               'port-only endpoint and the fingerprint dedupe would silently merge all hosts '
               'but the first.'))
space(1)
story.append(notes_table([
    ['service state', 'open or filtered; only open counts as exposed (x = 4), filtered as limited (x = 2).'],
    ['tentative match', 'a trailing "?" (e.g. "ppp?") is preserved in the description, strips the "?", and lowers confidence to γ = 55.'],
    ['severity', 'Low when the service is http/https (a normal web port), else Medium.'],
    ['confidence γ', '95 with a version banner, 70 with a clean name, 55 when the banner match was tentative.'],
    ['drivers', 'e = 2, i = 3 fixed; x = 4 (open) or 2 (filtered).'],
]))
space(2)

sub_no('4.3&nbsp;&nbsp;nuclei — severity folding')
story.append(P('nuclei reports five levels; the framework scores four. The informational level '
               'is evidence rather than a Medium risk, so the fold maps it to Low rather than '
               'inheriting the default. Each reported level also carries a fixed driver triple:'))
space(1)
story.append(md_table(
    ['Reported level', 'Folded severity σ', 'Drivers (e, i, x)', 'Confidence γ'],
    [
        ['critical', 'Critical', '(4, 5, 4)', '80'],
        ['high', 'High', '(4, 4, 4)', '80'],
        ['medium', 'Medium', '(3, 3, 4)', '80'],
        ['low', 'Low', '(2, 2, 4)', '80'],
        ['info', 'Low (down-folded)', '(1, 1, 3)', '80'],
    ],
    widths=[30 * mm, 42 * mm, 44 * mm, 58 * mm]))
space(1)
story.append(note_para('A template match is always remotely reachable — hence the steady '
                       'exposure of 3–4 — and the level changes how damaging and how readily '
                       'weaponised the underlying issue is. γ = 80 everywhere: signature '
                       'evidence, not exploitation.', bg=note_bg))
space(2)

sub_no('4.4&nbsp;&nbsp;curl — header audit, banners, cookies')
story.append(P('The header map is rebuilt at every response block, so a redirect chain is '
               'audited at the hop the client actually lands on and curl’s own diagnostics '
               '(no "HTTP/… nnn" status line) never enter the map. A response that never began '
               'produces no header findings at all — a refused connection must not be reported '
               'as "all security headers missing".'))
space(1)
story.append(alg('Algorithm 4 — _finding_curl(stdout)', [
    '1  headers <- {}; status <- ""; in_response <- false',
    '2  for each line in stdout:',
    '3      if line starts with HTTP/x nnn:            // STATUS_LINE_RE',
    '4          headers <- {}; status <- nnn; in_response <- true',
    '5          continue',
    '6      if in_response and line matches "Name: value":',
    '7          headers[lower(Name)] <- value',
    '8  if not in_response: return []                 // step never reached the host',
    '9',
    '10 for each (name, spec) in SECURITY_HEADERS:     // §4.4b table',
    '11     if name not in headers: emit missing-header finding(spec)',
    '12 for name in {server, x-powered-by}:            // technology disclosure',
    '13     if headers[name] non-empty: emit disclosure finding(name, value)',
    '14 for each Set-Cookie line:                       // cookie flags audit',
    '15     for flag in {httponly, secure}:',
    '16         if flag not in lower(cookie): emit missing-flag finding(flag)',
]))
space(2)
story.append(P('The audited headers, their severities and driver triples are fixed by the '
               'module-level dictionary; each missing header becomes its own finding:'))
space(1)
story.append(md_table(
    ['Security header', 'Severity', '(e, i, x)', 'Finding type'],
    [
        ['content-security-policy', 'Medium', '(3, 4, 4)', 'missing-header'],
        ['strict-transport-security', 'Medium', '(3, 3, 3)', 'missing-header'],
        ['x-frame-options', 'Low', '(2, 3, 4)', 'missing-header'],
        ['x-content-type-options', 'Low', '(2, 3, 4)', 'missing-header'],
        ['referrer-policy', 'Low', '(2, 2, 4)', 'missing-header'],
        ['cookie without httponly', 'Medium', '(3, 4, 3)', 'missing-cookie-flag'],
        ['cookie without secure', 'Medium', '(3, 4, 3)', 'missing-cookie-flag'],
        ['server / x-powered-by banner', 'Low', '(2, 2, 5)', 'technology-disclosure'],
    ],
    widths=[54 * mm, 22 * mm, 24 * mm, 74 * mm]))
space(2)

sub_no('4.5&nbsp;&nbsp;whatweb — technology fingerprints')
story.append(P('The parser keeps only the "…Name[Value]" plugin tokens after the HTTP status '
               'block, skipping prose-like entries (country, ip, title, html5, script, email, '
               'redirectlocation). Each remaining plugin becomes a fingerprint finding at '
               'γ = 85 with e = 2, i = 2, x = 5 — disclosure narrows an attacker’s search to '
               'the exact stack.'))
space(1)

sub_no('4.6&nbsp;&nbsp;sslscan — deprecated protocols')
story.append(P('The parser scans the de-colourised output for the string '
               + c('"Protocol enabled"') + ' for each legacy protocol. TLSv1.0/TLSv1.1 are '
               'rated Medium; SSLv2/SSLv3, which modern clients refuse entirely and which bring '
               'legacy-cipher attacks (POODLE family), are High:'))
space(1)
story.append(md_table(
    ['Protocol', 'Severity', '(e, i, x)', 'Confidence γ'],
    [
        ['SSLv2 / SSLv3', 'High', '(3, 4, 4)', '95'],
        ['TLSv1.0 / TLSv1.1', 'Medium', '(3, 4, 4)', '95'],
    ],
    widths=[40 * mm, 26 * mm, 30 * mm, 78 * mm]))
space(2)

sub_no('4.7&nbsp;&nbsp;Normalisation guards')
space(1)
story.append(notes_table([
    ['count caps', 'at most MAX_FINDINGS = 200 findings survive any analysis; every text field is truncated at intake (title 500, prose 20,000 chars).'],
    ['severity', 'all five parsers report through normalize_severity, so an untrusted label cannot introduce a sixth level.'],
    ['AI mode', 'with a provider, findings from the model run through the same _normalize → merge → score pipeline; the report states which mode produced them.'],
    ['per-target κ', '_normalize binds a missing asset_criticality to the assessment target’s value before scoring, never to the global 70.'],
]))
space(2)

# =========================================================================
# CHAPTER 5 — Provider analysis and token budget
# =========================================================================
chapter_no(5, 'Provider Analysis &amp; Token Budgeting')
story.append(P('Source: ' + c('backend/modules/analyzer.py') + ' — ' + c('_ai_findings()') + '. '
               'Scanner output is concatenated into a single prompt sent to the OpenAI-compatible '
               'provider. Two caps keep the prompt bounded: one per stream, and one shared budget '
               'across the whole batch so one very chatty scanner cannot crowd every later tool '
               'out of the request.'))

sub_no('5.1&nbsp;&nbsp;Budget allocation')
space(1)
story.append(notes_table([
    ['C', 'per-stream cap, MAX_ANALYSIS_OUTPUT_CHARS = 120,000 characters'],
    ['B', 'remaining shared budget, MAX_ANALYSIS_TOTAL_CHARS = 400,000, initialised once per analysis'],
]))
space(1)
story.append(P('For each output stream (stdout and stderr of each tool), the retained text is '
               'the shorter of the per-stream cap and the remaining budget, and the budget '
               'shrinks by what was retained:'))
eqn('5.1', '<i>t</i>&#8242;&nbsp;=&nbsp;prefix(<i>t</i>,&nbsp;min(<i>C</i>,&nbsp;max(<i>B</i>,&nbsp;0))),'
            '&nbsp;&nbsp;&nbsp;<i>B</i>&nbsp;←&nbsp;<i>B</i>&nbsp;−&nbsp;|<i>t</i>&#8242;|')
space(1)
story.append(P('The two-pass form matters: stdout is consumed first, then stderr from the same '
               'tool, then the next tool. A tool whose stdout already exhausts the budget leaves '
               'nothing for its own stderr — the global cap is a hard wall, not a soft hint.'))
space(1)
story.append(alg('Algorithm 5 — budgeted prompt construction', [
    'Input : raw_outputs (list of {tool, stdout, stderr})',
    'Output: prompt string embedding at most B characters of evidence',
    '',
    '1  B <- MAX_ANALYSIS_TOTAL_CHARS = 400_000',
    '2  for each output in raw_outputs:',
    '3      stdout <- prefix(output.stdout, min(C, max(B, 0)));   B <- B - |stdout|',
    '4      stderr <- prefix(output.stderr, min(C, max(B, 0)));   B <- B - |stderr|',
    '5  prompt <- fixed instructions + JSON(bounded_outputs)',
    '6  return prompt',
]))
space(2)

sub_no('5.2&nbsp;&nbsp;Safety and bound properties')
space(1)
story.append(P('The provider response is treated as untrusted input, not as a model that must '
               'be obeyed: the prompt instructs it that scanner output is evidence, and the '
               'response is capped before it becomes database rows or report sections.'))
space(1)
story.append(notes_table([
    ['response shape', 'must parse as a JSON list of objects; any other shape falls back to the deterministic path.'],
    ['count cap', 'at most MAX_FINDINGS = 200 findings are taken from the provider response.'],
    ['text cap', 'title ≤ 500 chars; description/evidence/remediation ≤ MAX_FINDING_TEXT_CHARS = 20,000 each.'],
    ['prompt-injection note', 'the system line tells the model that embedded scanner text is data, never instructions.'],
]))
space(2)

# =========================================================================
# CHAPTER 6 — Assessment planning
# =========================================================================
chapter_no(6, 'Assessment Planning')
story.append(P('Source: ' + c('backend/modules/planner.py') + '. A plan is an ordered list of '
               'policy-legal steps. The planner either drafts steps with an AI provider and then '
               'policy-filters them, or — with no provider, on provider error, or when every '
               'model step was rejected — falls back to a fixed deterministic plan.'))

sub_no('6.1&nbsp;&nbsp;Target classification and endpoint derivation')
story.append(P('The target string is first classified. A CIDR literal such as '
               + c('172.28.0.0/24') + ' is a segment, not a host, and gets its own two-step '
               'discovery plan (§6.3). Otherwise the target is parsed as a URL-ish endpoint to '
               'recover its host and optional port:'))
space(1)
story.append(alg('Algorithm 6 — classify and build default plan(target)', [
    '1  if "/" in target and ip_network(target, strict=False) parses:',
    '2      return SUBNET_PLAN formatted with target          // §6.3, 2 steps',
    '3',
    '4  parsed <- urlparse(target) or urlparse("//" + target)',
    '5  host   <- parsed.hostname or target.split(":")[0]',
    '6  port   <- parsed.port',
    '7  endpoint <- host if port is None else host + ":" + str(port)',
    '8',
    '9  for step in DEFAULT_PLAN:                              // §6.2, 7 steps',
    '10     if step.tool in {nmap, traceroute, dig, nslookup}:',
    '11         tgt <- host              // name-resolving tools want the BARE host',
    '12     else: tgt <- endpoint        // web / TLS tools parse host:port themselves',
    '13     step.command <- format(step.command, target=tgt, ports=("-p " + port if port else ""))',
    '14     append step',
]))
space(2)
story.append(note_para('The split matters. ' + c("nmap juice-shop:3000") + ' and '
                       + c("dig +short juice-shop:3000") + ' fail to resolve while still exiting '
                       '0, so a plan that keeps the port on those tools runs green and produces '
                       'nothing. nmap learns the port through -p instead; sslscan and the web '
                       'tools accept host:port and keep it.', bg=note_bg))
space(2)

sub_no('6.2&nbsp;&nbsp;Default host plan')
story.append(P('Seven steps, each already policy-legal. Targets are rate-limited to 30 probes/s '
               'and colour-off flags are set so parsers see clean tokens:'))
space(1)
story.append(md_table(
    ['#', 'Tool', 'Command template (target placeholder)', 'Purpose'],
    [
        ['1', 'nmap', c('nmap -sV --version-light --max-rate 30 {ports}{target}'),
         'exposed ports and versions'],
        ['2', 'traceroute', c('traceroute {target}'), 'network path / adjacency'],
        ['3', 'dig', c('dig +short {target}'), 'address resolution check'],
        ['4', 'curl', c('curl -sSI http://{target}'), 'HTTP header audit'],
        ['5', 'whatweb', c('whatweb -a 3 --color=never http://{target}'), 'stack fingerprinting'],
        ['6', 'sslscan', c('sslscan --no-colour {target}'), 'TLS protocol / cipher audit'],
        ['7', 'nuclei', c('nuclei -u http://{target} -tags cve,exposure,misconfig -severity medium,high,critical -rl 30 -nc -stats -duc -silent'),
         'rate-limited template checks'],
    ],
    widths=[8 * mm, 20 * mm, 92 * mm, 54 * mm]))
space(1)
story.append(P('The web-tool templates already carry ' + c('http://') + ', so the formatted '
               'target must not be re-prefixed — the bug that once produced '
               + c('http://http://host:3000') + ' lives in the formatting, not the tool.'))

sub_no('6.3&nbsp;&nbsp;Subnet discovery and probe budget')
story.append(P('A CIDR target authorizes a range sweep, and only nmap accepts a range. The '
               'subnet plan is therefore two nmap steps — a live-host discovery then a '
               'common-port sweep with light version detection:'))
space(1)
story.append(md_table(
    ['#', 'Command (target = 172.28.0.0/24)', 'What it establishes'],
    [
        ['1', c('nmap -sn --max-rate 30 172.28.0.0/24'), 'which addresses are alive'],
        ['2', c('nmap -sV --version-light --open --max-rate 30 -p 22,25,53,80,110,143,443,445,3000,3306,3389,5432,5900,6379,8000,8080,8443 172.28.0.0/24'),
         'exposed services on the 17 common ports'],
    ],
    widths=[8 * mm, 128 * mm, 38 * mm]))
space(1)
story.append(P('Why a /24 and not a /16? At the letter-mandated rate of <i>r</i> = 30 probes/s '
               'the probe count is the binding constraint. The discovery sweep costs about '
               'two probes per address and the service sweep one probe per (address × port):'))
eqn('6.1', 'n<sub>sn</sub>&nbsp;≈&nbsp;2·<i>N</i>,&nbsp;'
            '&nbsp;&nbsp;&nbsp;n<sub>sweep</sub>&nbsp;≈&nbsp;17·(<i>N</i>−2),&nbsp;'
            '&nbsp;&nbsp;&nbsp;t&nbsp;=&nbsp;n&nbsp;/&nbsp;<i>r</i>')
space(1)
story.append(md_table(
    ['Segment', 'N (addresses)', '≈ probes n', '≈ time t at 30/s', 'inside 360 s cap?'],
    [
        ['/24', '256', '512 + 4,318 ≈ 4,830', '≈ 161 s', 'yes'],
        ['/16', '65,536', '512 + 17·65,534 ≈ 1.1 M', '≈ 10.5 h', 'no — rejected by models.py'],
    ],
    widths=[22 * mm, 28 * mm, 52 * mm, 36 * mm, 36 * mm]))
space(1)
story.append(P('The schema layer makes the budget a hard limit before any scan starts: a '
               'registered network target may contain at most '
               + c('MAX_SUBNET_ADDRESSES') + ' = 256 addresses, which is exactly a /24 for IPv4. '
               'The executor timeout (§9.3) is the second, independent guard.'))

sub_no('6.4&nbsp;&nbsp;Plan sources and policy filtering')
story.append(P('Every plan — AI or default — is reviewed against the same per-target letter '
               'restrictions in ' + c('main.create_assessment()') + ': steps whose tool is '
               'client-restricted for the target are dropped before the plan is stored, with the '
               'count reported back to the UI. The source tag tells the operator why a default '
               'plan was used:'))
space(1)
story.append(md_table(
    ['Source tag', 'Meaning'],
    [
        ['ai-filtered', 'model plan survived per-step policy review'],
        ['default-unconfigured', 'no provider key + endpoint + model set'],
        ['default-provider-error', 'provider call or response failed'],
        ['default-policy-rejected', 'every model step was rejected by the policy engine'],
        ['user', 'operator supplied the plan directly'],
    ],
    widths=[46 * mm, 128 * mm]))
space(2)

# =========================================================================
# CHAPTER 7 — Policy engine and scope validation
# =========================================================================
chapter_no(7, 'Policy Engine &amp; Scope Validation')
story.append(P('Source: ' + c('backend/modules/policy_engine.py') + '. The engine is an '
               'allowlist, not a blocklist: every flag a tool may receive is enumerated per '
               'tool, and anything not enumerated fails closed. Flag semantics are per tool as '
               'well, because a shared table cannot express both ' + c('nmap -A') + ' (no value) '
               'and ' + c('curl -A') + ' (takes a value).'))

sub_no('7.1&nbsp;&nbsp;Argument grammar')
story.append(P('A tool spec declares its flag classes. When the argument scanner walks the '
               'tokens, each token is classified exactly one way:'))
space(1)
story.append(md_table(
    ['Class', 'Meaning', 'Example'],
    [
        ['bool flag', 'takes no value', 'nmap -sV, curl -I, nuclei -silent'],
        ['value flag', 'takes a value that is NOT a target', 'nmap -p, nuclei -rl, curl -A'],
        ['target flag', 'takes a value that IS a target (scope-checked)', 'curl --url, nuclei -u, dig -q'],
        ['resolver flag / sigil', 'takes a DNS resolver', "dig @8.8.8.8"],
        ['attached pattern', 'self-contained, e.g. -T4, +short, -p22', 'regex-validated token'],
        ['positional', 'bare argument; per-tool rule decides target vs resolver', 'the final URL'],
    ],
    widths=[32 * mm, 74 * mm, 68 * mm]))
space(1)
story.append(P('Scanning is a single forward pass with at most one pending value. Because '
               'argv is a list (split by ' + c('shlex.split') + '), a flag and its value are two '
               'tokens and a target never needs quoting. Flag recognition also honours '
               'POSIX short-flag bundling — for curl only, which genuinely supports '
               + c('-sSL') + ':'))

sub_no('7.2&nbsp;&nbsp;Argument scanning')
space(1)
story.append(alg('Algorithm 7 — scan_arguments(tokens, spec) → (targets, resolvers, error)', [
    '1  targets <- []; resolvers <- []; positionals <- []; pending <- None',
    '2  for each token in tokens[1:]:',
    '3      if pending: file under pending as target/resolver; pending <- None; continue',
    '4      if token starts with resolver sigil "@" (dig): resolvers += token[1:]; continue',
    '5      if token is a flag:',
    '6          match token against {bool, value, target, resolver} flag sets',
    '7          if value/target/resolver flag: pending <- class; continue',
    '8          if "name=value" split and name is allowed: handle; continue',
    '9          if token matches an attached pattern (-T4, +short): continue',
    '10         if tool supports bundling and -sSL decomposes cleanly: continue',
    '11         else: return error(blocked flag)          // fail closed',
    '12     else: positionals += token',
    '13 if pending: return error(pending flag starved of its value)',
    '14 split positionals per resolver_positionals (nslookup: index ≥ 1 is a resolver)',
    '15 return targets, resolvers, None',
]))
space(1)
story.append(note_para('Bundle rule: a token like -sSL decomposes only when every character is '
                       'a permitted boolean flag and, at most, the final character may take a '
                       'value. A value flag in the middle fails closed rather than swallowing the '
                       'rest of the token. nuclei and nslookup use single-dash long flags '
                       '(-silent) and are never decomposed.', bg=note_bg))
space(2)

sub_no('7.3&nbsp;&nbsp;Host normalisation')
story.append(P('All comparisons happen in a canonical form. A bare IPv6 literal is recognised '
               'before URL parsing (urlparse would read every colon as a port and discard the '
               'address); otherwise the host is pulled from a parsed URL, brackets and trailing '
               'dot are stripped, the name is lower-cased, and an IP literal is canonicalised so '
               'that ' + c('0:0:0:0:0:0:0:1') + ' and ' + c('::1') + ' compare equal:'))
eqn('7.1', '<i>N</i>(h)&nbsp;=&nbsp;canonicalise( lower( strip_brackets_and_dot( host(h) ) ) )')
space(1)
story.append(notes_table([
    ['URL vs literal', 'host(h) is parsed.hostname when a scheme or "//" prefix is present, else h.split(":")[0].'],
    ['IP canonicalisation', 'if the result parses as ip_address it is returned as its canonical string (::1).'],
]))
space(2)

sub_no('7.4&nbsp;&nbsp;Scope membership')
story.append(P('A target is in scope when it is inside an authorized network, equals an '
               'authorized host, or is a subdomain of an authorized host. The CIDR branch is a '
               'proper subnet test, never a base-address check:'))
eqn('7.2', 'CIDR&nbsp;target&nbsp;<i>R</i>&nbsp;accepted&nbsp;&nbsp;&#8660;&nbsp;&nbsp;'
            '&#8707;&nbsp;<i>N</i>&nbsp;&#8712;&nbsp;A:&nbsp;'
            '<i>R</i>.version&nbsp;=&nbsp;<i>N</i>.version&nbsp;&#8743;&nbsp;<i>R</i>&nbsp;⊆&nbsp;<i>N</i>')
eqn('7.3', 'host&nbsp;<i>h</i>&nbsp;accepted&nbsp;&nbsp;&#8660;&nbsp;&nbsp;'
            '&#8707;&nbsp;<i>s</i>&nbsp;&#8712;&nbsp;A:&nbsp;'
            '(<i>h</i>&nbsp;&#8712;&nbsp;<i>N</i>(<i>s</i>))&nbsp;&#8744;&nbsp;'
            '(<i>h</i>&nbsp;=&nbsp;<i>s</i>)&nbsp;&#8744;&nbsp;'
            '(<i>h</i>&nbsp;endswith&nbsp;&#39;.&#39;+<i>s</i>)')
space(1)
story.append(notes_table([
    ['A', 'the target’s authorized scope set (letter scopes, else the single primary scope).'],
    ['version guard', 'an IPv4 request is never matched against an IPv6 authorization and vice versa.'],
    ['subdomain rule', 'h = "app.example.com" is authorized by s = "example.com"; a bare suffix on a different label boundary is rejected.'],
]))
space(2)

sub_no('7.5&nbsp;&nbsp;Resolver policy')
story.append(P('A resolver argument is validated separately from targets because a DNS query '
               'aimed at a resolver is not an assessment action against it. It is accepted only '
               'when it is itself in scope or is one of the well-known public resolvers:'))
eqn('7.4', 'accepted(<i>r</i>)&nbsp;&nbsp;&#8660;&nbsp;&nbsp;<i>N</i>(<i>r</i>)&nbsp;&#8712;&nbsp;'
            'P<sub>resolvers</sub>&nbsp;&nbsp;&#8744;&nbsp;&nbsp;<i>validate_target</i>(<i>r</i>,&nbsp;A)')
space(1)

sub_no('7.6&nbsp;&nbsp;Decision procedure')
space(1)
story.append(alg('Algorithm 8 — validate_command(command, A, expected_tool)', [
    'Input : one shell command string, authorized scopes A, optional declared tool',
    'Output: (accepted, message, capability&risk)',
    '',
    '1  reject if command empty or contains a control char (\\n \\r \\t \\x00 \\x0b \\x0c)',
    '2  tokens <- shlex.split(command)                 // parse error -> reject',
    '3  reject if tokens[0] not in tool_registry        // executable not enabled',
    '4  reject if expected_tool set and tokens[0] != expected_tool',
    '5  (targets, resolvers, err) <- scan_arguments(tokens, rules[tokens[0]])',
    '6  reject if err                                 // blocked flag -> fail closed',
    '7  reject if targets is empty                     // no explicit target',
    '8  reject if any target fails validate_target (Eq. 7.2 / 7.3)',
    '9  reject if any resolver fails validate_resolver (Eq. 7.4)',
    '10 accept; return (True, "HITL approval required", capability · risk)',
]))
space(2)

# =========================================================================
# CHAPTER 8 — Engagement letter parsing
# =========================================================================
chapter_no(8, 'Engagement Letter Parsing')
story.append(P('Source: ' + c('backend/modules/engagement_parser.py') + '. A client letter '
               'arrives as free text once extracted from PDF/DOCX/MD/TXT. The parser recovers '
               'its structure deterministically — which hosts are in scope, their criticalities, '
               'and which tools the client ruled out per target — so what the agents "know" never '
               'depends on a provider being configured.'))

sub_no('8.1&nbsp;&nbsp;Pipeline')
space(1)
story.append(P('The letter is first split into clean lines (page furniture removed), then five '
               'independent extractors run over those lines. Targets are recovered first because '
               'restriction and objective extraction need to know which target a sentence names:'))
space(1)
story.append(alg('Algorithm 9 — parse_engagement(text)', [
    '1  lines <- clean_lines(text)        // drop blanks + furniture (footer, page n, "— Confidential")',
    '2  unbulleted <- strip bullet glyphs from lines   // bullet rows are still label/value rows',
    '3  targets   <- _parse_targets(unbulleted)        // label table + fallback scan (§8.3)',
    '4  targets   <- _parse_restrictions(lines, targets) // allow-list / deny-list prose (§8.4)',
    '5  fields    <- _parse_doc_fields(lines, text)    // engagement ref, test window',
    '6  objectives <- _parse_objectives(lines)         // "4.1 Service discovery: …"',
    '7  out_of_scope <- bullet block under "out of scope" heading',
    '8  prohibited  <- bullet block under "prohibited techniques" heading',
    '9  return brief {client, ref, window, contact, targets, objectives, out_of_scope, prohibited}',
]))
space(2)

sub_no('8.2&nbsp;&nbsp;Cleaning and furniture')
story.append(P('reportlab-style page furniture repeats on every page between sections and would '
               'be read as content if left in. A line is dropped when any furniture pattern '
               'matches it:'))
space(1)
story.append(md_table(
    ['Furniture pattern', 'Purpose'],
    [
        [c('^— Confidential$'), 'footer band on every page'],
        [c('^Engagement [A-Z0-9/]+$'), 'repeated engagement banner'],
        [c('^Page \\d+$'), 'page numbers'],
        [c('^Request for Security Assessment Services — Confidential$'), 'title band'],
    ],
    widths=[92 * mm, 82 * mm]))
space(2)
story.append(P('A bullet glyph that PDF extraction emits as ' + c('\\x7f') + ' (DEL) is treated '
               'as a bullet marker, so bulleted lists never parse as prose and lose their '
               'items.'))

sub_no('8.3&nbsp;&nbsp;Target extraction: label table then fallback scan')
story.append(P('Targets come from two passes. The first reads RFP-style label/value rows — a '
               'label like "Authorized target address" names the next line as the address, with '
               'a CIDR tried before the host:port pattern so a subnet’s mask is not left behind. '
               'The second is a fallback scan: any host:port or CIDR token anywhere in the body '
               'becomes a target unless it was already captured or sits inside the out-of-scope '
               'section:'))
space(1)
story.append(alg('Algorithm 10 — fallback target scan', [
    '1  excluded <- line indexes under the "out of scope" heading (until next numbered heading)',
    '2  known    <- addresses already captured by the label pass',
    '3  for each line not in excluded:',
    '4      for each host:port match in line:      // \b host:port \b',
    '5          if match not in known: append target; known <- known ∪ {match}',
    '6      for each CIDR match in line:           // \b a.b.c.d/len \b',
    '7          if match not in known: append subnet target; known <- known ∪ {match}',
    '8  return targets',
]))
space(1)
story.append(note_para('Set algebra keeps the two passes disjoint: ' + c("known") + ' is a set '
                       'growing by union, so the label pass and the fallback pass can never '
                       'register the same asset twice, and the out-of-scope set is subtracted '
                       'up front so "out of scope: the corporate network 10.10.0.0/16" never '
                       'becomes a scan target.', bg=note_bg))
space(2)

sub_no('8.4&nbsp;&nbsp;Restriction extraction — set algebra')
story.append(P('Per-target tool restrictions are read from the rules-of-engagement prose, which '
               'takes two sentence shapes. Known tools are the eight the framework can run: '
               + c('nmap traceroute dig nslookup curl whatweb sslscan nuclei') + '. For every '
               'target a section names, a sentence contributes a restriction only when it also '
               'names at least one known tool:'))
eqn('8.1', 'allow-list&nbsp;sentence&nbsp;S&nbsp;(&#8220;only&#8230;authorized against&#8221;):&nbsp;'
            'R<sub>t</sub>&nbsp;←&nbsp;R<sub>t</sub>&nbsp;∪&nbsp;(<i>K</i>&#8726;&nbsp;<i>K</i><sub>S</sub>)')
eqn('8.2', 'deny-list&nbsp;sentence&nbsp;S&nbsp;(&#8220;must not be run against&#8221;):&nbsp;'
            'R<sub>t</sub>&nbsp;←&nbsp;R<sub>t</sub>&nbsp;∪&nbsp;<i>K</i><sub>S</sub>')
space(1)
story.append(notes_table([
    ['K', 'the eight known tools; any tool named outside K is already refused by the policy engine.'],
    ['K_S', 'the known tools named inside the sentence, detected by whole-word match.'],
    ['R_t', 'the restriction set per target — later enforced at plan time and again at execute time.'],
    ['complement', 'an allow-list sentence bans every known tool EXCEPT those it names.'],
]))
space(2)

sub_no('8.5&nbsp;&nbsp;Objectives and ruled-out lists')
story.append(P('Numbered objective items of the form "4.1 Service discovery: …" are captured by '
               'a heading regex plus a colon filter — the colon is what separates an objective '
               'from a same-shaped section heading such as "3.1 Primary asset — …". A wrapped '
               'continuation line is folded back into the previous item when that item does not '
               'yet end a sentence. Out-of-scope and prohibited-technique lists are collected '
               'from bullet blocks under their headings, and items start only on bullet lines so '
               'a section’s intro sentence is never mistaken for an item.'))

# =========================================================================
# CHAPTER 9 — Execution and assessment lifecycle
# =========================================================================
chapter_no(9, 'Execution &amp; Assessment Lifecycle')
story.append(P('Source: ' + c('backend/modules/executor.py') + ' and ' + c('backend/main.py') +
               '. Commands run as real subprocesses (never through a shell), streamed into '
               'bounded buffers and killed on timeout.'))

sub_no('9.1&nbsp;&nbsp;Streaming, caps and truncation')
space(1)
story.append(alg('Algorithm 11 — execute_command(tool, command, env, execution_id)', [
    '1  start timer; chunks <- []',
    '2  process <- create_subprocess_exec(*shlex.split(command), pipes, env)',
    '3  spawn two drain coroutines (stdout, stderr) + process.wait() in parallel',
    '4  wait for all with timeout = EXECUTION_TIMEOUT_SECONDS = 360 s',
    '5  on timeout: kill process group (SIGKILL on POSIX); return_code <- -1; timed_out <- true',
    '6  stdout <- truncate(chunks.stdout); stderr <- truncate(chunks.stderr)',
    '7  if timed_out: prefix stderr with the timeout notice',
    '8  return {tool, command, stdout, stderr, return_code, duration_ms}',
]))
space(1)
story.append(P('Draining reads 64&nbsp;KiB chunks but retains at most '
               + c('MAX_OUTPUT_BYTES') + ' = 800,000 bytes per stream (200,000 chars × 4, an '
               'estimate of the worst-case UTF-8 width), continuing to read so a chatty scanner '
               'never blocks on a full pipe. The decoded text is finally truncated to '
               + c('MAX_OUTPUT_CHARS') + ' = 200,000 characters with a marker appended:'))
eqn('9.1', 'retain&nbsp;≤&nbsp;min(<i>B</i>,&nbsp;|<i>s</i>|),&nbsp;&nbsp;'
            '|text|&nbsp;≤&nbsp;200,000&nbsp;&nbsp;&#8658;&nbsp;&nbsp;text&#8242;&nbsp;='
            '&nbsp;text[:200,000]&nbsp;+&nbsp;&#39;\\n[stdout truncated]&#39;')
space(2)

sub_no('9.2&nbsp;&nbsp;Live terminal registry')
story.append(P('While a command is in flight, its partial output is kept in memory so the UI '
               'can stream it. The live buffer is a sliding window — appending and keeping only '
               'the most recent characters:'))
eqn('9.2', 'buf&nbsp;←&nbsp;(buf&nbsp;+&nbsp;<i>t</i>)[−<i>L</i>&nbsp;:&nbsp;],&nbsp;'
            '&nbsp;&nbsp;<i>L</i>&nbsp;=&nbsp;LIVE_BUFFER_CHARS&nbsp;=&nbsp;200,000')
space(1)
story.append(P('The registry holds only genuinely running commands: entries are registered '
               'before the process starts and removed however it ends, so a later poll that '
               'finds no entry knows the run is over and re-reads the authoritative database '
               'row.'))
space(2)

sub_no('9.3&nbsp;&nbsp;Timeout and process-group termination')
story.append(P('Both nmap and nuclei spawn children, so a timeout kills the whole process '
               'group, not just the parent. The 360&nbsp;s figure is measured against the nuclei '
               'step — 12,078 requests across 5,242 templates is about 308&nbsp;s at 30&nbsp;req/s '
               '— so the cap leaves headroom without letting a hung scanner wait meaningfully '
               'longer. On a client disconnect the coroutine is cancelled; the '
               'finally-branch terminates any process still running so a scan can never '
               'continue hammering the target with nobody left to read it.'))
space(1)
story.append(md_table(
    ['Execution aspect', 'Value / rule'],
    [
        ['timeout', '360 s (EXECUTION_TIMEOUT_SECONDS); on expiry return_code = -1 and a notice is prefixed to stderr'],
        ['output cap', '200,000 chars per stream (stdout, stderr) after drain'],
        ['read chunk', '64 KiB (READ_CHUNK_BYTES)'],
        ['live buffer', 'last 200,000 chars (LIVE_BUFFER_CHARS), in-memory only'],
        ['env sandbox', 'subprocess inherits only PATH/HOME/… + proxy vars, never DATABASE_URL or provider keys'],
    ],
    widths=[38 * mm, 136 * mm]))
space(2)

sub_no('9.4&nbsp;&nbsp;Retry, staleness and uniqueness')
story.append(P('Each plan step has at most one execution row per assessment '
               '(UniqueConstraint on assessment_id + step_index), which doubles as a '
               'concurrency guard. A step may be re-approved only when its previous attempt '
               'failed or was abandoned. An execution row whose command can no longer be alive '
               'is stale and reclaimable:'))
eqn('9.3', 'stale(<i>r</i>)&nbsp;&#8660;&nbsp;'
            '<i>r</i>.return_code&nbsp;=&nbsp;NULL&nbsp;&#8743;&nbsp;'
            'now&nbsp;−&nbsp;<i>r</i>.executed_at&nbsp;&gt;&nbsp;360&nbsp;s&nbsp;+&nbsp;60&nbsp;s')
space(1)
story.append(note_para('Retryable ⇔ return_code ≠ 0 and (the row is complete, or it is stale). '
                       'A successful step is never retried, keeping the audit trail '
                       'append-only in the case that matters. Re-running a step clears its old '
                       'output and invalidates any analysis derived from it.', bg=note_bg))
space(2)

sub_no('9.5&nbsp;&nbsp;Assessment status automaton')
space(1)
story.append(P('An assessment moves through a small set of states. Let '
               'E = enabled step indexes and X = indexes with a completed execution. Analysis '
               'is gated on X ⊇ E, and the plan is frozen once any execution exists:'))
space(1)
story.append(md_table(
    ['Transition', 'Guard'],
    [
        ['awaiting_approval → running', 'a step is approved and dispatched (per-step)'],
        ['running → awaiting_approval', 'enabled steps remain unexecuted after a step returns'],
        ['running → ready_for_analysis', 'X ⊇ E: every enabled step has a completed execution'],
        ['→ analyzed', 'analysis endpoint runs; findings written; analysis_mode recorded'],
        ['analyzed → reported', 'report rendered to data/reports/report_<id>.html'],
        ['any pre-run state → awaiting_approval', 'plan edited (rejected once X ≠ ∅)'],
        ['stale running → (recovered)', 'reconcile_running_status moves it off "running"'],
    ],
    widths=[78 * mm, 96 * mm]))
space(2)
story.append(note_para('Two gates look like bugs during a demo but are deliberate: the plan is '
                       'frozen once any step has executed (plan edits return 409), and analysis '
                       'requires every enabled step to have run. Disable steps before starting '
                       'for a shorter run.', bg=note_bg))
space(2)

# =========================================================================
# CHAPTER 10 — Credential encryption and proxy composition
# =========================================================================
chapter_no(10, 'Credential Encryption &amp; Proxy Composition')
story.append(P('Source: ' + c('backend/modules/secret_store.py') + '. The provider API key and '
               'proxy password are stored encrypted at rest, because the SQLite file is '
               'ordinary data: it gets copied into backups, mounted into containers, and '
               'occasionally attached to a bug report.'))

sub_no('10.1&nbsp;&nbsp;Fernet envelope')
story.append(P('Values use the Fernet symmetric-key format (AES-128-CBC with PKCS#7 padding and '
               'HMAC-SHA256 authentication). A Fernet token is one base64url blob whose binary '
               'content is laid out as:'))
space(1)
story.append(note_para('token&nbsp;=&nbsp;b64url(&nbsp;<b>0x80</b>&nbsp;‖&nbsp;'
                       'timestamp&nbsp;<i>t</i>&nbsp;(8&nbsp;bytes,&nbsp;big-endian&nbsp;seconds)&nbsp;‖&nbsp;'
                       'iv&nbsp;(16&nbsp;bytes)&nbsp;‖&nbsp;ciphertext&nbsp;AES-128-CBC<sub>k</sub>(m)&nbsp;‖&nbsp;'
                       'HMAC-SHA256<sub>k</sub>(0x80&nbsp;‖&nbsp;<i>t</i>&nbsp;‖&nbsp;iv&nbsp;‖&nbsp;ciphertext)'
                       '&nbsp;)', bg=note_bg))
space(1)
story.append(P('The framework stores the token with a versioning prefix so plaintext '
               'credentials written before encryption was introduced are recognised rather than '
               'fed to Fernet (which would reject them and silently discard a key the operator '
               'had already configured):'))
eqn('10.1', 'stored&nbsp;=&nbsp;&#39;enc:v1:&#39;&nbsp;‖&nbsp;token,&nbsp;'
            '&nbsp;&nbsp;&nbsp;is_encrypted(<i>v</i>)&nbsp;&#8660;&nbsp;'
            '<i>v</i>.startswith(&#39;enc:v1:&#39;)')
space(2)

sub_no('10.2&nbsp;&nbsp;Key hierarchy')
space(1)
story.append(md_table(
    ['Key source', 'When used', 'Notes'],
    [
        ['REDTEAM_SECRET_KEY (env)', 'always, when set', 'never lands on the same volume as the database; rotated key file takes effect without restart'],
        ['data/.secret_key (file)', 'otherwise, generated on first use', 'Fernet.generate_key(); chmod 0600 (Linux); read again on every use — deliberately uncached'],
    ],
    widths=[44 * mm, 30 * mm, 100 * mm]))
space(1)
story.append(P('A malformed master key raises rather than degrading to plaintext — storing a '
               'secret unencrypted because the key was mistyped is the one outcome worse than '
               'refusing the write. A decrypt that fails (rotated or lost key) degrades to '
               '"no provider configured":'))
space(1)
story.append(alg('Algorithm 12 — secret store', [
    'encrypt(v):',
    '1  if v is empty: return ""',
    '2  if is_encrypted(v): return v                // never double-encrypt',
    '3  return "enc:v1:" + Fernet(load_key()).encrypt(v)',
    '',
    'decrypt(v):',
    '4  if v is empty: return ""                    // nothing stored',
    '5  if not is_encrypted(v): return v            // legacy plaintext passes through',
    '6  try:    return Fernet(load_key()).decrypt(v[7:])   // v[7:] drops "enc:v1:"',
    '7  except (InvalidToken, ValueError): return ""    // key lost → provider looks unset',
]))
space(2)

sub_no('10.3&nbsp;&nbsp;Proxy environment composition')
story.append(P('When a proxy is configured with a username and password, the two secrets are '
               'percent-encoded into the authority component of the URL and the result is '
               'exported to the scanner subprocess through all four spellings of the proxy '
               'variables:'))
eqn('10.2', 'URL&#8242;&nbsp;=&nbsp;scheme&nbsp;://&nbsp;<i>q</i>(user)&nbsp;:&nbsp;<i>q</i>(pass)'
            '&nbsp;@&nbsp;remainder,&nbsp;&nbsp;'
            'env&nbsp;←&nbsp;{HTTP_PROXY,&nbsp;HTTPS_PROXY,&nbsp;http_proxy,&nbsp;https_proxy}&nbsp;=&nbsp;URL&#8242;')
space(1)
story.append(P('with <i>q</i> the RFC&nbsp;3986 percent-encoding of each segment, so a password '
               'containing ' + c(':') + ' or ' + c('@') + ' cannot corrupt the URL authority.'))

# =========================================================================
# CHAPTER 11 — Database migration and integrity
# =========================================================================
chapter_no(11, 'Database Migration &amp; Integrity')
story.append(P('Source: ' + c('backend/database.py') + '. SQLAlchemy ' + c('create_all') +
               ' only creates missing tables, so columns added after the first release are '
               'applied by an idempotent ALTER pass at import time.'))

sub_no('11.1&nbsp;&nbsp;Idempotent column migration')
space(1)
story.append(P('For each table, the columns already present are read once and only missing '
               'columns are added — running the migration a second time is a no-op because the '
               '"existing" set already contains every column:'))
eqn('11.1', '∀&nbsp;table&nbsp;<i>T</i>,&nbsp;∀&nbsp;declared&nbsp;column&nbsp;<i>c</i>:&nbsp;'
            'add&nbsp;<i>c</i>&nbsp;&#8660;&nbsp;<i>c</i>&nbsp;&#8713;&nbsp;'
            'existing(<i>T</i>)&nbsp;&nbsp;&nbsp;'
            '(ALTER&nbsp;TABLE&nbsp;<i>T</i>&nbsp;ADD&nbsp;COLUMN&nbsp;<i>c</i>)')
space(2)

sub_no('11.2&nbsp;&nbsp;Encrypt-once startup migration')
story.append(P('On startup any credential still stored as plaintext (written before encryption '
               'existed) is encrypted in place; legacy baked-in endpoint/model defaults are '
               'cleared only when no key was ever saved, so the operator is asked for their own '
               'provider rather than silently inheriting a third-party endpoint nobody chose.'))

sub_no('11.3&nbsp;&nbsp;Uniqueness repair')
story.append(P('The execution uniqueness constraint is created only when no duplicates exist, '
               'detected with a grouped count — if any (assessment_id, step_index) group has '
               'more than one row the constraint is left for manual reconciliation instead of '
               'failing the migration:'))

# =========================================================================
# CHAPTER 12 — Constants and bounds summary
# =========================================================================
chapter_no(12, 'Tunable Constants &amp; Bounds — Summary')
space(1)
story.append(md_table(
    ['Constant', 'Value', 'Module', 'What it bounds'],
    [
        [c('MAX_PLAN_STEPS'), '50', 'planner / main', 'maximum steps in a plan'],
        [c('MAX_PLAN_FIELD_CHARS'), '100 / 4000 / 2000', 'main', 'tool / command / reason length per step'],
        [c('MAX_ANALYSIS_OUTPUT_CHARS'), '120,000', 'analyzer', 'per-stream chars in an AI prompt'],
        [c('MAX_ANALYSIS_TOTAL_CHARS'), '400,000', 'analyzer', 'shared AI prompt budget'],
        [c('MAX_FINDINGS'), '200', 'analyzer', 'findings kept after analysis'],
        [c('MAX_FINDING_TEXT_CHARS'), '20,000', 'analyzer', 'prose field length and merge cap'],
        [c('DEFAULT_ASSET_CRITICALITY'), '70', 'analyzer', 'κ when the target declares none'],
        [c('EXECUTION_TIMEOUT_SECONDS'), '360', 'executor', 'per-command run cap'],
        [c('MAX_OUTPUT_CHARS / _BYTES'), '200,000 / 800,000', 'executor', 'persisted per-stream cap'],
        [c('LIVE_BUFFER_CHARS'), '200,000', 'executor', 'in-memory live-terminal window'],
        [c('READ_CHUNK_BYTES'), '65,536', 'executor / main', 'stream and upload chunk size'],
        [c('EXECUTION_STALE_AFTER'), '420 s', 'main', 'staleness = timeout + 60 s'],
        [c('MAX_SUBNET_ADDRESSES'), '256', 'models', 'largest CIDR target (a /24)'],
        [c('MAX_AUTHORIZED_SCOPES / _CHARS'), '50 / 255', 'models', 'scope list size and width'],
        [c('MAX_RESTRICTED_TOOLS / _CHARS'), '20 / 64', 'models', 'letter tool restrictions'],
        [c('MAX_REQUIREMENT_BYTES'), '5 MiB', 'main', 'uploaded file size'],
        [c('MAX_BRIEF_ITEMS / _CHARS'), '100 / 20,000', 'models', 'engagement brief bounds'],
        [c('objective / requirements'), '1000 / 30,000 chars', 'models', 'prompt field width'],
        [c('SEVERITY / SCORE'), '25 · 50 · 75 · 100', 'analyzer', 'σ base scores'],
        [c('SECRET_PREFIX'), 'enc:v1:', 'secret_store', 'encrypted-value marker'],
    ],
    widths=[62 * mm, 40 * mm, 26 * mm, 46 * mm]))
space(2)
story.append(note_para('These are the constants as shipped; every one is tunable at the module '
                       'top of the file named in the third column. Two interact: the /24 sweep '
                       'budget (§6.3) and the 360 s executor cap are sized together so a full '
                       'default-plan run on a /24 finishes inside the window.', bg=note_bg))
space(3)

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
    canvas.setFont(BODY_FONT, 7.4)
    canvas.setFillColor(colors.HexColor('#666666'))
    canvas.drawString(18 * mm, 287.5 * mm,
                      'Red Teaming Framework — Backend Algorithms & Formulae Reference')
    canvas.drawRightString(192 * mm, 287.5 * mm, 'Confidential')
    canvas.setStrokeColor(rule_grey)
    canvas.setLineWidth(0.75)
    canvas.line(18 * mm, 14 * mm, 192 * mm, 14 * mm)
    canvas.setFont(BODY_FONT, 7.4)
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
