# -*- coding: utf-8 -*-
"""Compile docs/backend_technical_reference.md into a styled A4 PDF.

Derives the PDF from the Markdown source so the two cannot drift: this script
handles the subset of Markdown the reference uses (ATX headings, paragraphs,
bullet and numbered lists, fenced code blocks, pipe tables, horizontal rules,
inline `code`). Styling mirrors make_client_request_pdf.py (brand navy/blue,
header and footer rules, info/grid table helpers).

Run from the project root:
    .venv\\Scripts\\python.exe make_backend_reference_pdf.py
"""
import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether,
                                 PageTemplate, Paragraph, Spacer, Table,
                                 TableStyle)

SOURCE = Path(__file__).with_name('docs') / 'backend_technical_reference.md'
OUT = SOURCE.with_suffix('.pdf')

styles = getSampleStyleSheet()

brand_navy = colors.HexColor('#1F3864')
brand_blue = colors.HexColor('#2E74B5')
brand_light = colors.HexColor('#DEEAF6')
rule_grey = colors.HexColor('#BFBFBF')
code_bg = colors.HexColor('#101828')

h1 = ParagraphStyle('H1x', parent=styles['Heading1'], fontName='Helvetica-Bold',
                    fontSize=18, leading=22, textColor=brand_navy, spaceAfter=8)
h2 = ParagraphStyle('H2x', parent=styles['Heading2'], fontName='Helvetica-Bold',
                    fontSize=13, leading=16, textColor=brand_blue, spaceBefore=14,
                    spaceAfter=6)
h3 = ParagraphStyle('H3x', parent=styles['Heading3'], fontName='Helvetica-Bold',
                    fontSize=11, leading=14, textColor=brand_navy, spaceBefore=10,
                    spaceAfter=4)
body = ParagraphStyle('Bodyx', parent=styles['BodyText'], fontName='Helvetica',
                      fontSize=9, leading=13, alignment=TA_JUSTIFY, spaceAfter=6)
bullet = ParagraphStyle('Bulletx', parent=body, leftIndent=14, bulletIndent=4,
                        spaceAfter=3)
code = ParagraphStyle('Codex', fontName='Courier', fontSize=7.5, leading=10,
                      textColor=colors.HexColor('#EAECF0'), spaceAfter=6)
cell = ParagraphStyle('Cellx', parent=body, fontSize=8, leading=11,
                      alignment=0, spaceAfter=0)
cellh = ParagraphStyle('CellHx', parent=cell, fontName='Helvetica-Bold',
                       textColor=colors.white)

# ---------------------------------------------------------------- inline md
BOLD = re.compile(r'\*\*(.+?)\*\*')
ITALIC = re.compile(r'(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)')
CODESPAN = re.compile(r'`([^`]+)`')


def md_inline(text):
    text = (text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            .replace('&lt;br/&gt;', '<br/>'))
    # Code spans are protected first: a '*' inside `--output*` is literal text,
    # not emphasis, and Markdown itself never formats inside inline code.
    saved = []

    def stash(match):
        saved.append(f'<font face="Courier" size="8">{match.group(1)}</font>')
        return f'\x00{len(saved) - 1}\x00'

    text = CODESPAN.sub(stash, text)
    text = BOLD.sub(r'<b>\1</b>', text)
    text = ITALIC.sub(r'<i>\1</i>', text)
    return re.sub(r'\x00(\d+)\x00', lambda m: saved[int(m.group(1))], text)


def code_block(lines):
    text = '<br/>'.join(line.replace('&', '&amp;').replace('<', '&lt;')
                        .replace('>', '&gt;').replace(' ', '&nbsp;') for line in lines)
    table = Table([[Paragraph(text, code)]], colWidths=[174 * mm])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), code_bg),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    return table


def md_table(rows):
    header = [Paragraph(md_inline(cell_text), cellh) for cell_text in rows[0]]
    data = [header]
    for row in rows[2:]:
        data.append([Paragraph(md_inline(cell_text), cell) for cell_text in row])
    table = Table(data, colWidths=[174 * mm / len(rows[0])] * len(rows[0]),
                  hAlign='LEFT', repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), brand_navy),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F2F6FB')]),
        ('GRID', (0, 0), (-1, -1), 0.5, rule_grey),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    return table


def split_table_row(line):
    return [part.strip() for part in line.strip().strip('|').split('|')]


def on_page(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(brand_navy)
    canvas.setLineWidth(1.5)
    canvas.line(18 * mm, 285 * mm, 192 * mm, 285 * mm)
    canvas.setFont('Helvetica', 7.5)
    canvas.setFillColor(colors.HexColor('#666666'))
    canvas.drawString(18 * mm, 287.5 * mm, 'Red Teaming Framework — Backend Technical Reference')
    canvas.drawRightString(192 * mm, 287.5 * mm, 'Confidential')
    canvas.setStrokeColor(rule_grey)
    canvas.setLineWidth(0.75)
    canvas.line(18 * mm, 14 * mm, 192 * mm, 14 * mm)
    canvas.drawString(18 * mm, 10.5 * mm, 'Semi-Autonomous Red Teaming Framework — technical documentation')
    canvas.drawRightString(192 * mm, 10.5 * mm, f'Page {doc.page}')
    canvas.restoreState()


doc = BaseDocTemplate(str(OUT), pagesize=A4, leftMargin=18 * mm,
                      rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=18 * mm,
                      title='Red Teaming Framework — Backend Technical Reference',
                      author='EPCET Security Research Laboratory')
frame = Frame(18 * mm, 18 * mm, 174 * mm, 264 * mm, id='main')
doc.addPageTemplates([PageTemplate(id='page', frames=[frame], onPage=on_page)])

story = []
lines = SOURCE.read_text(encoding='utf-8').splitlines()
index = 0
in_code, code_lines = False, []

while index < len(lines):
    line = lines[index]

    if line.strip().startswith('```'):
        if in_code:
            story.append(code_block(code_lines))
            story.append(Spacer(1, 4))
            code_lines = []
        in_code = not in_code
        index += 1
        continue
    if in_code:
        code_lines.append(line)
        index += 1
        continue

    stripped = line.strip()
    if not stripped:
        index += 1
        continue
    if stripped == '---':
        story.append(Spacer(1, 8))
        index += 1
        continue

    if stripped.startswith('#'):
        level = len(stripped) - len(stripped.lstrip('#'))
        text = stripped.lstrip('#').strip()
        if level == 1:
            story.append(Paragraph(md_inline(text), h1))
        elif level == 2:
            story.append(Paragraph(md_inline(text), h2))
        else:
            story.append(Paragraph(md_inline(text), h3))
        index += 1
        continue

    if stripped.startswith('|'):
        rows = []
        while index < len(lines) and lines[index].strip().startswith('|'):
            rows.append(split_table_row(lines[index]))
            index += 1
        if len(rows) >= 2:
            story.append(md_table(rows))
            story.append(Spacer(1, 6))
        continue

    bullet_match = re.match(r'^(\s*)[-*]\s+(.*)$', line)
    if bullet_match:
        indent = len(bullet_match.group(1))
        style = ParagraphStyle('b2', parent=bullet, leftIndent=14 + indent)
        story.append(Paragraph(md_inline(bullet_match.group(2)), style,
                               bulletText='•'))
        index += 1
        continue

    numbered_match = re.match(r'^(\d+)\.\s+(.*)$', stripped)
    if numbered_match:
        story.append(Paragraph(md_inline(numbered_match.group(2)), bullet,
                               bulletText=numbered_match.group(1) + '.'))
        index += 1
        continue

    # Paragraph: merge soft-wrapped continuation lines.
    paragraph = [stripped]
    index += 1
    while index < len(lines):
        nxt = lines[index].strip()
        if (not nxt or nxt.startswith(('#', '|', '```', '---'))
                or re.match(r'^\s*[-*]\s+', nxt) or re.match(r'^\d+\.\s+', nxt)):
            break
        paragraph.append(nxt)
        index += 1
    story.append(Paragraph(md_inline(' '.join(paragraph)), body))

doc.build(story)
print('Wrote', OUT)
