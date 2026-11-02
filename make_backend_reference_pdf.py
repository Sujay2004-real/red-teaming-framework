"""Render the project's Markdown backend references with ReportLab.

Run from the repository root with ReportLab installed:
    python make_backend_reference_pdf.py

The other reference generators call build_pdf with their Markdown source.
Importing this module does not write files.
"""
from html import escape
from pathlib import Path
import re
import textwrap
from urllib.parse import quote, urljoin

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, KeepTogether, LongTable, PageTemplate, Paragraph, Spacer, TableStyle,
)

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "docs" / "backend_technical_reference.md"
OUT = SOURCE.with_suffix(".pdf")
WIDTH = 174 * mm
NAVY = colors.HexColor("#193853")
BLUE = colors.HexColor("#176b80")
PALE = colors.HexColor("#edf4f7")
GREY = colors.HexColor("#cad6df")
GITHUB = "https://github.com/Sujay2004-real/red-teaming-framework/blob/main/"
BASE_STYLES = getSampleStyleSheet()


def style_set():
    body = ParagraphStyle(
        "ReferenceBody", parent=BASE_STYLES["BodyText"], fontName="Helvetica",
        fontSize=9.4, leading=13.4, textColor=NAVY, spaceAfter=7,
        splitLongWords=True,
    )
    return {
        "body": body,
        "h1": ParagraphStyle("ReferenceTitle", parent=body,
                            fontName="Helvetica-Bold", fontSize=23, leading=27,
                            textColor=NAVY, spaceAfter=16, keepWithNext=True),
        "h2": ParagraphStyle("ReferenceSection", parent=body,
                            fontName="Helvetica-Bold", fontSize=13, leading=17,
                            textColor=BLUE, spaceBefore=14, spaceAfter=7,
                            keepWithNext=True),
        "h3": ParagraphStyle("ReferenceSubsection", parent=body,
                            fontName="Helvetica-Bold", fontSize=10.5, leading=14,
                            spaceBefore=10, keepWithNext=True),
        "bullet": ParagraphStyle("ReferenceBullet", parent=body,
                                leftIndent=13, bulletIndent=2, spaceAfter=5),
        "code": ParagraphStyle("ReferenceCode", fontName="Courier",
                              fontSize=7.6, leading=10.5, textColor=NAVY),
        "cell": ParagraphStyle("ReferenceCell", parent=body,
                              fontSize=8.5, leading=11.5, spaceAfter=0),
        "head": ParagraphStyle("ReferenceCellHead", parent=body,
                              fontName="Helvetica-Bold", textColor=colors.white,
                              fontSize=8.5, leading=11.5, spaceAfter=0),
    }


def inline_markdown(value, source):
    # Protect code and links so formatting cannot interpret their punctuation.
    saved = []

    def stash(rendered):
        saved.append(rendered)
        return f"\x00{len(saved) - 1}\x00"

    value = re.sub(
        r"\x60([^\x60]+)\x60",
        lambda m: stash(f'<font face="Courier" size="8">{escape(m[1])}</font>'),
        value,
    )

    def link(match):
        label, target = match[1], match[2]
        if not re.match(r"https?://", target):
            relative = source.relative_to(ROOT).as_posix()
            target = urljoin(GITHUB + quote(relative), quote(target, safe="/:#?=&%"))
        return stash(f'<link href="{escape(target, quote=True)}" color="#176b80">'
                     f'{escape(label)}</link>')

    value = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", link, value)
    value = escape(value)
    value = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", value)
    value = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"<i>\1</i>", value)
    # Links may contain a previously protected code span in their label.
    for _ in range(2):
        value = re.sub(r"\x00(\d+)\x00", lambda m: saved[int(m[1])], value)
    return value


def code_block(lines, styles):
    rows = []
    for line in lines or [""]:
        for part in textwrap.wrap(
            line.expandtabs(4), width=98, replace_whitespace=False,
            drop_whitespace=False, break_long_words=True, break_on_hyphens=False,
        ) or [""]:
            text = escape(part).replace(" ", "&nbsp;") or "&#160;"
            rows.append([Paragraph(text, styles["code"])])
    table = LongTable(rows, colWidths=[WIDTH], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PALE),
        ("BOX", (0, 0), (-1, -1), 0.5, GREY),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, 0), 7),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 7),
    ]))
    return KeepTogether([table]) if len(rows) <= 30 else table


def markdown_table(rows, source, styles):
    columns = len(rows[0])
    if any(len(row) != columns for row in rows):
        raise ValueError(f"Unequal table columns in {source}")
    data = [
        [Paragraph(inline_markdown(value, source), styles["head" if index == 0 else "cell"])
         for value in row]
        for index, row in enumerate([rows[0], *rows[2:]])
    ]
    # Most references pair a short label/module with a longer explanation.
    fractions = [0.42, 0.58] if columns == 2 else [1 / columns] * columns
    table = LongTable(data, colWidths=[WIDTH * f for f in fractions],
                      hAlign="LEFT", repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]),
        ("GRID", (0, 0), (-1, -1), 0.4, GREY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def markdown_story(source, styles):
    lines = source.read_text(encoding="utf-8").splitlines()
    story, index = [], 0

    def block_start(line):
        return bool(re.match(r"^\s*(#|\||\x60\x60\x60|---\s*$|[-*]\s+|\d+\.\s+)", line))

    while index < len(lines):
        line = lines[index].strip()
        index += 1
        if not line:
            continue
        if line.startswith("\x60\x60\x60"):
            code_lines = []
            while index < len(lines) and not lines[index].strip().startswith("\x60\x60\x60"):
                code_lines.append(lines[index])
                index += 1
            if index == len(lines):
                raise ValueError(f"Unclosed code fence in {source}")
            index += 1
            story.extend([code_block(code_lines, styles), Spacer(1, 8)])
            continue
        if line.startswith("|"):
            rows = [line.strip("|").split("|")]
            while index < len(lines) and lines[index].strip().startswith("|"):
                rows.append(lines[index].strip().strip("|").split("|"))
                index += 1
            rows = [[value.strip() for value in row] for row in rows]
            story.extend([markdown_table(rows, source, styles), Spacer(1, 8)])
            continue
        if line == "---":
            story.append(Spacer(1, 8))
            continue
        heading = re.match(r"^(#{1,6})\s+(.*)$", line)
        if heading:
            level = min(3, len(heading[1]))
            story.append(Paragraph(inline_markdown(heading[2], source), styles[f"h{level}"]))
            continue
        item = re.match(r"^(?:([-*])|(\d+)\.)\s+(.*)$", line)
        text = item[3] if item else line
        while index < len(lines) and lines[index].strip() and not block_start(lines[index]):
            text += " " + lines[index].strip()
            index += 1
        if item:
            marker = "\u2022" if item[1] else item[2] + "."
            story.append(Paragraph(inline_markdown(text, source),
                                   styles["bullet"], bulletText=marker))
        else:
            style = styles["body"]
            if text.startswith(("Source:", "Sources:")):
                style = ParagraphStyle("ReferenceSource", parent=style, keepWithNext=True)
            story.append(Paragraph(inline_markdown(text, source), style))
    return story


def build_pdf(source=SOURCE, output=None, title="Backend technical reference"):
    source = Path(source).resolve()
    output = Path(output) if output else source.with_suffix(".pdf")
    output.parent.mkdir(parents=True, exist_ok=True)
    styles = style_set()

    def on_page(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(BLUE)
        canvas.setLineWidth(1.1)
        canvas.line(18 * mm, 282 * mm, 192 * mm, 282 * mm)
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(NAVY)
        canvas.drawString(18 * mm, 286 * mm, "RED TEAM CONTROL CENTER")
        canvas.drawRightString(192 * mm, 286 * mm, "Implementation reference")
        canvas.setStrokeColor(GREY)
        canvas.setLineWidth(0.5)
        canvas.line(18 * mm, 15 * mm, 192 * mm, 15 * mm)
        canvas.drawString(18 * mm, 10.5 * mm, title)
        canvas.drawRightString(192 * mm, 10.5 * mm, f"{doc.page}")
        canvas.restoreState()

    doc = BaseDocTemplate(
        str(output), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=21 * mm, bottomMargin=21 * mm,
        title=title, author="Red Team Control Center project",
        pageCompression=1, invariant=1,
    )
    frame = Frame(18 * mm, 21 * mm, WIDTH, 255 * mm, id="main",
                  leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    doc.addPageTemplates([PageTemplate(id="reference", frames=[frame], onPage=on_page)])
    doc.build(markdown_story(source, styles))
    print(f"Wrote {output}")
    return output


if __name__ == "__main__":
    build_pdf()
