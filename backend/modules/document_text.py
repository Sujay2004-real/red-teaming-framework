"""Bounded extraction in a disposable process, including Word table cells."""
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

MAX_TEXT = 30000
MAX_PAGES = 100
MAX_EXPANDED = 25 * 1024 * 1024


def extract(suffix, content):
    if suffix in {'.txt', '.md'}:
        return content.decode('utf-8', errors='replace').strip()[:MAX_TEXT + 1]
    result = subprocess.run([sys.executable, str(Path(__file__).resolve()), suffix],
                            input=content, capture_output=True, timeout=20, check=False)
    if result.returncode:
        raise ValueError('Document is invalid, encrypted, or exceeds extraction limits (100 pages / 25 MB expanded)')
    return json.loads(result.stdout)


def _extract(suffix, content):
    if suffix == '.pdf':
        from pypdf import PdfReader
        document = PdfReader(io.BytesIO(content))
        if document.is_encrypted or len(document.pages) > MAX_PAGES:
            raise ValueError('Encrypted PDF or page limit exceeded')
        chunks, length = [], 0
        for page in document.pages:
            text = page.extract_text() or ''
            chunks.append(text[:MAX_TEXT + 1 - length])
            length += len(chunks[-1]) + 1
            if length > MAX_TEXT:
                break
        return '\n'.join(chunks).strip()[:MAX_TEXT + 1]
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        members = archive.infolist()
        if len(members) > 1000 or sum(item.file_size for item in members) > MAX_EXPANDED:
            raise ValueError('Expanded document exceeds limit')
        if any(item.file_size > 1000 * max(1, item.compress_size) for item in members):
            raise ValueError('Suspicious compression ratio')
    from docx import Document
    from docx.table import Table
    document = Document(io.BytesIO(content))
    chunks, length = [], 0
    for block in document.iter_inner_content():
        text = '\n'.join(' | '.join(cell.text for cell in row.cells) for row in block.rows) if isinstance(block, Table) else block.text
        chunks.append(text[:MAX_TEXT + 1 - length])
        length += len(chunks[-1]) + 1
        if length > MAX_TEXT:
            break
    return '\n'.join(chunks).strip()[:MAX_TEXT + 1]


if __name__ == '__main__':
    print(json.dumps(_extract(sys.argv[1], sys.stdin.buffer.read(5 * 1024 * 1024 + 1))))
