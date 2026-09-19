"""Conservative verification attribution grounded in executed scanner output.

Only sqlmap's explicit SQL-injection confirmations currently qualify. HTTP
success, version banners, and AI-authored text are not exploitation proof.
"""
import re
import shlex
from urllib.parse import parse_qs, parse_qsl, urlsplit


SQLMAP_CONFIRMATION_RE = re.compile(
    r"\b(?:(?:GET|POST|URI|Cookie|HTTP)\s+)?parameter\s+['\"](?P<param>[^'\"]+)['\"]"
    r"\s+is\s+(?:['\"](?P<technique>[^'\"]+)['\"]\s+injectable\b|vulnerable\b)",
    re.IGNORECASE)
UNCERTAIN_RE = re.compile(r'\b(?:not|might|may|could|possibly|heuristic|appears?)\b', re.IGNORECASE)


def confirmation_match(line):
    return None if UNCERTAIN_RE.search(line) else SQLMAP_CONFIRMATION_RE.search(line)


def command_endpoint(tool, command):
    """The one explicit primary URL; ambiguity leaves evidence unlocated."""
    try:
        tokens = shlex.split(command or '')
    except ValueError:
        return ''
    if not tokens or tokens[0] != tool:
        return ''
    urls = []
    if tool == 'sqlmap':
        for index, token in enumerate(tokens[1:], 1):
            if token in {'-u', '--url'} and index + 1 < len(tokens):
                urls.append(tokens[index + 1])
            elif token.startswith(('--url=', '-u=')):
                urls.append(token.split('=', 1)[1])
        # Secondary requests make output attribution ambiguous without a
        # richer scanner adapter. They must never verify the primary URL.
        if any(t.split('=', 1)[0] in {'--csrf-url', '--second-order'} for t in tokens):
            return ''
    return urls[0] if len(urls) == 1 else ''


def verification_key(finding):
    title = str(finding.get('title') or '')
    if not re.search(r'\bsql[ -]?injection\b|\bsqli\b', title, re.IGNORECASE):
        return None
    try:
        url = urlsplit(finding.get('endpoint') or '')
        if url.scheme not in {'http', 'https'} or not url.hostname or url.username or url.password:
            return None
        parameter = str(finding.get('parameter') or '').strip()
        if not parameter:
            query = parse_qs(url.query, keep_blank_values=True)
            if len(query) == 1:
                parameter = next(iter(query))
        if not parameter:
            return None
        # Parameter names and paths can be case sensitive. Normalize only
        # the host and default port; never merge HTTP with HTTPS.
        return ('sql_injection', url.scheme, url.hostname.lower().rstrip('.'),
                url.port or (443 if url.scheme == 'https' else 80),
                url.path or '/', parameter,
                tuple(sorted((key, value) for key, value in parse_qsl(url.query, keep_blank_values=True)
                             if key != parameter)))
    except (ValueError, TypeError):
        return None


def match_verification(recon_findings, exploitation_findings):
    """Match only explicit confirmations of the same endpoint and flaw."""
    confirmed = {}
    for finding in exploitation_findings:
        if finding.get('verification_outcome') != 'confirmed':
            continue
        key = verification_key(finding)
        evidence = str(finding.get('evidence') or '').strip()
        if key and evidence:
            confirmed.setdefault(key, []).append((finding, evidence))
    return [(finding, proof, evidence) for finding in recon_findings
            for proof, evidence in confirmed.get(verification_key(finding), [])]
