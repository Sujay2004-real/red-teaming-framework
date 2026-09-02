"""Turn a client engagement letter into the structured data the agents use.

A client request PDF arrives as free text once extracted, but every part of
the framework needs the same facts from it: which hosts are in scope, how
critical the client declares each one to be, and which tools the client has
ruled out for a particular target. This module recovers those facts
deterministically, so what the agent "knows" about the engagement never
depends on an AI provider being configured.

The heuristics are label-driven first (RFP-style documents label their own
tables) with regex fallbacks (host:port patterns, criticality numbers), so a
letter laid out differently still yields its targets even when only some
fields are recoverable.
"""

import re

# Tools the framework can actually run. A restriction naming anything else is
# already refused by the policy engine, so it needs no per-target rule.
KNOWN_TOOLS = ('nmap', 'traceroute', 'dig', 'nslookup', 'curl', 'whatweb', 'sslscan', 'nuclei')

# reportlab-style page furniture repeats on every page between the sections;
# reading it as content would splice footers into the parsed brief.
FURNITURE_PATTERNS = (
    re.compile(r'— Confidential$'),
    re.compile(r'^Engagement [A-Z0-9/]+$'),
    re.compile(r'^Page \d+$'),
    re.compile(r'^Request for Security Assessment Services — Confidential$'),
)

# host[:port], host must start alphanumerically so a bare ':3000' or a
# sentence fragment never matches.
HOST_PORT_RE = re.compile(r'\b([A-Za-z0-9][A-Za-z0-9._\-]*:\d{1,5})\b')
CRITICALITY_RE = re.compile(r'^(\d{1,3})\b')
# '4.1 Service discovery: ...' style objective items.
NUMBERED_ITEM_RE = re.compile(r'^(\d+\.\d+)\s+(.*)$')
# '5.3 Technique restrictions ...' style section headings.
SECTION_HEADING_RE = re.compile(r'^\d+(\.\d+)?\.?\s+[A-Z]')
# reportlab's bullet glyph extracts through pypdf as '\x7f' (DEL) on some
# builds and as the literal bullet characters on others; all spellings must
# start a list item or the letter's bulleted sections parse as prose and
# every objective disappears.
BULLET_RE = re.compile(r'^[\u2022\u00b7\u25aa*\x7f]\s*')

# Table row labels an RFP uses for one in-scope asset, mapped to target
# fields. Labels are matched case-insensitively by prefix.
TARGET_LABELS = {
    'system name': 'name',
    'authorized target address': 'address',
    'authorized scope identifiers': 'scopes',
    'asset criticality': 'criticality',
    'assessment type': 'assessment_type',
    'technology': 'technology',
    'environment': 'environment',
}

DOC_LABELS = {
    'engagement reference': 'engagement_ref',
    'test window': 'test_window',
}


def _clean_lines(text):
    lines = []
    for raw in (text or '').splitlines():
        line = raw.strip()
        if not line or any(pattern.search(line) for pattern in FURNITURE_PATTERNS):
            continue
        lines.append(line)
    return lines


def _strip_bullet(line):
    return BULLET_RE.sub('', line).strip()


def _ends_sentence(text):
    """True when a line closes a sentence, so the next line is a new item.

    PDF extraction breaks a wrapped bullet across lines, and whether the
    bullet glyph survives extraction varies by producer, so continuation is
    detected from punctuation instead: a line that does not end a sentence is
    continued by whatever follows it.
    """
    return bool(text) and text[-1] in '.!?)]'


def _match_label(line, labels):
    """Return the field key when the line is a known table label.

    Labels sit in the left table column, so a match must be the whole line
    (allowing the parenthetical some letters add, e.g. 'Asset criticality
    (client-declared, 0-100)'), not just a prefix of a longer sentence -
    otherwise every sentence starting 'System name...' would be read as a
    table row.
    """
    lowered = line.lower()
    for label, field in labels.items():
        if lowered == label or lowered.startswith(label + ' ('):
            return field
    return None


def _parse_scopes(value):
    scopes = []
    for token in value.split(','):
        token = token.strip()
        if HOST_PORT_RE.fullmatch(token) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._\-]*', token):
            if token not in scopes:
                scopes.append(token)
    return scopes


def _parse_targets(lines):
    """Recover target records from label/value table lines.

    Handles the two layouts pypdf produces from two-column tables: rows in
    order ('System name', then its value on the next line) and any missed
    rows via a host:port scan, so an address the label pass misses still
    becomes a target.
    """
    targets = []
    current = None
    for index, line in enumerate(lines):
        field = _match_label(line, TARGET_LABELS)
        value = lines[index + 1] if index + 1 < len(lines) else ''
        if field == 'name':
            current = {'name': value, 'address': '', 'scopes': [], 'criticality': None,
                       'assessment_type': '', 'technology': '', 'environment': '',
                       'restricted_tools': [], 'notes': []}
            targets.append(current)
            continue
        if field and current is not None:
            if field == 'criticality':
                match = CRITICALITY_RE.match(value)
                current['criticality'] = int(match.group(1)) if match else None
            elif field == 'address':
                # Values carry qualifiers ('juice-shop:3000 (assessment-lab
                # network)'); only the host[:port] is an address.
                match = HOST_PORT_RE.search(value)
                current['address'] = match.group(1) if match else value
            elif field == 'scopes':
                current['scopes'] = _parse_scopes(value)
            else:
                current[field] = value

    # Fallback: any host:port line not already captured becomes a target, so
    # a differently laid-out letter still yields its in-scope assets.
    known_addresses = {target['address'].split(' ')[0] for target in targets if target['address']}
    for line in lines:
        for match in HOST_PORT_RE.finditer(line):
            address = match.group(1)
            if address not in known_addresses:
                host = address.split(':', 1)[0]
                targets.append({'name': host, 'address': address, 'scopes': [address],
                                'criticality': None, 'assessment_type': '', 'technology': '',
                                'environment': '', 'restricted_tools': [], 'notes': []})
                known_addresses.add(address)
    return targets


def _parse_doc_fields(lines, text):
    fields = {}
    for index, line in enumerate(lines):
        field = _match_label(line, DOC_LABELS)
        if field and field not in fields and index + 1 < len(lines):
            fields[field] = lines[index + 1]
    if 'engagement_ref' not in fields:
        match = re.search(r'\b[A-Z]{2,}[/-][A-Z]{2,}[/-]\d{4}[/-]\d+\b', text or '')
        if match:
            fields['engagement_ref'] = match.group(0)
    if 'test_window' not in fields:
        match = re.search(r'\d{1,2} \w+ \d{4}\s+to\s+\d{1,2} \w+ \d{4}[^.\n]*', text or '')
        if match:
            fields['test_window'] = match.group(0).strip()
    return fields


def _parse_client(lines):
    """First real line of the letter is the client's masthead in practice."""
    for line in lines[:5]:
        if re.match(r'^[A-Za-z0-9][\w&.,\'() ]+$', line) and len(line) > 3:
            return line
    return ''


def _parse_contact(text):
    match = re.search(r'escalation contact[^:]*:\s*([^\n]+)', text or '', re.IGNORECASE)
    if not match:
        return ''
    # 'Name — Role, phone' up to the sentence end; strip a trailing phone.
    contact = re.split(r'[.,]', match.group(1).strip())[0].strip(' —-')
    return contact


def _sections(lines):
    """Split the letter into (heading, body lines) at numbered headings."""
    sections, heading, body = [], '', []
    for line in lines:
        if SECTION_HEADING_RE.match(line):
            if heading or body:
                sections.append((heading, body))
            heading, body = line, []
        elif heading:
            body.append(line)
    if heading or body:
        sections.append((heading, body))
    return sections


def _sentences(lines):
    text = ' '.join(lines)
    return [sentence.strip() for sentence in re.split(r'(?<=[.!?])\s+', text) if sentence.strip()]


def _mentioned_targets(section_text, targets):
    """Targets whose host or name appears in a section's text."""
    mentioned = []
    for target in targets:
        host = target['address'].split(':', 1)[0].lower()
        name_words = [word for word in re.split(r'[^A-Za-z0-9]+', target.get('name') or '') if len(word) > 3]
        if host and re.search(r'\b' + re.escape(host) + r'\b', section_text, re.IGNORECASE):
            mentioned.append(target)
        elif any(re.search(r'\b' + re.escape(word) + r'\b', section_text, re.IGNORECASE) for word in name_words):
            mentioned.append(target)
    return mentioned


def _parse_restrictions(lines, targets):
    """Per-target tool restrictions from the rules-of-engagement prose.

    Two sentence shapes carry a restriction:
      allow-list - 'only service discovery (nmap ...) and HTTP header
        inspection (curl, whatweb) are authorized against it': every known
        tool NOT named becomes restricted for the targets the section names.
      deny-list - 'nuclei ... must not be run against the DVWA lab'.
    """
    for heading, body in _sections(lines):
        section_text = ' '.join([heading] + body)
        mentioned = _mentioned_targets(section_text, targets)
        if not mentioned:
            continue
        for sentence in _sentences(body):
            tools_in_sentence = {tool for tool in KNOWN_TOOLS if re.search(r'\b' + tool + r'\b', sentence, re.IGNORECASE)}
            if not tools_in_sentence:
                continue
            if re.search(r'\bonly\b.*\bauthorized against\b', sentence, re.IGNORECASE):
                for target in mentioned:
                    target['restricted_tools'] = sorted(
                        {tool for tool in KNOWN_TOOLS if tool not in tools_in_sentence} | set(target['restricted_tools']))
            elif re.search(r'\bmust not be (run|used|executed)\b.*\bagainst\b', sentence, re.IGNORECASE):
                for target in mentioned:
                    target['restricted_tools'] = sorted(set(target['restricted_tools']) | tools_in_sentence)
    return targets


def _parse_objectives(lines):
    """Numbered items like '4.1 Service discovery: identify ...'.

    The colon filters out same-shaped section headings ('3.1 Primary asset —
    ...'), which number their subsections but never title-and-describe them.
    Wrapped continuations are merged back into their item.
    """
    objectives = []
    for line in lines:
        item = _strip_bullet(line)
        match = NUMBERED_ITEM_RE.match(item)
        if match and ':' in match.group(2):
            objectives.append(match.group(2).strip())
        elif objectives and not _ends_sentence(objectives[-1]) and not SECTION_HEADING_RE.match(line) and not BULLET_RE.match(line):
            objectives[-1] += ' ' + item
    return objectives


def _parse_bullet_block(lines, start_pattern, stop_patterns=()):
    """Collect bullet lines after a heading until the next section heading.

    Items start only on bullet lines: the section's own intro sentence is not
    an item, however the parser's start pattern matches it.
    """
    items, active = [], False
    for line in lines:
        if active and (SECTION_HEADING_RE.match(line) or any(p.search(line) for p in stop_patterns)):
            break
        if start_pattern.search(line):
            active = True
            continue
        if active:
            # A non-bullet line only continues the previous item; it never
            # starts one. This is what keeps the "The following are strictly
            # out of scope. Any traffic..." intro out of the item list.
            if not BULLET_RE.match(line):
                if items and not _ends_sentence(items[-1]):
                    items[-1] += ' ' + _strip_bullet(line)
                continue
            item = _strip_bullet(line)
            if not item:
                continue
            if not items or _ends_sentence(items[-1]):
                items.append(item)
            else:
                items[-1] += ' ' + item
    return items


def parse_engagement(text):
    """Return the structured engagement brief the UI and agents consume."""
    lines = _clean_lines(text)
    # Bulleted table rows are still label/value pairs, so strip the bullet
    # marker before the label matcher sees them; a list, because the fallback
    # pass below iterates the same lines a second time.
    unbulleted = [_strip_bullet(line) if BULLET_RE.match(line) else line for line in lines]
    targets = _parse_targets(unbulleted)
    targets = _parse_restrictions(lines, targets)
    fields = _parse_doc_fields(lines, text)
    objectives = _parse_objectives(lines)
    out_of_scope = _parse_bullet_block(lines, re.compile(r'out of scope', re.IGNORECASE))
    prohibited = _parse_bullet_block(lines, re.compile(r'prohibited techniques', re.IGNORECASE))
    return {
        'client_name': _parse_client(lines),
        'engagement_ref': fields.get('engagement_ref', ''),
        'test_window': fields.get('test_window', ''),
        'escalation_contact': _parse_contact(text),
        'targets': targets,
        'objectives': objectives,
        'out_of_scope': out_of_scope,
        'prohibited': prohibited,
    }
