"""No HTTP requests: parse MIME and admit only authenticated, allowlisted links."""
import email
import fnmatch
import re
from datetime import timezone
from email import policy
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import urlsplit


class Anchors(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.urls = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'a':
            self.urls.extend(value for key, value in attrs if key.lower() == 'href' and value)


def parse(raw):
    return email.message_from_bytes(raw, policy=policy.default)


def matches_header(msg, provider, rule):
    if len(msg.get_all('From', [])) != 1:
        return False
    addresses = getaddresses(msg.get_all('From', []))
    if len(addresses) != 1:
        return False
    sender = addresses[0][1].lower()
    if not any(fnmatch.fnmatchcase(sender, pattern.lower()) for pattern in rule.senders):
        return False
    if rule.subject_contains.lower() not in str(msg.get('Subject', '')).lower():
        return False
    # Proton emits one adjacent Authentication-Results header per method.
    # Read only the first contiguous block, never lower sender-supplied blocks.
    results = []
    for name, value in msg.raw_items():
        if name.lower() == 'authentication-results':
            results.append(value)
        elif results:
            break
    if not results:
        return False
    for result in results:
        parts = str(result).split(';')
        if parts[0].strip().lower() not in [v.lower() for v in provider.authserv_ids]:
            return False
        for part in parts[1:]:
            part = re.sub(r'\([^)]*\)', ' ', part)
            if re.match(r'\s*dkim=', part, re.I):
                # The first DKIM result wins: a forged later pass cannot
                # override the receiving server's fail/none result.
                domain = re.search(r'\bheader\.d=([a-zA-Z0-9.-]+)', part, re.I)
                return bool(re.match(r'\s*dkim=pass\b', part, re.I) and domain
                            and domain[1].lower() in [v.lower() for v in rule.dkim_domains])
    return False


def allowed_url(value, rule):
    if not isinstance(value, str) or len(value) > 4096 or any(c.isspace() or ord(c) < 32 for c in value) or '\\' in value:
        return False
    try:
        u = urlsplit(value)
        return (u.scheme == 'https' and u.hostname in [v.lower() for v in rule.url_hosts]
                and not u.username and not u.password and u.port in [None, 443]
                and u.path in rule.url_paths and bool(u.fragment or u.query))
    except ValueError:
        return False


def extract(raw, provider, rule):
    msg = parse(raw)
    if not matches_header(msg, provider, rule):
        return []
    links = []
    for part in body_parts(msg):
        kind = part.get_content_type()
        if kind not in ['text/plain', 'text/html']:
            continue
        try:
            body = part.get_content()
        except (LookupError, UnicodeError, ValueError):
            continue
        if kind == 'text/html':
            parser = Anchors()
            parser.feed(body)
            values = parser.urls
        else:
            values = re.findall(r'https://[^\s<>"\x27]+', body)
        for value in values:
            if allowed_url(value, rule) and value not in links:
                links.append(value)
    # Ambiguous messages fail closed rather than choosing an arbitrary token.
    return links if len(links) == 1 else []


def body_parts(part):
    # Skipping a parent in Message.walk() still visits its attached children.
    # Never consider attached/forwarded messages or their nested body parts.
    if part.get_content_disposition() == 'attachment' or part.get_content_type() == 'message/rfc822':
        return
    if part.is_multipart():
        for child in part.iter_parts():
            yield from body_parts(child)
    else:
        yield part


def sent_timestamp(msg):
    try:
        dt = parsedate_to_datetime(str(msg.get('Date', '')))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError, OverflowError):
        return None
