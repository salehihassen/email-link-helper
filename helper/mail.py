"""Persistent read-only IMAP sessions. Bodies are read only after header admission."""
import imaplib
import os
import re
import socket
import ssl
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from helper import matching

MAX_BYTES = 262144


class ReadOnly:
    def _command(self, name, *args):
        if name not in {'CAPABILITY', 'STARTTLS', 'LOGIN', 'EXAMINE', 'UID', 'LOGOUT', 'NOOP'}:
            raise ValueError('IMAP command outside read-only allowlist')
        if name == 'UID':
            if not args or args[0] not in {'SEARCH', 'FETCH'}:
                raise ValueError('Only UID SEARCH and FETCH are permitted')
            if args[0] == 'FETCH' and re.search(r'BODY\[|RFC822(?!\.SIZE)', str(args[-1]), re.I):
                raise ValueError('Only BODY.PEEK may read message content')
        return super()._command(name, *args)


class UnixIMAP(ReadOnly, imaplib.IMAP4):
    def _create_socket(self, timeout):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect(os.getenv('BRIDGE_SOCKET', '/mail/imap.sock'))
            return sock
        except BaseException:
            sock.close()
            raise


class TLSIMAP(ReadOnly, imaplib.IMAP4_SSL):
    pass


def password(provider, secret_dir):
    path = Path(secret_dir) / f'{provider.id}-imap-password'
    if path.exists():
        return path.read_text().strip()
    name = 'MAIL_' + provider.id.upper().replace('-', '_') + '_PASSWORD'
    return os.getenv(name, '') or provider.password


def connect(provider, secret_dir):
    value = password(provider, secret_dir)
    if not value or not provider.username:
        raise ValueError('Mailbox credentials are missing')
    context = ssl.create_default_context(cafile=str(Path(secret_dir)/'bridge-cert.pem') if provider.type == 'bridge' else None)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    client = (UnixIMAP(host='127.0.0.1', timeout=15) if provider.type == 'bridge' else
              TLSIMAP(provider.host, provider.port, ssl_context=context, timeout=15))
    try:
        if provider.type == 'bridge':
            client.starttls(ssl_context=context)
        client.login(provider.username, value)
        return client
    except BaseException:
        close(client)
        raise


def close(client):
    try:
        client.logout()
    except Exception:
        try:
            client.shutdown()
        except Exception:
            pass


def literal(rows):
    return next((r for r in rows if isinstance(r, tuple)), None)


def quoted(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def scan(client, provider, rules, settings, store, generation):
    admitted = 0
    for mailbox in provider.mailboxes:
        typ, _ = client.select(quoted(mailbox), readonly=True)
        if typ != 'OK':
            raise RuntimeError('Configured mailbox cannot be examined')
        validity = client.response('UIDVALIDITY')[1][0].decode()
        high = int(client.response('UIDNEXT')[1][0]) - 1
        key = provider.id + ':' + mailbox
        previous = store.cursor(key)
        low = previous['uid'] if previous and previous['validity'] == validity else 0
        if low >= high:
            continue
        since = (datetime.now(timezone.utc)-timedelta(days=1)).strftime('%d-%b-%Y')
        # Server-side FROM search is only an optimization; exact admission below
        # validates the parsed address, subject and the receiving server's DKIM result.
        domains = sorted({s.rsplit('@', 1)[1] for rule in rules for s in rule.senders})
        criteria = ['UID', f'{low+1}:{high}', 'SINCE', since]
        criteria += ['OR'] * (len(domains)-1)
        for domain in domains:
            criteria.extend(['FROM', quoted('@'+domain)])
        typ, rows = client.uid('SEARCH', None, *criteria)
        if typ != 'OK':
            raise RuntimeError('Mailbox search failed')
        uids = sorted(int(v) for v in rows[0].split() if low < int(v) <= high)
        for uid in uids[:100]:
            typ, rows = client.uid('FETCH', str(uid), '(UID RFC822.SIZE INTERNALDATE BODY.PEEK[HEADER]<0.32768>)')
            if typ != 'OK':
                raise RuntimeError('Header fetch failed')
            item = literal(rows)
            if not item:
                continue
            meta, headers = item
            size = re.search(rb'RFC822\.SIZE (\d+)', meta)
            date = re.search(rb'INTERNALDATE "([^"]+)"', meta)
            if not size or not date or int(size[1]) > MAX_BYTES or len(headers) >= 32768:
                continue
            msg = matching.parse(headers)
            sent = matching.sent_timestamp(msg)
            try:
                received = datetime.strptime(date[1].decode(), '%d-%b-%Y %H:%M:%S %z').timestamp()
            except ValueError:
                continue
            now = time.time()
            if sent is None or max(sent, received) > now+120 or min(sent, received)+settings.max_age_seconds <= now:
                continue
            candidates = [r for r in rules if matching.matches_header(msg, provider, r)]
            if not candidates:
                continue
            typ, rows = client.uid('FETCH', str(uid), f'(UID BODY.PEEK[]<0.{MAX_BYTES+1}>)')
            if typ != 'OK':
                raise RuntimeError('Body fetch failed')
            item = literal(rows)
            if not item or len(item[1]) > MAX_BYTES:
                continue
            raw = item[1]
            for rule in candidates:
                for url in matching.extract(raw, provider, rule):
                    admitted += store.enqueue(provider.id, rule, url, min(sent, received)+settings.max_age_seconds, generation)
        store.checkpoint(key, validity, uids[99] if len(uids) > 100 else high, generation)
    return admitted
