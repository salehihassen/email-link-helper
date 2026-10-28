import email
import importlib
import json
import time
from email.message import EmailMessage
from email.utils import formatdate

import pytest
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from helper.config import CLAUDE_RULE, Provider, Rule, Settings, effective
from helper.matching import allowed_url, extract, matches_header, parse
from helper.store import Store
from helper import mail


@pytest.fixture
def provider():
    return Provider(id='proton', label='Personal', type='bridge', username='test@example.test', authserv_ids=['mail.protonmail.ch'], mailboxes=['INBOX', 'Archive'])


@pytest.fixture
def rule():
    return Rule(**CLAUDE_RULE)


def message(url='https://claude.ai/magic-link#test-only-token', sender='no-reply-test@mail.anthropic.com', auth=None):
    msg = EmailMessage()
    msg['From'] = sender
    msg['Subject'] = 'Your secure link to Claude is here'
    msg['Date'] = formatdate(usegmt=True)
    msg['Authentication-Results'] = auth or 'mail.protonmail.ch; dkim=pass (Good signature) header.d=mail.anthropic.com'
    msg.set_content('Sign in: '+url)
    msg.add_alternative(f'<a href="{url}">Sign in</a><img src="https://tracking.example.test/pixel">', subtype='html')
    return msg.as_bytes()


def test_admits_only_expected_authenticated_link(provider, rule):
    assert extract(message(), provider, rule) == ['https://claude.ai/magic-link#test-only-token']
    assert not extract(message(sender='evil@anthropic.com'), provider, rule)
    assert not extract(message(sender='no-reply-x@mail.anthropic.com.evil.test'), provider, rule)
    assert not extract(message(auth='mail.protonmail.ch; dkim=fail header.d=mail.anthropic.com'), provider, rule)
    assert not extract(message(auth='mail.protonmail.ch; dkim=pass header.d=evil.test'), provider, rule)
    assert not extract(message(auth='attacker.test; dkim=pass header.d=mail.anthropic.com'), provider, rule)


def test_cannot_trust_lower_authentication_header(provider, rule):
    msg = parse(message(auth='mail.protonmail.ch; dkim=fail header.d=mail.anthropic.com'))
    msg['Authentication-Results'] = 'mail.protonmail.ch; dkim=pass header.d=mail.anthropic.com'
    assert not matches_header(msg, provider, rule)


def test_proton_split_authentication_block_and_injected_lower_block(provider, rule):
    msg = parse(message())
    del msg['Authentication-Results']
    msg['Authentication-Results'] = 'mail.protonmail.ch; dmarc=pass header.from=mail.anthropic.com'
    msg['Authentication-Results'] = 'mail.protonmail.ch; spf=pass'
    msg['Authentication-Results'] = 'mail.protonmail.ch; arc=none'
    msg['Authentication-Results'] = 'mail.protonmail.ch; dkim=pass header.d=mail.anthropic.com'
    assert matches_header(msg, provider, rule)
    del msg['Authentication-Results']
    msg['Authentication-Results'] = 'mail.protonmail.ch; dmarc=pass'
    msg['X-Untrusted-Separator'] = 'value'
    msg['Authentication-Results'] = 'mail.protonmail.ch; dkim=pass header.d=mail.anthropic.com'
    assert not matches_header(msg, provider, rule)
    msg = parse(b'From: no-reply-other@mail.anthropic.com\n'+message())
    assert not matches_header(msg, provider, rule)


@pytest.mark.parametrize('url', [
    'http://claude.ai/magic-link#x', 'javascript:alert(1)',
    'https://claude.ai.evil.test/magic-link#x', 'https://evil.test/claude.ai/magic-link#x',
    'https://evil.test@claude.ai/magic-link#x', 'https://claude.ai:444/magic-link#x',
    'https://claude.ai/magic-link/../evil#x', 'https://claude.ai/magic-link%2f#x',
    'https://claude.ai/magic-link', 'https://claude.ai/magic-link#x\ny',
    'https://claude.ai\\@evil.test/magic-link#x', 'https://claude.ai/other#x',
])
def test_unsafe_destinations_rejected(url, rule):
    assert not allowed_url(url, rule)


def test_html_entities_decoded_and_ambiguous_tokens_rejected(provider, rule):
    raw = message('https://claude.ai/magic-link?token=x&other=y')
    assert len(extract(raw, provider, rule)) == 1
    msg = parse(message())
    msg.clear_content()
    msg.set_content('https://claude.ai/magic-link#one https://claude.ai/magic-link#two')
    assert not extract(msg.as_bytes(), provider, rule)


def test_attached_forwarded_message_is_not_a_login_link(provider, rule):
    msg = parse(message())
    msg.clear_content()
    msg.set_content('See attachment')
    forwarded = parse(message())
    msg.add_attachment(forwarded)
    assert not extract(msg.as_bytes(), provider, rule)


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path/'helper.db', Fernet.generate_key())


def test_encrypted_queue_expiry_one_time_and_replay(store, rule):
    url = 'https://claude.ai/magic-link#sensitive-test-token'
    assert store.enqueue('proton', rule, url, time.time()+30)
    assert url.encode() not in store.path.read_bytes()
    pending = store.pending()
    assert 'url' not in pending[0]
    assert store.claim(pending[0]['id']) == url
    assert store.claim(pending[0]['id']) is None
    assert not store.enqueue('proton', rule, url, time.time()+30)
    assert not store.enqueue('proton', rule, url+'2', time.time()-1)


def test_newer_link_supersedes_older_and_stale_workers_cannot_enqueue(store, rule):
    assert store.enqueue('proton', rule, 'https://claude.ai/magic-link#new', time.time()+100)
    assert not store.enqueue('proton', rule, 'https://claude.ai/magic-link#old', time.time()+50)
    assert len(store.pending()) == 1
    generation = store.generation
    store.save_settings({})
    assert not store.enqueue('proton', rule, 'https://claude.ai/magic-link#stale', time.time()+100, generation)
    assert not store.pending()


def test_device_hashes_revocation_and_encrypted_settings(store):
    d = store.create_device('Test browser')
    assert store.device(d['token']) == d['id']
    assert d['token'].encode() not in store.path.read_bytes()
    store.save_settings({'providers': [{'password': 'sensitive-password'}]})
    assert b'sensitive-password' not in store.path.read_bytes()
    with store.db() as db:
        db.execute('DELETE FROM devices WHERE id=?', (d['id'],))
    assert not store.device(d['token'])


def test_provider_environment_and_gmail_exclusion(provider):
    saved = Settings(providers=[provider]).model_dump()
    config, locked = effective(saved, {'MAIL_PROVIDERS': 'proton', 'MAIL_PROTON_USERNAME': 'other@example.test', 'POLL_SECONDS': '10'})
    assert config.providers[0].username == 'other@example.test'
    assert config.poll_seconds == 10
    assert 'providers.proton.username' in locked
    with pytest.raises(ValueError):
        Provider(id='gmail', label='Gmail', host='imap.gmail.com', authserv_ids=['mx.google.com'])


def test_imap_write_commands_impossible():
    client = object.__new__(mail.UnixIMAP)
    for command, args in [('SELECT', ('INBOX',)), ('STORE', ('1',)), ('EXPUNGE', ()),
                          ('UID', ('STORE', '1', '+FLAGS', '\\Seen')),
                          ('UID', ('FETCH', '1', '(RFC822)')),
                          ('UID', ('FETCH', '1', '(BODY[])'))]:
        with pytest.raises(ValueError):
            client._command(command, *args)


class FakeIMAP:
    def __init__(self, raw, when=None):
        self.raw = raw
        self.date = when or time.time()
        self.body_fetches = 0
        self.mailboxes = []

    def select(self, mailbox, readonly):
        assert readonly
        self.mailboxes.append(mailbox)
        return 'OK', []

    def response(self, name):
        return name, [b'123' if name == 'UIDVALIDITY' else b'3']

    def uid(self, command, *args):
        if command == 'SEARCH':
            return 'OK', [b'2']
        if 'BODY.PEEK[HEADER]' in args[-1]:
            date = time.strftime('%d-%b-%Y %H:%M:%S +0000', time.gmtime(self.date))
            meta = f'2 (UID 2 RFC822.SIZE {len(self.raw)} INTERNALDATE "{date}")'.encode()
            return 'OK', [(meta, self.raw.split(b'\n\n')[0]+b'\n\n')]
        self.body_fetches += 1
        return 'OK', [(b'2 (UID 2)', self.raw)]


def test_scanner_ignores_other_senders_and_old_archive_without_reading_bodies(provider, rule, store):
    settings = Settings(providers=[provider], rules=[rule])
    client = FakeIMAP(message(sender='newsletter@mail.anthropic.com'))
    assert mail.scan(client, provider, [rule], settings, store, store.generation) == 0
    assert client.body_fetches == 0
    store.save_settings({})
    client = FakeIMAP(message(), time.time()-86400)
    assert mail.scan(client, provider, [rule], settings, store, store.generation) == 0
    assert client.body_fetches == 0
    store.save_settings({})
    client = FakeIMAP(message())
    assert mail.scan(client, provider, [rule], settings, store, store.generation) == 1
    assert len(store.pending()) == 1
    assert client.mailboxes == ['"INBOX"', '"Archive"']


@pytest.fixture
def web(tmp_path, monkeypatch):
    monkeypatch.setenv('PUBLIC_ORIGIN', 'https://links.private.example')
    secret = tmp_path/'secrets'; secret.mkdir()
    (secret/'encryption-key').write_bytes(Fernet.generate_key())
    (secret/'web-password-hash').write_text(PasswordHasher().hash('test-web-password'))
    import app
    app = app.create_app(tmp_path/'state', secret, run_worker=False)
    with TestClient(app, base_url='https://links.private.example') as client:
        yield client, app.state.store


GUARD = {'Origin': 'https://links.private.example', 'X-Link-Helper': '1'}


def sign_in(client):
    return client.post('/api/login', json={'username': 'admin', 'password': 'test-web-password'}, headers=GUARD)


def test_web_auth_csrf_and_cookie_security(web):
    client, store = web
    assert client.get('/api/settings').status_code == 401
    assert client.post('/api/login', json={'username': 'admin', 'password': 'test-web-password'}).status_code == 403
    response = sign_in(client)
    assert response.status_code == 200
    cookie = response.headers['set-cookie'].lower()
    assert all(v in cookie for v in ['secure', 'httponly', 'samesite=strict', 'path=/'])
    assert client.get('/api/settings').status_code == 200
    assert client.put('/api/settings', json={}).status_code == 403
    response = client.get('/')
    assert response.headers['cache-control'] == 'no-store'
    assert response.headers['strict-transport-security'] == 'max-age=31536000'
    assert "frame-ancestors 'none'" in response.headers['content-security-policy']
    assert client.get('/api/settings', headers={'Host': 'evil.test'}).status_code == 400


def test_device_cannot_manage_settings_and_claim_is_atomic(web, rule):
    client, store = web
    sign_in(client)
    device = client.post('/api/devices', json={'name': 'Test'}, headers=GUARD).json()
    client.cookies.clear()
    headers = {'Authorization': 'Bearer '+device['token']}
    assert client.get('/api/settings', headers=headers).status_code == 401
    assert client.get('/api/links').status_code == 401
    store.enqueue('proton', rule, 'https://claude.ai/magic-link#test', time.time()+30)
    response = client.get('/api/links', headers=headers)
    assert response.status_code == 200
    assert 'url' not in response.text
    ident = response.json()[0]['id']
    assert client.post('/api/links/'+ident+'/claim', headers=headers).json()['url'].endswith('#test')
    assert client.post('/api/links/'+ident+'/claim', headers=headers).status_code == 404
    assert client.get('/api/links', headers=headers).headers.get('access-control-allow-origin') is None


def test_rate_limit_survives_new_clients(web):
    client, store = web
    for _ in range(10):
        assert client.post('/api/login', json={'username': 'wrong', 'password': 'wrong'}, headers=GUARD).status_code == 401
    assert sign_in(client).status_code == 429


def test_ui_password_redaction_and_preservation(web, provider, rule):
    client, store = web
    sign_in(client)
    settings = Settings(providers=[provider], rules=[rule]).model_dump()
    settings['providers'][0]['password'] = 'secret-mailbox-password'
    assert client.put('/api/settings', json=settings, headers=GUARD).status_code == 200
    response = client.get('/api/settings')
    assert 'secret-mailbox-password' not in response.text
    assert client.put('/api/settings', json=response.json()['settings'], headers=GUARD).status_code == 200
    assert store.settings()['providers'][0]['password'] == 'secret-mailbox-password'


def test_environment_managed_fields_and_rules_cannot_be_changed_in_ui(web, provider, rule, monkeypatch):
    client, store = web
    store.save_settings(Settings(providers=[provider], rules=[rule]).model_dump())
    monkeypatch.setenv('MAIL_PROVIDERS', 'proton')
    monkeypatch.setenv('MAIL_PROTON_USERNAME', 'locked@example.test')
    monkeypatch.setenv('LINK_RULES_JSON', json.dumps([rule.model_dump()]))
    sign_in(client)
    current = client.get('/api/settings').json()['settings']
    current['providers'][0]['username'] = 'different@example.test'
    assert client.put('/api/settings', json=current, headers=GUARD).status_code == 409
    current = client.get('/api/settings').json()['settings']
    current['rules'][0]['url_hosts'] = ['evil.test']
    assert client.put('/api/settings', json=current, headers=GUARD).status_code == 409
    current = client.get('/api/settings').json()['settings']
    assert client.put('/api/settings', json=current, headers=GUARD).status_code == 200


def test_downloads_correct_browser_manifest_without_credentials(web):
    import io
    import zipfile
    client, _ = web
    assert client.get('/api/extensions/chrome.zip').status_code == 401
    sign_in(client)
    for browser in ['chrome', 'firefox']:
        response = client.get(f'/api/extensions/{browser}.zip')
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            manifest = json.loads(archive.read('manifest.json'))
            assert ('service_worker' if browser == 'chrome' else 'scripts') in manifest['background']
            assert 'content_scripts' not in manifest
            assert not manifest.get('host_permissions')


def test_settings_revision_prevents_stale_form_overwrites(web, provider, rule):
    client, store = web
    store.save_settings(Settings(providers=[provider], rules=[rule]).model_dump())
    sign_in(client)
    first = client.get('/api/settings').json()
    assert client.get('/api/settings').json()['revision'] == first['revision']
    candidate = first['settings']
    candidate['providers'][0]['label'] = 'Updated name'
    headers = GUARD | {'If-Match': first['revision']}
    assert client.put('/api/settings', json=candidate, headers=headers).status_code == 200
    latest = client.get('/api/settings').json()
    assert latest['revision'] != first['revision']
    candidate['providers'][0]['label'] = 'Stale tab'
    response = client.put('/api/settings', json=candidate, headers=headers)
    assert response.status_code == 409
    assert store.settings()['providers'][0]['label'] == 'Updated name'


def test_field_errors_never_echo_passwords_and_password_source_is_metadata(web, provider, rule, monkeypatch):
    client, store = web
    store.save_settings(Settings(providers=[provider], rules=[rule]).model_dump())
    sign_in(client)
    monkeypatch.setenv('MAIL_PROTON_PASSWORD', 'environment-password-do-not-echo')
    config = client.get('/api/settings').json()
    assert config['password_sources']['proton'] == 'env'
    assert 'environment-password-do-not-echo' not in str(config)
    candidate = config['settings']
    candidate['providers'][0]['password'] = 'input-password-do-not-echo'
    candidate['providers'][0]['port'] = 'bad-port'
    response = client.put('/api/settings', json=candidate, headers=GUARD)
    assert response.status_code == 422
    assert response.json()['errors'][0]['path'] == ['providers', 0, 'port']
    assert 'input-password-do-not-echo' not in response.text
    assert all(set(error) == {'path', 'message'} for error in response.json()['errors'])
