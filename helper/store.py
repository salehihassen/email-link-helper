"""Encrypted short-lived delivery queue and hashed, revocable credentials."""
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from cryptography.fernet import Fernet


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class Store:
    def __init__(self, path, encryption_key):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.generation = 0
        self.cipher = Fernet(encryption_key)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.db() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY, data BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, version TEXT, created REAL, seen REAL);
            CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, name TEXT, token TEXT UNIQUE, created REAL);
            CREATE TABLE IF NOT EXISTS queue (id TEXT PRIMARY KEY, fingerprint TEXT UNIQUE, provider TEXT,
                rule_id TEXT, label TEXT, host TEXT, url BLOB, created REAL, expires REAL);
            CREATE TABLE IF NOT EXISTS seen (fingerprint TEXT PRIMARY KEY, expires REAL);
            CREATE TABLE IF NOT EXISTS cursors (id TEXT PRIMARY KEY, validity TEXT, uid INTEGER);
            CREATE TABLE IF NOT EXISTS login_limit (id INTEGER PRIMARY KEY, start REAL, attempts INTEGER);
            ''')
        os.chmod(self.path, 0o600)

    @contextmanager
    def db(self):
        with self.lock:
            db = sqlite3.connect(self.path, timeout=10)
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA secure_delete=ON')
            try:
                with db:
                    yield db
            finally:
                db.close()

    def settings(self):
        with self.db() as db:
            row = db.execute('SELECT data FROM config WHERE id=1').fetchone()
            return json.loads(self.cipher.decrypt(row['data'])) if row else {}

    def settings_version(self):
        with self.db() as db:
            row = db.execute('SELECT data FROM config WHERE id=1').fetchone()
            return hashlib.sha256(row['data'] if row else b'').hexdigest()

    def save_settings(self, data):
        with self.db() as db:
            db.execute('INSERT OR REPLACE INTO config VALUES(1,?)', (self.cipher.encrypt(json.dumps(data).encode()),))
            # Settings changes invalidate pending links immediately.
            db.execute('DELETE FROM queue')
            db.execute('DELETE FROM cursors')
            self.generation += 1

    def cleanup(self, db):
        now = time.time()
        db.execute('DELETE FROM queue WHERE expires <= ?', (now,))
        db.execute('DELETE FROM seen WHERE expires <= ?', (now,))
        db.execute('DELETE FROM sessions WHERE created <= ? OR seen <= ?', (now-86400, now-3600))

    def enqueue(self, provider, rule, url, expires, generation=None):
        from urllib.parse import urlsplit
        key = digest(provider + ':' + url)
        with self.db() as db:
            if generation is not None and generation != self.generation:
                return False
            self.cleanup(db)
            if expires <= time.time() or db.execute('SELECT 1 FROM seen WHERE fingerprint=?', (key,)).fetchone():
                return False
            db.execute('INSERT INTO seen VALUES(?,?)', (key, time.time()+172800))
            newer = db.execute('SELECT 1 FROM queue WHERE provider=? AND rule_id=? AND expires>=?',
                               (provider, rule.id, expires)).fetchone()
            if newer:
                return False
            # A new login email supersedes older links for the same rule.
            db.execute('DELETE FROM queue WHERE provider=? AND rule_id=?', (provider, rule.id))
            db.execute('INSERT INTO queue VALUES(?,?,?,?,?,?,?,?,?)', (
                secrets.token_urlsafe(18), key, provider, rule.id, rule.label,
                urlsplit(url).hostname, self.cipher.encrypt(url.encode()), time.time(), expires))
            return True

    def pending(self):
        with self.db() as db:
            self.cleanup(db)
            return [dict(r) for r in db.execute('SELECT id,provider,label,host,created,expires FROM queue ORDER BY created DESC LIMIT 40')]

    def claim(self, link_id):
        with self.db() as db:
            self.cleanup(db)
            row = db.execute('DELETE FROM queue WHERE id=? RETURNING url', (link_id,)).fetchone()
            return self.cipher.decrypt(row['url']).decode() if row else None

    def cursor(self, key):
        with self.db() as db:
            row = db.execute('SELECT * FROM cursors WHERE id=?', (key,)).fetchone()
            return dict(row) if row else None

    def checkpoint(self, key, validity, uid, generation=None):
        with self.db() as db:
            if generation is not None and generation != self.generation:
                return
            db.execute('INSERT OR REPLACE INTO cursors VALUES(?,?,?)', (key, validity, uid))

    def reserve_login(self):
        with self.db() as db:
            now = time.time()
            db.execute('INSERT OR IGNORE INTO login_limit VALUES(1,?,0)', (now,))
            row = db.execute('SELECT * FROM login_limit WHERE id=1').fetchone()
            if now - row['start'] >= 300:
                db.execute('UPDATE login_limit SET start=?,attempts=1 WHERE id=1', (now,))
            elif row['attempts'] >= 10:
                return False
            else:
                db.execute('UPDATE login_limit SET attempts=attempts+1 WHERE id=1')
            return True

    def session(self, token, version):
        with self.db() as db:
            self.cleanup(db)
            return bool(db.execute('UPDATE sessions SET seen=? WHERE token=? AND version=? RETURNING token',
                                   (time.time(), digest(token), version)).fetchone())

    def create_session(self, version):
        token = secrets.token_urlsafe(32)
        with self.db() as db:
            self.cleanup(db)
            db.execute('INSERT INTO sessions VALUES(?,?,?,?)', (digest(token), version, time.time(), time.time()))
        return token

    def create_device(self, name):
        token = secrets.token_urlsafe(32)
        ident = secrets.token_urlsafe(12)
        with self.db() as db:
            if db.execute('SELECT count(*) FROM devices').fetchone()[0] >= 20:
                raise ValueError('Revoke an old device before adding another')
            db.execute('INSERT INTO devices VALUES(?,?,?,?)', (ident, name, digest(token), time.time()))
        return dict(id=ident, token=token)

    def device(self, token):
        with self.db() as db:
            row = db.execute('SELECT id FROM devices WHERE token=?', (digest(token),)).fetchone()
            return row['id'] if row else None
