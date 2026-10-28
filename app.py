"""Private login-link broker: no SMTP, URL fetching, AI or email mutation."""
import asyncio
import contextlib
import hashlib
import io
import json
import logging
import os
import re
import secrets
import threading
import time
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from helper.config import Settings, effective, valid_origin
from helper.store import Store, digest
from helper import mail

COOKIE = '__Host-email-link-helper'
ROOT = Path(__file__).resolve().parent
hasher = PasswordHasher()
log = logging.getLogger('email-link-helper')


def create_app(state_dir=None, secret_dir=None, run_worker=True):
    state = Path(state_dir or os.getenv('STATE_DIR', '/state'))
    secret = Path(secret_dir or os.getenv('SECRET_DIR', '/run/secrets'))
    origin = valid_origin(os.environ['PUBLIC_ORIGIN'])
    store = Store(state/'helper.db', (secret/'encryption-key').read_bytes().strip())
    stop = threading.Event()
    status = {}
    status_lock = threading.Lock()

    def settings():
        return effective(store.settings())[0]

    def credentials():
        encoded = (secret/'web-password-hash').read_text().strip()
        return encoded, digest(encoded + ':' + os.getenv('WEB_USERNAME', 'admin'))

    def web_auth(request: Request):
        if not store.session(request.cookies.get(COOKIE, ''), credentials()[1]):
            raise HTTPException(401, 'Sign in to continue')

    def same_origin(request: Request):
        if request.headers.get('origin') != origin or request.headers.get('x-link-helper') != '1':
            raise HTTPException(403, 'Reload this page and try again')

    def device_auth(request: Request):
        token = request.headers.get('authorization', '').removeprefix('Bearer ')
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}', token) or not store.device(token):
            raise HTTPException(401, 'Device token is invalid or revoked')

    def worker():
        clients = {}
        generation = -1
        while not stop.is_set():
            try:
                if generation != store.generation:
                    for client in clients.values():
                        mail.close(client)
                    clients.clear()
                    generation = store.generation
                config = settings()
                for provider in config.providers:
                    rules = [r for r in config.rules if r.enabled and r.provider == provider.id]
                    if not provider.enabled or not rules:
                        continue
                    try:
                        if provider.id not in clients:
                            clients[provider.id] = mail.connect(provider, secret)
                        count = mail.scan(clients[provider.id], provider, rules, config, store, generation)
                        with status_lock:
                            status[provider.id] = dict(ok=True, last_scan=time.time(), delivered=count)
                    except Exception:
                        # Exception strings can contain server responses or credentials.
                        # Never emit them to logs or expose them in the UI.
                        if provider.id in clients:
                            mail.close(clients.pop(provider.id))
                        with status_lock:
                            status[provider.id] = dict(ok=False, last_scan=time.time(), error='Check mailbox credentials, certificate, folders and connection')
                with store.db() as db:
                    store.cleanup(db)
                stop.wait(config.poll_seconds)
            except Exception:
                log.error('Mail configuration could not be loaded; check settings')
                stop.wait(10)
        for client in clients.values():
            mail.close(client)

    @asynccontextmanager
    async def lifespan(_):
        settings()  # Fail deployment early on invalid environment configuration.
        credentials()
        thread = threading.Thread(target=worker, daemon=True)
        if run_worker:
            thread.start()
        yield
        stop.set()
        if run_worker:
            await asyncio.to_thread(thread.join, 20)

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store

    @app.middleware('http')
    async def protection(request: Request, call_next):
        # Deny wrong hosts and large/streamed bodies before route validation.
        if request.headers.get('host') not in [origin.removeprefix('https://'), '127.0.0.1:8000']:
            return JSONResponse({'detail': 'Invalid host'}, status_code=400)
        length = request.headers.get('content-length', '0')
        if not length.isdigit() or int(length) > 65536 or request.headers.get('transfer-encoding'):
            return JSONResponse({'detail': 'Request too large'}, status_code=413)
        response = await call_next(request)
        response.headers.update({
            'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
            'Strict-Transport-Security': 'max-age=31536000',
            'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
        })
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_, __):
        return JSONResponse({'detail': 'Invalid input; check field formats and required values'}, status_code=422)

    @app.get('/health')
    def health():
        return {'ok': True}

    @app.get('/')
    def index():
        return FileResponse(ROOT/'static/index.html')

    class Login(BaseModel):
        username: str = Field(max_length=254)
        password: str = Field(max_length=512)

    @app.post('/api/login', dependencies=[Depends(same_origin)])
    def login(body: Login, request: Request):
        if not store.reserve_login():
            raise HTTPException(429, 'Too many attempts; try again in five minutes', headers={'Retry-After': '300'})
        encoded, version = credentials()
        try:
            valid = hasher.verify(encoded, body.password)
        except (VerificationError, InvalidHashError):
            valid = False
        if not valid or not secrets.compare_digest(body.username.encode(), os.getenv('WEB_USERNAME', 'admin').encode()):
            raise HTTPException(401, 'Username or password is incorrect')
        token = store.create_session(version)
        with store.db() as db:
            db.execute('DELETE FROM sessions WHERE token=?', (digest(request.cookies.get(COOKIE, '')),))
        response = JSONResponse({'ok': True})
        response.set_cookie(COOKIE, token, max_age=86400, secure=True, httponly=True, samesite='strict', path='/')
        return response

    @app.post('/api/logout', dependencies=[Depends(same_origin)])
    def logout(request: Request):
        with store.db() as db:
            db.execute('DELETE FROM sessions WHERE token=?', (digest(request.cookies.get(COOKIE, '')),))
        response = JSONResponse({'ok': True})
        response.delete_cookie(COOKIE, secure=True, httponly=True, samesite='strict', path='/')
        return response

    @app.get('/api/settings', dependencies=[Depends(web_auth)])
    def get_settings():
        config, locked = effective(store.settings())
        public = config.model_dump()
        for p in public['providers']:
            p['password'] = ''
        with status_lock:
            current = dict(status)
        return dict(settings=public, locked=locked, status=current, origin=origin)

    @app.put('/api/settings', dependencies=[Depends(web_auth), Depends(same_origin)])
    def save_settings(body: Settings):
        current, locked = effective(store.settings())
        data = body.model_dump()
        adjusted, _ = effective(data)
        if adjusted.model_dump(exclude={'providers': {'__all__': {'password'}}}) != body.model_dump(exclude={'providers': {'__all__': {'password'}}}):
            raise HTTPException(409, 'Environment-managed fields cannot be changed')
        old = {p.id: p for p in current.providers}
        required = set(filter(None, os.getenv('MAIL_PROVIDERS', '').split(',')))
        if not required.issubset({p.id for p in body.providers}):
            raise HTTPException(409, 'Environment-managed providers cannot be removed')
        for p in data['providers']:
            if not p['password'] and p['id'] in old:
                p['password'] = old[p['id']].password
        store.save_settings(data)
        return {'ok': True}

    @app.get('/api/devices', dependencies=[Depends(web_auth)])
    def devices():
        with store.db() as db:
            return [dict(r) for r in db.execute('SELECT id,name,created FROM devices ORDER BY created')]

    class Device(BaseModel):
        name: str = Field(min_length=1, max_length=80)

    @app.post('/api/devices', dependencies=[Depends(web_auth), Depends(same_origin)])
    def add_device(body: Device):
        try:
            return store.create_device(body.name)
        except ValueError:
            raise HTTPException(409, 'Device limit reached; revoke an old device') from None

    @app.delete('/api/devices/{device_id}', dependencies=[Depends(web_auth), Depends(same_origin)])
    def revoke_device(device_id: str):
        with store.db() as db:
            db.execute('DELETE FROM devices WHERE id=?', (device_id,))
        return {'ok': True}

    @app.get('/api/links', dependencies=[Depends(device_auth)])
    def links():
        return store.pending()

    @app.post('/api/links/{link_id}/claim', dependencies=[Depends(device_auth)])
    def claim(link_id: str):
        url = store.claim(link_id)
        if not url:
            raise HTTPException(404, 'Link expired or was already opened')
        return {'url': url}

    @app.get('/api/extensions/{browser}.zip', dependencies=[Depends(web_auth)])
    def extension(browser: str):
        if browser not in ['chrome', 'firefox']:
            raise HTTPException(404)
        manifest = json.loads((ROOT/f'extension/manifest.{browser}.json').read_text())
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('manifest.json', json.dumps(manifest, indent=2))
            for path in (ROOT/'extension').iterdir():
                if path.suffix in ['.js', '.html', '.css', '.svg']:
                    archive.write(path, path.name)
        return Response(data.getvalue(), media_type='application/zip', headers={'Content-Disposition': f'attachment; filename="email-link-helper-{browser}.zip"'})

    app.mount('/static', StaticFiles(directory=ROOT/'static'), name='static')
    return app
