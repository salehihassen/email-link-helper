"""Validated settings; deployment environment takes precedence over UI values."""
import json
import os
import re
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

ID = r'^[a-z][a-z0-9-]{0,31}$'


class Provider(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(pattern=ID)
    label: str = Field(min_length=1, max_length=80)
    type: Literal['bridge', 'imap'] = 'imap'
    host: str = Field(default='', max_length=253, pattern=r'^[a-zA-Z0-9.-]*$')
    port: int = Field(default=993, ge=1, le=65535)
    username: str = Field(default='', max_length=254)
    password: str = Field(default='', max_length=512)
    mailboxes: list[str] = Field(default_factory=lambda: ['INBOX'], min_length=1, max_length=10)
    authserv_ids: list[str] = Field(default_factory=list, max_length=10)
    enabled: bool = True

    @model_validator(mode='after')
    def validate_provider(self):
        if self.type == 'imap' and not self.host:
            raise ValueError('An IMAPS host is required')
        if self.host.lower().endswith(('gmail.com', 'googlemail.com')):
            raise ValueError('Gmail is out of scope')
        for value in [self.username, self.password, *self.mailboxes, *self.authserv_ids]:
            if any(c in value for c in '\r\n\x00') or len(value) > 512:
                raise ValueError('Invalid IMAP value')
        if not self.authserv_ids:
            raise ValueError('Configure the receiving mail server Authentication-Results ID')
        return self


class Rule(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(pattern=ID)
    label: str = Field(min_length=1, max_length=80)
    provider: str = Field(pattern=ID)
    senders: list[str] = Field(min_length=1, max_length=20)
    subject_contains: str = Field(default='secure link', max_length=120)
    dkim_domains: list[str] = Field(min_length=1, max_length=20)
    url_hosts: list[str] = Field(min_length=1, max_length=20)
    url_paths: list[str] = Field(min_length=1, max_length=20)
    enabled: bool = True

    @model_validator(mode='after')
    def validate_rule(self):
        for sender in self.senders:
            if not re.fullmatch(r'[a-zA-Z0-9._+*\-]+@[a-zA-Z0-9.-]+', sender):
                raise ValueError('Sender patterns allow * only in the local part; use an exact domain')
        for host in self.url_hosts + self.dkim_domains:
            if not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?', host):
                raise ValueError('Use exact DNS hosts, without wildcards')
        for path in self.url_paths:
            if not re.fullmatch(r'/[a-zA-Z0-9/_-]*', path):
                raise ValueError('Use exact URL paths')
        return self


class Settings(BaseModel):
    model_config = ConfigDict(extra='forbid')
    providers: list[Provider] = Field(default_factory=list, max_length=12)
    rules: list[Rule] = Field(default_factory=list, max_length=40)
    poll_seconds: int = Field(default=5, ge=5, le=300)
    max_age_seconds: int = Field(default=600, ge=60, le=900)

    @model_validator(mode='after')
    def unique_ids(self):
        ids = [p.id for p in self.providers]
        if len(ids) != len(set(ids)) or len(self.rules) != len({r.id for r in self.rules}):
            raise ValueError('Provider and rule IDs must be unique')
        if any(r.provider not in ids for r in self.rules):
            raise ValueError('Each rule must name an existing provider')
        return self


CLAUDE_RULE = dict(id='claude', label='Claude sign-in', provider='proton',
                   senders=['no-reply-*@mail.anthropic.com', 'no-reply@mail.anthropic.com'],
                   subject_contains='secure link', dkim_domains=['mail.anthropic.com'],
                   url_hosts=['claude.ai', 'platform.claude.com', 'console.anthropic.com'],
                   url_paths=['/magic-link'])


def effective(saved, env=None):
    env = os.environ if env is None else env
    data = json.loads(json.dumps(saved))
    locked = []
    providers = {p['id']: p for p in data.get('providers', [])}
    for pid in filter(None, env.get('MAIL_PROVIDERS', '').split(',')):
        pid = pid.strip().lower()
        if not re.fullmatch(ID, pid):
            raise ValueError('Invalid MAIL_PROVIDERS ID')
        p = providers.setdefault(pid, {'id': pid, 'label': pid.title()})
        prefix = 'MAIL_' + pid.upper().replace('-', '_') + '_'
        for key in Provider.model_fields:
            name = prefix + key.upper()
            if key == 'password' or name not in env:
                continue
            value = env[name]
            if key in ['mailboxes', 'authserv_ids']:
                value = [v.strip() for v in value.split(',') if v.strip()]
            elif key == 'enabled':
                value = value.lower() in ['true', '1', 'yes']
            p[key] = value
            locked.append(f'providers.{pid}.{key}')
        locked.append(f'providers.{pid}.id')
    data['providers'] = list(providers.values())
    if env.get('LINK_RULES_JSON'):
        data['rules'] = json.loads(env['LINK_RULES_JSON'])
        locked.append('rules')
    for key in ['poll_seconds', 'max_age_seconds']:
        if key.upper() in env:
            data[key] = int(env[key.upper()])
            locked.append(key)
    return Settings.model_validate(data), locked


def valid_origin(value):
    u = urlsplit(value)
    if u.scheme != 'https' or not u.hostname or u.username or u.password or u.path not in ['', '/'] or u.query or u.fragment:
        raise ValueError('PUBLIC_ORIGIN must be an HTTPS origin')
    return value.rstrip('/')
