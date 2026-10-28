"""Initialize keys/settings without accepting or printing credentials on the CLI."""
import argparse
import os
from pathlib import Path

from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from helper.config import CLAUDE_RULE, effective
from helper.store import Store


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['init'])
    parser.add_argument('--claude', action='store_true', help='Seed the Claude rule for provider proton')
    args = parser.parse_args()
    os.umask(0o077)
    secret = Path(os.getenv('SECRET_DIR', '/run/secrets'))
    state = Path(os.getenv('STATE_DIR', '/state'))
    secret.mkdir(parents=True, exist_ok=True, mode=0o700)
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = secret/'encryption-key'
    if not key.exists():
        key.write_bytes(Fernet.generate_key())
    hashed = secret/'web-password-hash'
    if not hashed.exists():
        password = secret/'web-password'
        if not password.exists():
            parser.error('Provision secrets/web-password privately, or supply web-password-hash')
        hashed.write_text(PasswordHasher().hash(password.read_text().strip()))
    store = Store(state/'helper.db', key.read_bytes().strip())
    saved = store.settings()
    if args.claude and not saved.get('rules'):
        saved['rules'] = [CLAUDE_RULE]
    config, _ = effective(saved)
    store.save_settings(config.model_dump())
    print('Initialized encrypted state and web login. No credentials printed.')


if __name__ == '__main__':
    main()
