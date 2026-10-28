# Email Link Helper

A private, single-user broker between narrowly selected sign-in emails and a
Chrome/Firefox extension. New links produce a badge; opening always needs a
click. The helper never follows sign-in links, loads tracking images, sends
mail, or marks messages read. Other message bodies are ignored.

Source lives here. Compose, Caddy, inventory and backup declarations belong in
the sibling `homelab-infra/hosts/server-1/email-link-helper` directory. Runtime
configuration belongs under `/opt/email-link-helper`, outside either checkout.

See [SECURITY.md](SECURITY.md) for the network-peer threat model, encryption,
credential boundaries, audit evidence and local-host limitations.

## Setup

1. Provision `secrets`, `state` and `run` directories, mode 700, owned by runtime
   UID 1000. Keep secret files mode 600. See `.env.example`; never commit real env
   files or credentials.
2. Supply `secrets/web-password-hash` (Argon2), or privately provision
   `secrets/web-password` for initialization. For Bridge, supply its pinned
   `secrets/bridge-cert.pem`, `secrets/proton-imap-password` (the Bridge-generated
   password), and `MAIL_PROTON_USERNAME`.
3. With the example `MAIL_*` variables exported, run
   `SECRET_DIR=/path/to/secrets STATE_DIR=/path/to/state python manage.py init --claude`.
   This generates a Fernet encryption key and seeds the Claude rule. Do not
   regenerate the key for an existing database.
4. Build `docker build -t email-link-helper:0.1.0 .`, then start the relay/app from
   the infra repo. The app runs `uvicorn app:create_app --factory`; only loopback
   8904 is published. Caddy serves `PUBLIC_ORIGIN` on the existing Tailscale listener.
5. Sign in, download the browser extension and create a separate device token
   for each browser. Tokens are shown once and can be revoked. In extension
   Settings, paste your private HTTPS source and device token. Grant access
   only to that source. Destination hosts are separately allowlisted.

Chrome: unzip, open `chrome://extensions`, enable Developer mode, Load unpacked.
Firefox: unzip, open `about:debugging` → This Firefox → Load Temporary Add-on.
Permanent Firefox installation requires signing; the development ZIP is unsigned.
Authenticated downloads include the correct browser-specific `manifest.json`.

## Configuration

The settings page edits validated JSON containing providers, rules, polling and
expiry. Providers support Bridge via pinned STARTTLS and a Unix socket, or
verified IMAPS (e.g. Zoho). Gmail is out of scope. Use provider app passwords
where supported. UI passwords are encrypted and redacted on read; an empty
password preserves the saved value.

Environment fields take precedence and appear as locked. `MAIL_PROVIDERS` lists
IDs; `MAIL_<ID>_LABEL`, `_TYPE`, `_HOST`, `_PORT`, `_USERNAME`, `_MAILBOXES`,
`_AUTHSERV_IDS` and `_ENABLED` configure those fields. Lists are comma-separated.
Passwords resolve from `secrets/<id>-imap-password`, then `MAIL_<ID>_PASSWORD`,
then the encrypted UI value. Prefer files, since Docker operators can inspect
environment values. `LINK_RULES_JSON` optionally sets and locks the entire rule
array. `POLL_SECONDS` accepts 5–300; `MAX_AGE_SECONDS` accepts 60–900 (default 600).

Rules contain `id`, `label`, `provider`, `senders`, `subject_contains`,
`dkim_domains`, `url_hosts`, `url_paths` and `enabled`. Sender patterns permit
`*` only before @, with an exact domain. Links require HTTPS, exact host/path
matches, no userinfo or nonstandard ports, and a query or fragment. Ambiguous
messages fail closed. Other sign-in services can be added without code or an LLM.

The Claude seed uses varying `no-reply-*@mail.anthropic.com` addresses, secure-link
subjects, and `/magic-link` on `claude.ai`, `platform.claude.com` or
`console.anthropic.com`. Old and mobile-only paths aren't rewritten or followed.

`authserv_ids` must match the receiving provider's **first contiguous block** of
Authentication-Results headers (Proton splits methods across headers). The first
DKIM result must pass with an allowed signing
domain. This trusts the receiving provider's result; the helper does not verify
DKIM independently. The provider must prepend trustworthy Authentication-Results
and sanitize impersonations of its own ID. Missing or untrusted results fail
closed, even if the sender looks correct.

## Delivery and security

Persistent read-only IMAP sessions check folders every 5 seconds by default.
Server-side sender searches and header checks precede bounded body reads.
UIDVALIDITY/folder cursors persist; recent mail is rescanned on settings changes.
Date and INTERNALDATE both enforce age limits, so old archived links aren't
sent. Links deduplicate across folders; a newer queued link replaces an older one.

Queue URLs and saved settings are Fernet-encrypted. Server-side device/session
tokens are hashed. Links expire relative to the email's time, not scan time;
claiming atomically removes the link for all devices. The issuing service may
invalidate a link sooner or bind it to the browser that requested it.

The extension checks about every 30 seconds while awake, and immediately when
its popup opens. Browsers can defer alarms while suspended. For Proton, add
Bridge's 20–40 second upstream polling and local processing time. The helper
never prefetches or automatically opens links; source HTTP redirects are rejected.

The extension uses no content scripts, page/history access, remote code or
synchronized storage. It grants host access only for the chosen source and
stores its token locally. A browser/host administrator or compromised extension
can still access it. The app requires authentication in addition to private
ingress. Settings use CSRF protection, secure opaque sessions, login rate limits,
strict CSP and no-store responses. Access logs are disabled; URLs aren't logged.

The deployed service is included in the infrastructure repo's nightly backup:
configuration, credentials, encryption key and a SQLite **online backup** travel
together. The live DB/journals and relay socket are excluded. Restore the staged
database with its matching key/credentials and saved ownership, then clear
`queue` and `sessions` before starting. Device-token hashes/settings persist;
revoke/re-pair devices if an older snapshot predates a token revocation.

## Development

Install `requirements.lock` plus pytest/httpx in a virtual environment:

```sh
python -m pytest -q
node --test tests/extension.test.cjs
pip-audit -r requirements.lock
```

The lock pins the production dependency graph. Tests use synthetic messages,
cover security and delivery behavior, and never request real sign-in URLs.

Browser references: [Chrome network requests](https://developer.chrome.com/docs/extensions/develop/concepts/network-requests),
[Chrome alarms](https://developer.chrome.com/docs/extensions/reference/api/alarms),
[Firefox background scripts](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/background).
