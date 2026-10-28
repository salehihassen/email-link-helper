# Security model

The intended boundary I tried to protect this service from is a malicious LAN / tailscale peer with **network access only**,
without the user's web password/device token, access to the browser profile,
server files/containers, trusted TLS private keys, or Tailscale administration.
Tailnet membership supplies reachability; it never supplies application identity.
This model protects confidentiality and authorization. Availability under a
determined flood, host compromise and browser compromise are separate problems.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/salehihassen/email-link-helper/security/advisories/new)
(Security tab → Report a vulnerability). If you cannot use GitHub, email
security@salehh.xyz. Do not open a public issue.

Include the affected component, reproduction steps and impact. This is a
single-maintainer project: responses are best-effort and there is no bounty.
Only the latest commit on `main` is supported.

## In transit

The extension accepts HTTPS origins only and uses normal browser certificate
validation. It sends its token in Authorization, never in the URL; requests omit
cookies, refuse redirects, disable caching and suppress referrers. Network peers
cannot redirect it to plaintext HTTP or another host to obtain that token.
The settings UI uses HTTPS, HSTS, Secure/HttpOnly/SameSite=Strict host-only
cookies, same-origin/custom-header CSRF checks, no CORS allowances, and a strict
content security policy. Logout and failed session loading clear sensitive form
contents. Tailnet identity/forwarding headers do not bypass authentication.

Tailscale uses device-to-device WireGuard encryption, including relayed paths;
being another peer does not give a node the keys to read other devices' traffic.
HTTPS adds independent server identity and content encryption. A peer may still
probe reachable services, discover names/ports, or observe limited traffic timing
where it is positioned to do so; encryption does not conceal every metadata item.

Caddy is the TLS endpoint and proxies to a loopback-only HTTP listener. That
short local hop is inside the trusted server boundary. Bridge is reached over
a filesystem-restricted Unix relay socket with certificate-verified STARTTLS;
other IMAP providers require verified TLS. The helper never fetches login links
or tracking images. Its separate Bridge TCP gateway, if enabled elsewhere in the
deployment, must retain its own source allowlist and mailbox authentication.

## Authentication and link delivery

Web passwords use Argon2 hashes, and login attempts are persistently limited
account-wide. Opaque sessions have a 24-hour absolute lifetime and one-hour idle
limit. Extension devices use independent 256-bit random bearer tokens, with only
SHA-256 hashes stored server-side. Those tokens can list and claim links, but
cannot access settings, mailbox passwords, device administration or full emails.
Tokens have no automatic expiry; revoke a device to invalidate its token.

Unauthenticated peers cannot list metadata or retrieve a queued login URL.
Only narrow authenticated sender/DKIM/destination rules create links. Reading
the queue does not return URLs; an explicit click claims the URL once. Claims
delete it atomically, and queue expiry defaults to ten minutes from email time.
An authenticated recipient could copy a URL during that period: single-use
delivery is not an application-level guarantee that the issuing site has already
invalidated the underlying login token.

## At rest

The service Fernet-encrypts saved settings (including UI-provided passwords) and
queued login URLs. Device/session credentials are stored as hashes. Non-secret
queue labels, destination hosts, timestamps, device names and cursors remain
readable in SQLite. Runtime directories are owner-only and secret/DB files are
mode 600. Mailbox passwords supplied as secret files and the Fernet key remain
readable to their owning OS account and the authorized app container.

The key is stored alongside the protected runtime, rather than in an independent
hardware vault. This helps against theft of the database alone; it does **not**
protect against theft of the whole runtime, a process running as the owning OS
user, root, a privileged packet-capture service on the server, or host/container
compromise. Do not infer full-disk encryption from SQLite encryption. A network-
only peer cannot read these files merely by sharing the tailnet.

The extension persists its token in local extension storage, never storage.sync.
Chrome limits access to trusted extension contexts. There are no content scripts,
external message listeners, web-accessible resources, remote scripts, or history
permissions. Browser storage is not an independent encrypted credential vault:
local malware/profile access can steal the token. The extension keeps pending
metadata but does not persist sign-in URLs. After a click, the browser and target
site handle the URL; browser history/session/history-sync policies may apply.

Nightly restic backups encrypt runtime files, credentials, encryption key and
online SQLite exports together. Temporary exports have restricted permissions.
Restore the matching key and DB, then clear queue/sessions before startup. An
older restore can resurrect previously revoked device hashes, so re-pair/revoke
devices after such a restore. Backup encryption protects off-host storage; it
does not make the live server independent of its own keys.

## What remains possible for an untrusted peer

The login page and minimal health endpoint are intentionally public to reachable
peers. Other endpoints require app credentials. Peers can try to exhaust
connections or the login attempt allowance; rate limits/body/resource bounds
reduce impact but do not promise denial-of-service resistance. Restricting which
devices may reach the HTTPS port through Tailscale policy is optional additional
containment. On a shared Caddy port, policy changes can affect other hosted apps.

This audit covers this helper and its immediate ingress/storage paths; it does
not establish that every other application on the host or tailnet is secure.
Keep browser/OS/container dependencies maintained, use HTTPS URLs, avoid disabling
certificate checks, and revoke a token when a browser profile is lost or exposed.

## Verification, 2026-10-28

Source/runtime review checked HTTPS-only extension requests, redirect refusal,
no URL persistence, token hashing/revocation, role separation, encrypted queue/
settings, CSRF/cookie/CSP controls, safe read-only IMAP and backup declarations.
Live probes verified certificate trust/hostname, TLS 1.3 and 1.2, backend isolation
on tailnet IPv4/IPv6, unauthorized/invalid-token/forged-identity rejection and
foreign-origin login denial. File permissions, dependency audit and secret scan
were checked. Tests cover expiry/replay, spoofed senders/URLs, token revocation
and extension click behavior. These are scoped checks, not a proof that no
software vulnerability exists or a full penetration test from every peer.

Primary references: [Tailscale encryption](https://tailscale.com/kb/1504/encryption),
[Chrome extension storage](https://developer.chrome.com/docs/extensions/reference/api/storage),
[Chrome cross-origin requests](https://developer.chrome.com/docs/extensions/develop/concepts/network-requests).
