# Security model

This is a defensive design. The helper handles sign-in links and mailbox
credentials, so its goal is to keep that data confidential, in transit and at
rest, from **other devices on the same private network**: a compromised or
untrusted machine on your LAN, VPN or mesh network (for example Tailscale or
WireGuard) that can reach the service but holds none of your credentials.

Such a peer is assumed to have **network access only**: no web password or
device token, no access to your browser profile, server files or containers,
trusted TLS private keys, or network administration. Network reachability never
grants application identity. The model protects confidentiality and
authorization; availability under a determined flood, host compromise and
browser compromise are separate problems.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/salehihassen/email-link-helper/security/advisories/new)
(Security tab → Report a vulnerability). If you cannot use GitHub, email
security@salehh.xyz. Do not open a public issue.

Include the affected component, reproduction steps and impact. This is a
single-maintainer project: responses are best-effort and there is no bounty.
Only the latest commit on `main` is supported.

## Deployment assumptions

The model holds when the deployment provides:

- A TLS-terminating reverse proxy (Caddy, nginx, Traefik, …) serving
  `PUBLIC_ORIGIN` with a certificate your browsers trust, and forwarding the
  original `Host` header.
- The app's HTTP port published on loopback only, so peers reach it solely
  through the proxy.
- Ingress limited to your private network. Exposing the login page to the
  public internet is outside this model: authentication still applies, but the
  account-wide login limit then lets anyone lock you out.

## In transit

The extension accepts HTTPS origins only and uses normal browser certificate
validation. It sends its token in Authorization, never in the URL; requests omit
cookies, refuse redirects, disable caching and suppress referrers. Network peers
cannot redirect it to plaintext HTTP or another host to obtain that token.
The settings UI uses HTTPS, HSTS, Secure/HttpOnly/SameSite=Strict host-only
cookies, same-origin/custom-header CSRF checks, no CORS allowances, and a strict
content security policy. Logout and failed session loading clear sensitive form
contents. Proxy, forwarding or VPN identity headers do not bypass authentication.

HTTPS is the security boundary for traffic, independent of the network layer.
An encrypted overlay such as Tailscale or WireGuard adds a second layer, but a
plain LAN is acceptable because HTTPS already provides server identity and
content encryption. A peer may still probe reachable services, discover
names/ports, or observe traffic timing where it is positioned to do so;
encryption does not conceal every metadata item.

The reverse proxy proxies to a loopback-only HTTP listener. That short local hop
is inside the trusted server boundary. Proton Bridge is reached over a
filesystem-restricted Unix relay socket with certificate-verified STARTTLS;
other IMAP providers require verified TLS. The helper never fetches login links
or tracking images. If Bridge's own TCP port is exposed elsewhere in the
deployment, it must keep its own source allowlist and mailbox authentication.

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
only peer cannot read these files merely by reaching the service.

The extension persists its token in local extension storage, never storage.sync.
Chrome limits access to trusted extension contexts. There are no content scripts,
external message listeners, web-accessible resources, remote scripts, or history
permissions. Browser storage is not an independent encrypted credential vault:
local malware/profile access can steal the token. The extension keeps pending
metadata but does not persist sign-in URLs. After a click, the browser and target
site handle the URL; browser history/session/history-sync policies may apply.

If you back up the runtime, back up the configuration, credentials, encryption
key and a SQLite online backup together, and encrypt the backup. Restore the
matching key and DB, then clear queue/sessions before startup. An older restore
can resurrect previously revoked device hashes, so re-pair/revoke devices after
such a restore. Backup encryption protects off-host storage; it does not make
the live server independent of its own keys.

## What remains possible for an untrusted peer

The login page and minimal health endpoint are intentionally reachable by any
peer that can reach the proxy. Other endpoints require app credentials. Peers
can try to exhaust connections or the login attempt allowance; rate
limits/body/resource bounds reduce impact but do not promise denial-of-service
resistance. Restricting which devices may reach the HTTPS port (firewall rules,
VLANs or VPN access policies) is optional additional containment. On a shared
proxy port, such rules can affect other hosted apps.

This model covers this helper and its immediate ingress/storage paths; it does
not establish that every other application on the host or network is secure.
Keep browser/OS/container dependencies maintained, use HTTPS URLs, avoid disabling
certificate checks, and revoke a token when a browser profile is lost or exposed.

## Verification, 2026-10-28

These checks ran against the maintainer's reference deployment: Docker, Caddy
and a Tailscale network. Results on other deployments depend on their proxy,
certificate and network configuration.

Source/runtime review checked HTTPS-only extension requests, redirect refusal,
no URL persistence, token hashing/revocation, role separation, encrypted queue/
settings, CSRF/cookie/CSP controls, safe read-only IMAP and backup declarations.
Live probes verified certificate trust/hostname, TLS 1.3 and 1.2, backend isolation
on the network's IPv4/IPv6 addresses, unauthorized/invalid-token/forged-identity
rejection and foreign-origin login denial. File permissions, dependency audit and
secret scan were checked. Tests cover expiry/replay, spoofed senders/URLs, token
revocation and extension click behavior. These are scoped checks, not a proof
that no software vulnerability exists or a full penetration test from every peer.

Primary references: [Tailscale encryption](https://tailscale.com/kb/1504/encryption),
[Chrome extension storage](https://developer.chrome.com/docs/extensions/reference/api/storage),
[Chrome cross-origin requests](https://developer.chrome.com/docs/extensions/develop/concepts/network-requests).
