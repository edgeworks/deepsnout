# Security and reporting

This pre-release security application has not had an independent security audit.
Do not post real tokens, private logs or operational details in public issues.
Use private vulnerability reporting in the repository Security tab if enabled;
otherwise request a private contact without exposing the vulnerability details.

Implemented: random private first-run token, Argon2 password hashes, revocable
server sessions, admin/analyst/viewer roles, signed double-submit CSRF, explicit
host allowlist, escaped templates, self-only CSP, request/queue caps, safe XML,
no executed telemetry, encrypted source credentials, verified outbound TLS/no
credential-following redirects, transactional cursors, isolated demo namespace,
audit and limited application-container privileges.

Splunk sources use CA and hostname verification by default. A source administrator
can explicitly select a legacy **pinned leaf certificate** mode for an HTTPS
management endpoint whose certificate has no usable hostname identity. This is
not a global TLS-ignore switch: the source requires an exact SHA-256 fingerprint,
an unauthenticated preflight verifies that leaf before DeepSnout adds the Splunk
Authorization header, and authenticated responses are checked against the same
pin. Certificate replacement intentionally fails closed until an administrator
verifies and updates the pin. Keep internal Splunk management traffic direct
rather than making a TLS-intercepting proxy part of the trusted path where
possible.

The standard Compose deployment exposes only bundled Caddy on ports 80/443.
Port 80 redirects to HTTPS; FastAPI and PostgreSQL are not directly published.
Caddy uses a persistent DeepSnout Local CA for bootstrap TLS. The CA private key
in `caddy-data` is highly sensitive: anyone who obtains it can mint certificates
trusted by clients that trust that root. Back it up securely and never distribute it.

Private source origins/custom CA/certificate pins are privileged administrator
choices. Network restrictions are still required; no claim of protection against
all malicious-admin SSRF/DNS-rebinding scenarios is made. Do not mount the Docker
socket or add a shell.

HTTPS protects transport but does not make the pilot safe for unrestricted Internet
exposure. Restrict the listener to intended analyst/admin networks. The bootstrap
CA is untrusted until deliberately installed; verify its public-root fingerprint
through a trusted channel before adding it to client trust stores. GUI organization-
certificate management and ACME are not yet implemented. Throttling is single-process.
No SSO, MFA, multi-tenant isolation or assurance of production hardening exists yet.

Source references, paths, DNS samples and backups may remain sensitive even though
raw commands are discarded. Do not import arbitrary serialized ML objects; there
is no model-import path in this release.

Before broader use: verify actual telemetry/Splunk behavior, calibrate detectors,
load-test cardinality/queue/storage, inspect source permissions, scan dependencies,
and exercise backup/recovery. Unit tests do not replace those checks.
