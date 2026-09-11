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
audit and limited container privileges.

Private source origins/custom CA are privileged administrator choices. Network
restrictions are still required; no claim of protection against all malicious-admin
SSRF/DNS-rebinding scenarios is made. Do not mount the Docker socket or add a shell.

HTTP is loopback evaluation only. Shared operation needs HTTPS, secure cookies,
explicit allowed hosts and access controls. Throttling is single-process. No SSO,
MFA, multi-tenant isolation or assurance of production hardening exists yet.
Source references, paths, DNS samples and backups may remain sensitive even though
raw commands are discarded. Do not import arbitrary serialized ML objects; there
is no model-import path in this release.

Before broader use: verify actual telemetry/Splunk behavior, calibrate detectors,
load-test cardinality/queue/storage, inspect source permissions, scan dependencies,
and exercise backup/recovery. Unit tests do not replace those checks.
