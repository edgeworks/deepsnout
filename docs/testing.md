# Verification report - 0.1.0a2

## Automated verification

The current GitHub Actions run for commit `ec9130982f7885ea2e1bd354b1cfe408c48c499a`
passed all three jobs: the Python suite against SQLite, the same suite against
PostgreSQL, and the disposable Compose deployment.

The Compose job builds the Python, PostgreSQL and Caddy images, starts the complete
stack, exports the generated DeepSnout Local CA root, verifies the HTTPS endpoint
with that CA (not with certificate verification disabled), verifies the HTTP-to-HTTPS
redirect, checks that the public CA download matches the generated root, completes
first-run setup/login/demo analysis/removal through Caddy, rejects an unsafe
Caddyfile-shaped public-host value, and reruns the interrupted PostgreSQL-bootstrap
recovery regression.

The first Caddy publication run proved the container path but failed the Python
jobs only because a CLI test still expected version `0.1.0a1`; the package correctly
reported `0.1.0a2`. The assertion now follows the package version and the complete
rerun passed.

The Python test command is:

```sh
python -m pytest --cov=deepsnout --cov-report=term-missing -W error::sqlalchemy.exc.SAWarning
```

It covers safe parsing, source time/identity, replay handling, peer qualification,
same-day exclusion, scoped expectations, capacities, retention, source
pagination/failure rollback, role/CSRF controls, command privacy, settings, account
recovery, secret separation and GUI routes/decisions.

## Earlier local verification

Before the Caddy change, 107 tests passed locally with 88% statement coverage. A
live loopback test started the actual CLI web server and a separate CLI worker,
completed authenticated HTTP requests, and waited for the worker to produce the
two synthetic findings. A wheel build with `--no-deps --no-build-isolation`
verified package assembly.

Actual GUI responses were rendered with Chromium at desktop and mobile sizes. The
inbox fit a 420px viewport without horizontal overflow. That was offline rendering
of responses obtained from the live service, not interactive browser end-to-end
certification. HTTP mutation flows are covered by TestClient tests.

The Caddy/Compose path itself is now tested in GitHub Actions rather than claimed
from that earlier local environment.

## Runtime boundary

The container/CI path installs the pinned direct dependencies declared in
`pyproject.toml` on Python 3.13 and exercises PostgreSQL 17 plus the pinned Caddy
image. Passing CI establishes compatibility for the exercised paths; it is not an
independent security audit or a production-capacity certification.

No real Splunk deployment is available to GitHub Actions. Splunk behavior is
covered with contract/mock tests only until an operator pilot exercises the actual
management/search API, certificate chain, permissions, sourcetypes and event
formats.

The bundled Caddy test validates the generated local-CA chain and the HTTPS
application flow for `localhost`. It does not validate an organization's PKI,
firewall, DNS, proxy, TLS inspection or browser policy.

## Synthetic timing

`tools/benchmark.py` records one short SQLite ingestion run for 5,000 synthetic
records across 100 host identities. No production-shaped benchmark is claimed.
This excludes actual Splunk retrieval, PostgreSQL history, new-process-heavy
workloads, concurrent users and sustained load. It is NOT a capacity estimate for
2,000-3,000 endpoints. State cardinality and retention need an actual pilot.

## Remaining acceptance gates

In a controlled operator environment:

- configure one real browser-facing DNS name/IP and validate bootstrap CA behavior;
- test restart and persistence of `caddy-data`, application secrets and PostgreSQL;
- import sanitized real Sysmon XML and compare source counts/identity;
- exercise Splunk token/custom-CA failures, restart and backfill;
- start with one endpoint using the GUI Computer selection pattern;
- assess findings against reviewed known/normal examples;
- measure storage, queue growth and ingestion lag;
- validate backup and restore of database, app secrets and Caddy CA identity;
- then increase scope.

Evaluate useful findings per analyst decision rather than merely reducing alert
count.

## Publication notes

The parser explicitly rejects JSON deeper than 64 levels, including embedded
`_raw` JSON, while ignoring brackets inside quoted strings. Regression tests cover
arrays, objects, escaped strings and `_raw`.

The secret initializer creates exported DB credentials only when absent, verifies
existing contents and refuses mismatched secret volumes rather than silently
rotating a live database credential. The PostgreSQL bootstrap is packaged inside
its image so restrictive host checkout permissions do not prevent initialization;
the application health probe verifies a real login/query.

The current Compose deployment publishes only Caddy. FastAPI and PostgreSQL have
no standard host port. Caddy's local CA state persists in `caddy-data`; deleting
that volume changes the server trust identity.
