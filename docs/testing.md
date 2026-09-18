# Verification report - 0.1.0a12

## Automated verification

The 0.1.0a12 feature code is exercised by the Python suite against SQLite and
PostgreSQL. The final disposable Compose verification is tracked on the
release-head workflow run; the source manifest is checked in CI so published
integrity hashes cannot silently drift from tracked files.

The Compose job builds the Python, PostgreSQL and Caddy images, starts the complete
stack, exports the generated DeepSnout Local CA root, verifies the HTTPS endpoint
with that CA (not with certificate verification disabled), verifies the HTTP-to-HTTPS
redirect, checks that the public CA download matches the generated root, completes
first-run setup/login/demo analysis/removal through Caddy, rejects an unsafe
Caddyfile-shaped public-host value, and reruns the interrupted PostgreSQL-bootstrap
recovery regression.

The Python test command is:

```sh
python -m pytest --cov=deepsnout --cov-report=term-missing -W error::sqlalchemy.exc.SAWarning
```

It covers safe parsing, source time/identity, XML and JSON Sysmon normalization,
common structured Windows-event JSON layouts, explicit payload-format enforcement,
replay handling, peer qualification, same-day exclusion, scoped expectations,
capacities, retention, Splunk source pagination/failure rollback, source TLS-pin
configuration/fingerprint extraction, role/CSRF controls, command privacy,
settings, account recovery, secret separation and GUI routes/decisions.

Automatic peer-group tests exercise immediate same-day provisional discovery,
multi-channel application/process/activity profiles, recurring application-pair
explanations, approval and automatic membership, rejection-memory fingerprints,
manual groups and the safety transition from provisional non-suppressive evidence to
stable suppressive evidence. Regressions also verify that Windows/platform-only
similarity is classified as a non-suppressive technical cluster and that missing or
unknown parents do not become `->child.exe` grouping signals. GUI coverage includes
the Peer Groups page, creation of a manual group, managed endpoint assignment and
viewer write restrictions. These are synthetic grouping fixtures, not a claim that
the current thresholds are validated for arbitrary enterprise fleets.

Environment-specific JSON semantics are exercised separately through the built-in
compatibility-adapter seam. Regressions cover the observed flat Cribl
`sourceMachineID`/`Name`/`Guid`/`Task` shape, trusted-provider/GUID detection,
Event 1/3/22 Task hints only when the corresponding payload signature corroborates
the type, supported symbolic IDs, and the observed unsupported Sysmon families
represented by Tasks 2, 4, 5, 6, 7, 8, 11, 12, 13, 15 and 16. Those unsupported
families are counted as ignored only when their event-specific payload signature
also matches. Known Tasks with incomplete/mismatched fields and unknown Tasks remain
malformed. `ID=IMAGE_LOAD` is a separately verified unsupported symbolic case.
Trusted flat Sysmon records with `Task=255` and a symbolic error subtype are treated
as unsupported when they do not look like a supported Event 1/3/22 payload; negative
tests prevent a Task-255 symbol from masking a supported-looking payload. A flat
non-Sysmon Windows provider in a mixed sourcetype remains ignored rather than being
interpreted with Sysmon rules. The core parser does not treat generic `ID`/`id` or
`Task` as EventID.

Splunk malformed-event diagnostics are regression-tested as grouped failure
signatures rather than only the first 20 records. Repeated failures are counted,
later distinct signatures remain visible, and each group keeps bounded sample
pointers/schema/candidate details without persisting full `_raw` or CommandLine.

The pinned-TLS implementation was also exercised during development against a
local HTTPS server with a self-signed certificate whose hostname deliberately did
not match: the configured exact leaf SHA-256 succeeded and a wrong fingerprint
failed hard. GitHub Actions does not provide a live Splunk service, so this is a
transport test rather than Splunk compatibility certification.

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
covered with contract/mock tests until an operator pilot exercises the actual
management/search API, certificate mode, permissions, sourcetype and event format.
The JSON normalizer intentionally accepts several common representations, while
unusual collector-specific semantics belong in explicit compatibility adapters;
neither layer can infer arbitrary organization-specific field renames without a
real sample.

The bundled Caddy test validates the generated local-CA chain and the HTTPS
application flow for `localhost`. It does not validate an organization's PKI,
firewall, DNS, proxy, TLS inspection or browser policy.

## Synthetic timing

`tools/benchmark.py` records one short SQLite ingestion run for 5,000 synthetic
records across 100 host identities. No production-shaped benchmark is claimed.
This excludes actual Splunk retrieval, PostgreSQL history, new-process-heavy
workloads, concurrent users, peer-group discovery and sustained load. It is NOT a
capacity estimate for 2,000-3,000 endpoints. State cardinality and retention need
an actual pilot.

## Remaining acceptance gates

In a controlled operator environment:

- configure one real browser-facing DNS name/IP and validate bootstrap CA behavior;
- test restart and persistence of `caddy-data`, application secrets and PostgreSQL;
- import or poll sanitized real Sysmon XML/JSON and compare source counts/identity;
- exercise a real Splunk token, strict custom-CA or pinned-certificate mode, restart
  and backfill;
- for Cribl-transformed input, inspect real Event 1, 3 and 22 payloads and confirm
  Computer/MachineName/sourceMachineID, original timestamp, ProcessGuid and required
  network/DNS fields;
- review recommended peer groups and technical clusters against actual organizational
  roles, especially early/provisional groups, and measure discovery runtime at real
  fleet size;
- assess findings against reviewed known/normal examples;
- measure storage, queue growth and ingestion lag;
- validate backup and restore of database, app secrets and Caddy CA identity;
- then increase scope.

Evaluate useful findings per analyst decision rather than merely reducing alert
count.

## Publication notes

The parser explicitly rejects JSON deeper than 64 levels, including embedded
`_raw` JSON, while ignoring brackets inside quoted strings. Regression tests cover
arrays, objects, escaped strings, `_raw`, explicit JSON/XML source modes, common
structured JSON layouts and the registered compatibility adapters.

The secret initializer creates exported DB credentials only when absent, verifies
existing contents and refuses mismatched secret volumes rather than silently
rotating a live database credential. The PostgreSQL bootstrap is packaged inside
its image so restrictive host checkout permissions do not prevent initialization;
the application health probe verifies a real login/query.

The current Compose deployment publishes only Caddy. FastAPI and PostgreSQL have
no standard host port. Caddy's local CA state persists in `caddy-data`; deleting
that volume changes the server trust identity.
