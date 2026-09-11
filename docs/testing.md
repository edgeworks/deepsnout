# Verification report - 0.1.0a1

## Executed locally

106 tests passed. 88% statement coverage in the publication recheck. The run treats
SQLAlchemy SAWarning as an error, including the repeated demo-removal/reload
regression. Tests exercise safe parsing, source time/identity, replay handling,
peer qualification, same-day exclusion, scoped expectations, capacities, retention,
source pagination/failure rollback, role/CSRF controls, command privacy, settings,
account recovery, secret separation and GUI routes/decisions.

```sh
python -m pytest --cov=deepsnout --cov-report=term-missing -W error::sqlalchemy.exc.SAWarning
```

A live loopback test also started the actual CLI web server and a separate CLI
worker, completed authenticated HTTP requests, and waited for the worker to
produce the two synthetic findings. A wheel build with `--no-deps
--no-build-isolation` verified package assembly; that is not dependency installation.

Actual GUI responses were rendered with Chromium at desktop and mobile sizes.
The inbox fit a 420px viewport without horizontal overflow. This was OFFLINE
rendering of responses obtained from the live service, not an interactive browser
end-to-end run: this environment blocked browser loopback navigation. HTTP mutation
flows are covered by TestClient tests. No claim of browser automation certification.

## Runtime boundary

Local interpreter: Python 3.13.5. Locally available FastAPI 0.128.2, Starlette 0.50.0,
SQLAlchemy 2.0.50, Uvicorn 0.48.0, HTTPX 0.28.1, Pydantic 2.13.4, Jinja2 3.1.6,
python-multipart 0.0.29, cryptography 46.0.4 and argon2-cffi 25.1.0.

The release declares newer FastAPI 0.141.1 and Starlette 1.6.0 and psycopg 3.3.5.
Their releases were checked against primary package/project sources, but could not
be installed here because package-download networking was unavailable. Therefore
**the exact pinned container dependency combination is not locally validated**.
The provided CI installs that combination and must pass before wider deployment.

No Docker daemon, PostgreSQL server or real Splunk environment was available here.
Compose YAML and the database bootstrap shell script were checked structurally,
not executed as containers. PostgreSQL role initialization, its upsert/locking
paths and the full container first-run sequence are awaiting CI/live verification.
Mock Splunk contract tests are not a live-server compatibility test.

The original publication was denied with HTTP403. Repository access has since
been corrected. Check GitHub Actions for the current publication run; it contains SQLite/PostgreSQL tests, image build/start, and a
fresh-stack GUI setup/login/demo analysis/removal smoke test. Files on disk are not
proof of those jobs passing.

## Synthetic timing

`tools/benchmark.py` records one short SQLite ingestion run for 5,000 synthetic
records across 100 host identities. No completed benchmark result was captured in the initial archive; run it in
the target test environment and retain its output.
This excludes actual Splunk retrieval, PostgreSQL, long history, new-process-heavy
workloads, concurrent users and sustained load. It is NOT a capacity estimate for
2,000-3,000 endpoints. State cardinality and retention need an actual pilot.

## Remaining acceptance gates

Run included PostgreSQL/container CI; import sanitized real XML; compare source
counts and identity; exercise token/CA failures and restart/backfill; start with
one endpoint using the GUI Computer selection pattern; assess novelty/findings
against reviewed examples; measure storage and queue growth; validate backup and
restore; then increase scope. Investigate useful-findings-per-decision rather than
optimizing merely for a smaller alert count.

## Publication recheck

Before publication, a fresh local run exposed a nesting-limit test that relied on
the JSON decoder's recursion behavior. Parsing now rejects JSON deeper than 64
levels explicitly (including embedded `_raw` JSON), ignoring brackets in quoted
strings. Regression tests cover arrays, objects, escaped strings and `_raw`.
The latest raw test output is in `docs/test-output.txt`. Three SQLite connection
ResourceWarnings remain in the test harness; no SQLAlchemy SAWarning was allowed.
The release source omits generated screenshots and the empty benchmark output;
application functionality is unchanged apart from the parser hardening.
