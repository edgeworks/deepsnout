# Verification report - 0.1.0a23

## Sortable findings table and controlled CSV export (0.1.0a23)

The original card-based investigation inbox remains available. A separate
authenticated `/findings/table` view shows six columns: last seen (UTC),
detector, hostname, parent executable basename, process image path and
a compact trigger description. The trigger for DS-BEH-001 includes the
relevant fleet rarity counts; DS-NET-001 includes observed destination
diversity versus prior p95. Data is drawn from frozen finding evidence,
not rebuilt from ingestion. A later repeat updates Last seen but not the
original evidence snapshot. Network findings do not retain a process
image path, so their application basename is labeled 'path unavailable'.

The table supports status, detector, behavioral category and literal
hostname/parent/process search; SQL-backed sortable columns and
100-row pages apply to all matching findings, not only the current page.
`/findings/table.csv` exports all filtered rows in the same order, up
to an explicit 10,000-row cap. Larger exports return HTTP 413 and must
be filtered; data is never silently truncated. The full CSV retains
internal hostnames and redacted image paths; a 'privacy-reduced' mode
generates new per-export HMAC host aliases, reduces timestamps to UTC
dates, and collapses process paths into normalized location classes
and executable basenames. These are still potentially identifying
(e.g., bespoke executable names); operators must inspect any CSV
before external sharing. Both exports are authenticated and include
spreadsheet formula-injection safeguards. Existing middleware prevents
caching and sets restrictive content and framing policies.

Synthetic tests cover each detector's evidence variant, mixed findings,
server-side JSON-field sorting on SQLite and PostgreSQL, category and
text filters, 100-row pagination vs complete CSV export, authenticated
access, CSV quoting/spreadsheet formulas, and the limits of the
privacy-reduced export. No schema migration, detector tuning, or new
external network calls are introduced.

## Observable environment-relative detection funnel (0.1.0a22)

The operational metrics endpoint now reports `evaluation_pipeline_last_7d`,
aggregated by **processing UTC day** rather than event time. Counters
distinguish accepted process creates, historical backfill, older-than-24h
events, live events, locally familiar behavior, insufficient local history,
missing usable app identity, insufficient fleet coverage, evaluated fleet
reference and unusual application/launch candidates. The output contains
counts only, no namespaces, hosts, processes or raw log fields. The
stored State JSON is bounded to seven processing UTC days and committed
in the same ingest transaction as the source observations. Replays that
were de-duplicated do not advance counters. Counts begin with the new
release; they are not a historical recomputation.

There is no change to detector thresholds, findings, policy defaults or
approval rules. This instrumentation answers why a freshly deployed
behavioral detector has zero findings without assuming zero anomalous
behavior or silently making it more sensitive. The counters are **events**,
not unique endpoints or distinct behavioral relationships. Live event
processing still requires event timestamps within 24 hours of ingestion.
Tests verify eligibility stages, historical vs live counts, count-only
metrics, and deduplicated replay behavior.

## Environment-relative behavioral discovery (0.1.0a21)

Added DS-BEH-001: a genuine detector for locally novel process execution
uncommon across the observed endpoint fleet. It needs no network connection,
ATT&CK mapping, attack signature or hand-built suspicious-executable list.
Two separate signals surface: previously rare application identities, and
parent/application/location triples rarely seen among hosts running a common
application. All fleet references use only previous UTC days in the same
source namespace; training windows exclude the triggering event.

The default requires seven prior locally observed process days and >=50
distinct hosts with prior Sysmon process-creation coverage. Application
rarity is <=max(2, floor(1% of fleet hosts)); common-app relationship
rarity is <=max(2, floor(2% of app hosts)) and requires the application
to have been seen on >=max(15, ceil(3% of fleet hosts)) hosts.
Fleet support counts use *any* prior process coverage, not complete
collection, so workstation onboarding and data gaps can affect prevalence.
All thresholds and detector enablement appear in GUI Settings.

Read-only supporting context can reference one currently screened cohort,
counting only peers that ran the same application on enough prior days.
This peer evidence never suppresses or gates the finding and does not
imply stable/independently verified peers. DS-EXEC-002 is unchanged.
The new detector creates a review-priority finding, grouping repetitions
by host/application for rare apps and by host/parent/app/location for
rare launch patterns. Exact host/detector/context expectations remain
reviewable; the underlying observations are retained.

An authenticated counts-only endpoint
`/api/behavioral-discovery/metrics` exposes detector volume and decision
states without hostnames or application names. Synthetic tests cover
signature-free findings, no-network discovery, local/fleet learning,
routine behavior, parent novelty, de-duplication, GUI controls and peer
comparison. Real-world false-positive volume and detection utility
remain unmeasured until operator tests.

## Shadow reference-pool prioritization (0.1.0a20)

A pure helper now uses frozen historical group membership and a disjoint
later-window comparison to select at most one preferred reference group
per host for process behavior and one for network behavior. Only groups
with training and later residual support are eligible. Reports show both
the existing 0.08 residual-advantage cutoff and a stricter 0.12 sensitivity
scenario. These are heuristic screening margins, not calibrated security
thresholds or validated detector quality.

The read-only `deepsnout validate-cohorts` command prints only aggregate
counts: the number of hosts with a preferred process/network comparison
population, the number of distinct groups used, and how many overlapping
candidate assignments are reduced. No user/group/host identifiers are
exposed. Application-specific peer eligibility and same-context prevalence
are NOT calculated. This is NOT enabled in detector code, and cannot
suppress findings. Tests use only synthetic populations with overlapping
memberships and confirm missing validation evidence fails closed.

The manual report is retrospective: using its holdout evidence to select
future reference candidates is not independent evaluation of those
selections. The next milestone should assess detector-context relevance
on a genuinely later observation window before promoting any policy.

## Release and historical validation (0.1.0a19)

The GUI uses the Python package __version__, which is bumped together with
pyproject.toml for every release. A version-consistency regression test checks
these sources against the GUI template.

The operator-only command `deepsnout validate-cohorts` evaluates cohorts on
genuinely disjoint historical data: the older 21 of the previous 28 completed
UTC days for training, then the subsequent seven for validation. Group
memberships are frozen from training; the later period cannot recruit peers.
The command reads local summary data without changing the database. Its JSON
contains only aggregate counts and similarity metrics, no hostnames, namespace
labels, application names or group IDs. Synthetic tests cover disjoint windows,
missing later observations and training-only signals.

This manual diagnostic adds database read load and is not part of the normal
hourly discovery job. The organization must validate the results locally;
synthetic tests do not establish five-thousand-host runtime or detection
performance. Review aggregate results under your local sharing policy.

## Automatic comparison-cohort milestone

New synthetic tests target 5,000 generated in-memory host profiles, verify
overlapping/non-suppressive analytical strata, and bound pairwise candidate
generation. This is NOT verification of real telemetry quality, five-thousand-host
runtime, PostgreSQL storage throughput, or memory performance. The new code
requires a fresh CI run and operator validation after Splunk catch-up.

The residual matched-control diagnostic adds synthetic negative controls
where process/network features are solely consequences of seed executables,
plus tests for comparable outside hosts, unavailable controls and overlap
cardinality. The supported label is provisional; the experiment has not been
validated with temporally held-out organizational telemetry.

The new application-pair shadow discovery has synthetic tests for actual shared
features, absent corroborating behavior, sparse history and deterministic
5,000-host input. No production dataset or endpoint telemetry was uploaded
or executed externally. These tests do not establish grouping quality or
full-fleet capacity on the user's infrastructure.

The quality-diagnostic follow-up measures capped within-cohort versus fleet
feature-set overlap in four independent views. Synthetic tests verify that
identical feature counts cannot masquerade as identical features, empty
channels remain unscorable, and reports expose neither names nor IDs.
A successful test is not evidence of population similarity in production.

For the operator: refresh Peer Groups, review the automatic cohort coverage,
inspect the authenticated /api/peer-groups/metrics report, and collect refresh
runtime and memory/CPU observations. Never run the destructive pytest fixture
against the production PostgreSQL instance.

## Automated verification

The 0.1.0a22 feature code is exercised by the Python suite against SQLite and
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

Peer-group input processing now streams projected BehaviorDay/Window rows in bounded
batches and stores per-feature day presence as compact bitsets. Worker progress,
scheduled-attempt backoff, and interrupted-job recovery are exercised alongside the
existing job cancellation tests. Unexpected worker restarts fail the interrupted job
instead of silently replaying it in a crash loop; transactional checkpoints remain
unchanged.

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

A 0.1.0a18 regression covers the production KeyError where historical
window preloading included a summary whose event was later skipped by retention;
finalization must ignore untouched preloaded windows. Unexpected worker exceptions
now retain a traceback in container logs for diagnosis without logging local payload
values.

Historical catch-up regressions verify that batches older than the 24-hour
execution-finding horizon do not call the per-context reference() path, do not
retain temporary ProcessGuid state, and still create BehaviorDay baseline state.
The historical engine preloads existing host/coverage/behavior/window rows in
bounded ID chunks and flushes newly discovered hosts before dependent summaries,
so SQLite and PostgreSQL preserve foreign-key integrity.

Splunk catch-up regressions now cover hard-coded Cribl Event 1/3/22
search-profile pushdown, 1,000-row result pagination, adaptive slice metadata,
result-density span learning, and Auto profile promotion after a sufficiently large
supported Cribl sample. The worker persists learned spans separately per search
profile so the daily broad revalidation does not discard the optimized catch-up
window. Poll reports expose index-time progress and wall-time throughput; automatic
peer-group scheduling is deferred while an enabled source is behind. These are
contract/mock tests: the optimized SPL still requires validation against the pilot
Splunk/Cribl deployment.

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


Task-15 compatibility regression coverage includes the observed flat Cribl
FileCreateStreamHash variant where `Contents` is absent. Recognition still requires
ProcessGuid, Image, TargetFilename, CreationUtcTime and Hash; a Task-15 record missing
that corroborating payload remains malformed/fail-closed.
