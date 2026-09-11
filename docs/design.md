# Architecture and invariants

## Modules

`normalize.py`: untrusted source records -> versioned compact Event.
`features.py`: offline public-suffix grouping and fixed-size diversity.
`engine.py`: reference comparison and deterministic findings.
`splunk.py`: read-only search adapter. `worker.py`: durable jobs and one analysis
writer. `web.py`: authenticated GUI. `db.py`: relational persistence.
`config.py`: validated policy. `security.py`: hashes, sessions and secret storage.

Python/FastAPI, Jinja, SQLAlchemy and PostgreSQL. SQLite is a development/test
alternative. No broker, Redis, Node build chain, vector DB or externally loaded UI.
A PostgreSQL session advisory lock prevents accidental parallel analysis writers;
SQLite development uses flock. Normal GUI writes remain transactional.

## Collection and commit

The worker retrieves a bounded Splunk index-time slice outside the transaction,
validates completeness, then commits normalized observations, finding changes,
batch receipt and source cursor together. Failure does not advance the cursor.
Restarted jobs can replay against receipts. The queue is capped at 20 pending jobs;
one pending job per source is coalesced. Source changes invalidate in-flight data.

Original event time drives history. Splunk index time drives collection progress.
Missing event time is an error, not a fabricated current timestamp. Older-than-
reference and future-clock events are counted explicitly. Historical accepted
records build baseline; only recent 24-hour activity generates findings.

## Identity

Original Computer takes precedence over collector host; fallback is warned.
Namespace + consistent hostname identifies an endpoint. Operators must avoid
aliases/hostname collisions; reimage identity resolution is not implemented.
Record IDs can reset, so fingerprints incorporate time and content identity, not
just an ID. Collector receipt time does not change a fingerprint.

Process attribution uses endpoint + ProcessGuid, not PID or timing. Creation can
fill a network placeholder on delayed arrival. A network timestamp before creation
is not displayed as a subsequent action. Parent fields are reported from Event 1,
not claimed to be an independently verified multi-hop process tree.

Behavior context = application basename, parent basename, image-location class
and fixed command flags. Hash/version churn alone does not change it. This modest
v1 identity can conflate same-named binaries in the same class, and a path class is
not a verified writable ACL. Hashes and original source references remain evidence.

## Stored data and privacy

Hosts, cohort labels and observed-day source coverage; fingerprints; process GUID
metadata, redacted image and SHA-256; endpoint/context/day summaries; application/
location/type/30-minute network windows; frozen finding evidence and analyst audit.

Each window uses a 256-byte HyperLogLog (344 characters base64, roughly 6.5%
standard error) plus five representative exact destinations. These are comparison
estimates, not exact forensic totals. DNS groups use the system libpsl Public Suffix
List including private rules. Without it the safe fallback is the exact domain,
never the final two labels guessed as an ownership boundary.

Full raw logs and commands are not persisted. Commands are inspected up to 32768
characters, reduced to flags, and included in the one-way event fingerprint.
This is not an anonymity guarantee. Hosts, paths, destination samples, source
references and notes may still be sensitive. Only the first user-profile path
segment is masked; it is not comprehensive PII redaction. Restrict access/backups.
Normalized queued imports retain compact records until success, then payloads are
cleared. Failed payloads expire with their job after seven days.

## Reference and decision semantics

Previous calendar days only, current day excluded. Default 28-day reference,
seven prior observed days. A single event on a day does not prove full-day coverage.
Peers require the same namespace/cohort and enough prior days running the app;
current endpoint excluded. No cohort means no invented peer comparison. Sparse
peers fall back to local history with explicit uncertainty.

One open finding per endpoint/detector/context. First evidence is frozen; later
support updates last-seen/count, not priority. IP and DNS shifts for the same app
share one network-finding context, not independent scores. This can combine
separate episodes within an unresolved context; finer episode segmentation is
future work. Open findings are never auto-closed by normality or age.

Expectations require exact endpoint/detector/context, owner, reason and expiry.
They do not delete observations. DS-EXEC-001 has no automatic expectation mechanism;
confirmed-malicious findings cannot directly become expected. Network expectations
scope app/location, not a destination allowlist. Detected shifts and analyst-marked
bad network windows are excluded from the network reference. Execution history
remains observational; stable malware can become familiar. This is a known blind
spot, not a solved baseline-poisoning problem.

## Bounds and retention

Default references 28d, inactive process joins 7d, exact fingerprints 48h, batch
receipts reference+1d, finished/failed jobs 7d, closed findings 90d, audit one year.
Open evidence is preserved. Host retirement is not automatic. Per-host/day context
caps appear in reports; global receipt-row capacity refuses the whole next batch
instead of silently consuming its checkpoint. That check conservatively reserves
space for the batch even when some records may later prove duplicated.

These are bounds on specific growth paths, NOT total database size. Application,
process and host cardinality and open findings can still grow; measure actual state.
PostgreSQL vacuum reuses deleted space but need not shrink a file immediately.

Identical retained imports and committed source slices have batch idempotency.
Recombined older imports beyond individual receipt retention can increase counts.
Cursor reset is explicit. Configured lag tolerates ordinary search visibility
delay, not arbitrarily late distributed-search visibility. No universal collection-
completeness guarantee is made. Backfill deliberately after outages.

## Schema and upgrades

Fresh schema version 1 is initialized; unknown versions are refused. There is no
automatic migration framework in this first release. Add explicit migrations and
upgrade/recovery tests before deploying a changed schema. Preserve PostgreSQL and
app secrets together. Do not mount the old Greycode Redis data here.
