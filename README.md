# DeepSnout

**Local-first security analytics. A nose for the unusual.**

DeepSnout turns existing endpoint telemetry into explainable investigation
findings. It compares recent behavior with local history and suitable application
peers rather than ranking computers by lifetime counts of rare hashes or IPs.

**Status: 0.1.0a15, initial runnable pilot.** Not a validated EDR, a SIEM, a
production-capacity promise, or a probability-of-compromise model. Start with a
limited source and known examples. See [the exact verification boundary](docs/testing.md).

## Implemented

- Standard Sysmon 1, 3 and 22 in XML, flat/nested JSON, Splunk result wrappers,
  NDJSON, and English rendered event text. Common structured JSON forms stay in
  the transport-neutral normalizer; environment-specific JSON quirks live in a
  small registered compatibility-adapter layer. The observed flat Cribl
  `sourceMachineID`/`Name`/`Guid`/`Task`/`ID` dialect is handled there rather than
  teaching the core parser that generic `Task` or `ID` means EventID. Verified
  unsupported flat Sysmon shapes (including observed Tasks 2, 4, 5, 6, 7, 8, 11,
  12, 13, 15 and 16, plus observed Event-255 symbolic error IDs) are ignored only
  when their source-specific evidence corroborates the classification;
  unknown/mismatched shapes still fail closed. The observed flat Cribl Sysmon Task 15
FileCreateStreamHash shape may omit `Contents`; DeepSnout recognizes it using the
remaining stable Event 15 payload fields. No binary EVTX reader.
- GUI-configured **Splunk search-API pull** with encrypted credentials, strict
  CA/hostname TLS by default, an explicit per-source leaf-certificate pin mode
  for legacy management certificates, index-time checkpoints and failure without
  advancing the source cursor. Catch-up polling learns a safe slice duration per
  source/search profile up to a 15-minute default ceiling instead of repeatedly
  probing an oversized slice. The Auto search profile can recognize the verified
  flat-Cribl Sysmon adapter from supported events and then push a hard-coded
  Event 1/3/22 prefilter into Splunk; it periodically returns to a broad slice to
  revalidate the assumption. Result pages use 1,000 rows and scheduled peer-group
  discovery is deferred while a source is catching up. Historical catch-up older
  than the live finding horizon uses bulk baseline prefetching and skips temporary
  ProcessGuid/reference work that cannot create a current finding. Historical window finalization only touches summaries actually processed in the batch, avoiding failures when a preloaded window belongs to an event later skipped by retention/deduplication.
- Three local detectors: remote-execution characteristics; new launch contexts
  with exact-GUID-attributed outbound activity; sustained application-level
  destination-diversity changes. Findings have deterministic explanations.
- Explainable **automatic peer-group discovery** from bounded behavioral summaries.
  Suggestions begin as soon as useful endpoint observations exist rather than
  waiting for a 28-day baseline. The v2 layer compares broad application footprints,
  recurring application combinations, parent-child process ecology, application
  network roles and coarse activity patterns separately. Windows/platform signals
  are retained for technical-cluster discovery but do not make a group suitable for
  detector suppression. Narrow clusters such as a shared image or one product remain
  visible and are labelled technical; only analyst-approved, mature `recommended`
  automatic groups (or explicit manual groups) may provide suppressive peer-common
  evidence to DS-EXEC-002. Correlated app/parent/network signals are collapsed in
  explanations. See [Peer groups](docs/peer-groups.md).
- Durable single-writer jobs are visible under **Operations**, including queued/running state, source, runtime and operator cancellation. Running Splunk polls use cooperative cancellation and a 15-minute wall budget; cancellation never advances the checkpoint. Interrupted running jobs are explicitly recovered after worker restart.
- Prior-day references, qualified application peers, bounded evidence,
  temporary process metadata and fixed-size approximate diversity summaries.
- Investigation inbox, endpoint/discovery views, evidence export, decisions,
  exact-scope expiring expectations, source health, retention controls, audit and
  local administrator/analyst/viewer accounts.
- Synthetic demo through the **same parser and analysis engine**, clearly marked
  and removable from the GUI. It is not a canned list of findings.
- Bundled Caddy edge service: HTTPS from first boot, HTTP-to-HTTPS redirect and a
  persistent DeepSnout Local CA. FastAPI and PostgreSQL are not directly published.

No VirusTotal, external reputation feeds, LLM, tracking, font CDN, model downloads
or cloud inference is required or implemented. No endpoint agent is shipped.
WEF/Elastic transports and experimental local ML remain future work.

## Quick start: Linux containers

Install Docker Engine/Desktop with the **Compose v2 plugin**. Clone the repository:

```sh
git clone https://github.com/edgeworks/deepsnout.git
cd deepsnout
```

For a headless server, create `.env` and set the one browser-facing DNS name or IP:

```sh
cp .env.example .env
# Edit DEEPSNOUT_PUBLIC_HOST, for example:
# DEEPSNOUT_PUBLIC_HOST=deepsnout.example.internal
# or DEEPSNOUT_PUBLIC_HOST=10.20.30.40
```

`DEEPSNOUT_PUBLIC_HOST` becomes both the Caddy certificate identity and an allowed
HTTP Host. The initial configuration deliberately supports one primary name/address;
additional application Host aliases do not automatically receive certificates.

Start the stack and retrieve the first-run token:

```sh
docker compose up --build -d
docker compose exec web deepsnout setup-token
```

Open **https://DEEPSNOUT_PUBLIC_HOST/**. Port 80 only redirects to HTTPS. On first
boot Caddy uses the persistent **DeepSnout Local CA**, so an administrator workstation
will normally show an untrusted-certificate warning until that CA is trusted or the
deployment is moved to an organization certificate.

To export only the public root certificate after Caddy has started:

```sh
docker compose exec -T caddy cat /data/caddy/pki/authorities/local/root.crt > deepsnout-local-ca.crt
docker compose exec -T caddy sha256sum /data/caddy/pki/authorities/local/root.crt
```

Transfer/trust the public certificate according to your workstation/organization
policy and verify its fingerprint over a trusted channel. **Never copy the CA private
key from the Caddy data volume.** It can issue certificates trusted by any workstation
that trusts this root.

Paste the one-time setup token and create the first administrator. There is no
shared/default password. Try **Import & demo -> Load synthetic demo**, inspect its
job report, then open the investigation inbox.

Next configure a limited real connection under **Sources**, test, poll once, and
inspect the result before enabling scheduling. [Splunk guide](docs/splunk.md).

Compose provides Caddy, PostgreSQL, two Python services (web and analysis worker),
and two one-shot initialization jobs. Only Caddy publishes host ports (80/443;
443/UDP enables HTTP/3). Secrets, DB state and Caddy PKI state persist in named
volumes; `docker compose down` retains them. **`docker compose down -v` destroys
them.** The initial image build downloads packages/images; local analysis does not
require external connectivity after deployment. The operator-configured Splunk
connection is the intentional network dependency for collection.

If your network requires an outbound proxy while building images, configure the
Docker daemon/builder or preserve the proxy environment and pass standard proxy
build arguments. Do not bake proxy credentials into the Dockerfiles.

## Why this architecture?

Python/FastAPI and Jinja keep the code approachable without a frontend build
system. PostgreSQL provides transactions, durable jobs and checkpoints without
adding Redis/Celery/Kafka. Caddy owns the browser-facing TLS protocol and local PKI
instead of teaching the application server to manage certificates. One analysis
writer makes ordering explicit. SQLite supports local development/tests;
**PostgreSQL is the deployment target**.

Full commands are inspected transiently and replaced by flags; original source
references remain available. There is no permanent raw-event archive. Read
[the data model, privacy and limits](docs/design.md).

## Initial detectors

| Detector | Investigation question |
| --- | --- |
| DS-EXEC-001 | Why does this scripting-capable process combine a remote reference with an execution primitive? |
| DS-EXEC-002 | Why is a new launch context making an attributable outbound connection? |
| DS-NET-001 | Why did this application's destination diversity exceed its prior range for two consecutive windows? |

A rare domain, changing software hash or sparse history alone does not create a
review card. Common software is not automatically trusted. Open findings do not
vanish because activity becomes common. [Precise detector semantics](docs/detectors.md).

## Development

Python 3.12+ on Linux/macOS; the application container uses Python 3.13:

```sh
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
python -m pytest
# Terminal 1: local SQLite HTTP development only
python -m deepsnout.cli serve
# Terminal 2
python -m deepsnout.cli worker
python -m deepsnout.cli setup-token
```

The direct development server is intentionally separate from the Compose deployment;
Compose is HTTPS through Caddy. CI exercises SQLite, a disposable PostgreSQL DB,
the Caddy certificate chain/redirect, and the Compose stack. Mock Splunk tests are
not certification against your deployment.

## Faster mixed-age polling (v0.1.0a25)

DeepSnout's Splunk source may deliver events within one index-time
slice whose actual event timestamps span more than 24 hours. Previously,
one recent event forced the full slice through expensive live
reference queries and process tracking. The worker now uses the
historical fast path for older observations and live evaluation only
for recent ones. Both portions run within **one transaction** with
one batch receipt and source checkpoint. On error or cancellation,
neither portion or the checkpoint is committed.

The Operations job report separates historical and live event counts
and ingestion seconds. While the PostgreSQL worker ingests, its
existing heartbeat exposes processing stages and numeric counts.
This does not change any detection thresholds and requires no
database migration. Rebuilding the worker image is necessary; the
speedup has been tested functionally with synthetic data but depends
on the age composition of actual source batches.

## DeepSnout finding-quality self-diagnosis (v0.1.0a24)

The **Finding quality** page is an independent, read-only view of
the past seven days' non-demo findings. DeepSnout automatically
discovers recurring application/parent/location patterns, including
version-number churn across different executable basenames, and
highlights when a family dominates the finding stream. It does not
use product-name signatures, threat allowlists, or internet lookups.
Original alerts stay open with their existing states and priorities.

The worker runs this diagnostic approximately hourly once source
catch-up is complete. You can open **Finding quality -> Refresh
analysis** to analyze already-existing findings immediately. Every
family links to an internal page of supporting original findings.
The separate authenticated endpoint `/api/finding-quality/metrics`
is counts-only and suitable for constrained sharing review.

A common pattern is not necessarily legitimate: deliberate attackers
can produce the same broad repetition. The analysis identifies
redundancy and rollout-like structure, not proven benign software.
The snapshot has a 20,000-finding input cap (explicit failure rather
than silent truncation), a top-30-family display, a seven-day
observation window, and no schema migration. This release does not
resolve existing false positives automatically.

## Review hundreds of findings in a table (v0.1.0a23)

Open **Findings table** in the left navigation (or the table link from
the investigation inbox). The separate table lists Last seen, Detector,
Hostname, Parent, Process (path) and Trigger. You can sort any column,
filter by detector and status, narrow DS-BEH-001 to 'Rare application'
versus 'Rare launch relationship', or search hostnames, parent names
and process paths. Click a hostname to open the original finding.

Use **Export full CSV** for on-premises review, or
**Export privacy-reduced CSV** to help compare false-positive patterns
without exporting raw hostnames or directory paths. A new host alias
is generated per export, consistent across rows in that export.
Privacy-reduced paths retain only the process location class and
executable basename; timestamps are reduced to dates. Bespoke program
names and other remaining values may still be identifying: inspect the
file before sharing outside your organization. Exports honor active
filters, contain all matching findings (not only one table page), and
reject requests exceeding 10,000 rows rather than silently truncating.

The parent process is the retained basename, not its full path. For
DS-NET-001 the original evidence has only an application basename
without a process path, so the table reports that limitation instead
of inventing a path. The original card view, detail pages and all
detectors remain unchanged.

## Understanding zero findings

From v0.1.0a22, the authenticated
`/api/behavioral-discovery/metrics` endpoint includes a counts-only
`evaluation_pipeline_last_7d` section. It shows how many accepted
process-create events were historical, older than the live finding horizon,
recent, stopped by local-history/familiarity or fleet-coverage checks, or
identified as candidates for a rarity finding. This diagnostic is useful
even when `findings_total` is zero: an empty detection inbox does not
prove that no eligible process events were assessed. The numbers count
accepted events, not unique hosts, and begin accumulating after the
updated build is deployed. No detector behavior is relaxed.

## Environment-relative anomaly discovery

In v0.1.0a21, DS-BEH-001 discovers rare application execution and uncommon
parent/application/location patterns compared with this environment's
prior-day Sysmon observations. It does not require network activity, a
known suspicious executable or an ATT&CK technique. Findings explain local
novelty, fleet frequency and optional (nonsuppressive) learned peer context.
The GUI Settings page exposes thresholds, and the authenticated
`/api/behavioral-discovery/metrics` endpoint reports counts only.

Unlike prior shadow work, this detector produces review-priority findings
by default. Normal software rollouts and data gaps can trigger it; operators
should measure the first week's finding volume and review a sample locally.
It is not a compromise classifier and makes no external data requests.

## Shadow peer-reference evaluation

Version 0.1.0a20 extends the read-only `deepsnout validate-cohorts`
command with a counts-only `shadow_reference_pools` summary.
It compares two exploratory residual similarity thresholds, prioritizes
at most one process and one network reference population per host,
and reports remaining candidate coverage and membership redundancy.
No live detector is changed or allowed to suppress based on this output.
The output does not yet verify application-specific DS-EXEC-002 peer
qualification or future detector accuracy.

## Read-only historical cohort evaluation

To evaluate exploratory comparison cohorts on non-overlapping historical
periods in your own deployment, run:

`docker compose exec -T worker deepsnout validate-cohorts`

It learns groups from 21 completed UTC days and evaluates frozen members on
seven subsequent completed days. Only aggregate counts and similarity
metrics are printed. The manual command does not write to the database,
modify detectors or approve groups; it adds database read load, so avoid
active ingestion catch-up periods.

## Deliberate boundaries

No SSO/MFA, automated remediation, long-term exact IOC inventory, alert email
engine, trained ML model, automatic offline update bundle or GUI disaster-recovery
restore. Automatic peer grouping is deterministic similarity discovery rather than
a learned classifier. Executable basenames are not product identities, so suites
with several helper processes can still appear broader than they really are; full
prototype/membership drift protection remains a focused follow-up. Observed history
is not necessarily benign. Missing joins, limited history, retention, cardinality
and source lag remain important limitations. No 3,000-endpoint throughput claim is
made.

The bundled Caddy mode currently uses DeepSnout's local CA. GUI upload/activation of
an organization certificate and automated public/internal ACME are **not implemented
yet**; those will be added without making the FastAPI service own the TLS private
key. See [deployment](docs/deployment.md).

Future enrichment stays optional and entitlement-aware. A possible VirusTotal
adapter uses **one configured account**, deduplication, cache, explicit budgets,
pacing and backoff. It never rotates accounts to evade limits or markets a free
license workaround. Provider terms and any operator agreement must permit the
actual use: respecting a rate limit is not permission. See
[enrichment policy](docs/enrichment-policy.md).

Project code is [MIT licensed](LICENSE). Dependency licenses remain their own.
The offline Public Suffix List comes from system `libpsl`; availability/fallback
is shown in Operations. [Contributing](CONTRIBUTING.md) | [Security](SECURITY.md) |
[Product brief](docs/product-brief.md) | [Peer groups](docs/peer-groups.md).
