# DeepSnout

**Local-first security analytics. A nose for the unusual.**

DeepSnout turns existing endpoint telemetry into explainable investigation
findings. It compares recent behavior with local history and suitable application
peers rather than ranking computers by lifetime counts of rare hashes or IPs.

**Status: 0.1.0a1, initial runnable pilot.** Not a validated EDR, a SIEM, a
production-capacity promise, or a probability-of-compromise model. Start with a
limited source and known examples. See [the exact verification boundary](docs/testing.md).

## Implemented

- Standard Sysmon 1, 3 and 22 in XML, flat/nested JSON, Splunk result wrappers,
  NDJSON, and English rendered event text. XML preferred; no binary EVTX reader.
- GUI-configured **Splunk search-API pull** with encrypted credentials, verified
  TLS/custom CA, index-time checkpoints, pagination, adaptive slices and failure
  without advancing the source cursor.
- Three local detectors: remote-execution characteristics; new launch contexts
  with exact-GUID-attributed outbound activity; sustained application-level
  destination-diversity changes. Findings have deterministic explanations.
- Prior-day references, qualified cohort/application peers, bounded evidence,
  temporary process metadata and fixed-size approximate diversity summaries.
- Investigation inbox, endpoint/discovery views, evidence export, decisions,
  exact-scope expiring expectations, source health, retention controls, audit and
  local administrator/analyst/viewer accounts.
- Synthetic demo through the **same parser and analysis engine**, clearly marked
  and removable from the GUI. It is not a canned list of findings.

No VirusTotal, external reputation feeds, LLM, tracking, font CDN, model downloads
or cloud inference is required or implemented. No endpoint agent is shipped.
WEF/Elastic transports and experimental local ML remain future work.

## Quick start: Linux containers

Install Docker Engine/Desktop with the **Compose v2 plugin**. Clone the repository and enter the directory containing `compose.yaml`:

```sh
git clone https://github.com/edgeworks/deepsnout.git
cd deepsnout
```

Then start the stack:

```sh
docker compose up --build -d
docker compose exec web deepsnout setup-token
```

Open **http://localhost:8080**, paste the one-time token and create your first
administrator. There is no shared/default password. Try **Import & demo -> Load
synthetic demo**, inspect its job report, then open the investigation inbox.

Next configure a limited real connection under **Sources**, test, poll once, and
inspect the result before enabling scheduling. [Splunk guide](docs/splunk.md).

Default HTTP binds **only to loopback**. For a remote host, use an SSH tunnel
(`ssh -L 8080:127.0.0.1:8080 host`) or a trusted HTTPS reverse proxy. Read
[deployment](docs/deployment.md) before exposing it to other users. Do not publish
the unencrypted default port on an untrusted network.

Compose provides PostgreSQL, two Python services (web and analysis worker), and
two one-shot initialization jobs. Secrets and DB state persist in named volumes;
`docker compose down` retains them. **`docker compose down -v` destroys them.**
The initial image build downloads packages/images; local analysis does not require
external connectivity after deployment. The operator-configured Splunk connection
is the intentional network dependency for collection.

## Why this architecture?

Python/FastAPI and Jinja keep the code approachable without a frontend build
system. PostgreSQL provides transactions, durable jobs and checkpoints without
adding Redis/Celery/Kafka. One analysis writer makes ordering explicit. SQLite
supports local development/tests; **PostgreSQL is the deployment target**.

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

Python 3.12+ on Linux/macOS; the container uses Python 3.13:

```sh
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
python -m pytest
# Terminal 1: local SQLite development
python -m deepsnout.cli serve
# Terminal 2
python -m deepsnout.cli worker
# Setup token for http://localhost:8000
python -m deepsnout.cli setup-token
```

CI configuration exercises SQLite, a disposable PostgreSQL DB and the Compose
stack. Check the Actions tab for the result of the current commit. Mock Splunk tests
are not certification against your deployment. The testing report distinguishes
locally tested libraries from newer container pins.

## Deliberate boundaries

No SSO/MFA, automated remediation, fleetwide rollout clustering, long-term exact
IOC inventory, alert email engine, trained ML model, automatic offline update
bundle or GUI disaster-recovery restore. Observed history is not necessarily
benign. Missing joins, limited history, retention, cardinality and source lag
remain important limitations. No 3,000-endpoint throughput claim is made.

Future enrichment stays optional and entitlement-aware. A possible VirusTotal
adapter uses **one configured account**, deduplication, cache, explicit budgets,
pacing and backoff. It never rotates accounts to evade limits or markets a free
license workaround. Provider terms and any operator agreement must permit the
actual use: respecting a rate limit is not permission. See
[enrichment policy](docs/enrichment-policy.md).

Project code is [MIT licensed](LICENSE). Dependency licenses remain their own.
The offline Public Suffix List comes from system `libpsl`; availability/fallback
is shown in Operations. [Contributing](CONTRIBUTING.md) | [Security](SECURITY.md) |
[Product brief](docs/product-brief.md).
