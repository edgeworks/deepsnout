# DeepSnout

**Local-first security analytics. A nose for the unusual.**

DeepSnout turns existing endpoint telemetry into explainable investigation
findings. It compares recent behavior with local history and suitable application
peers rather than ranking computers by lifetime counts of rare hashes or IPs.

**Status: 0.1.0a10, initial runnable pilot.** Not a validated EDR, a SIEM, a
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
  unknown/mismatched shapes still fail closed. No binary EVTX reader.
- GUI-configured **Splunk search-API pull** with encrypted credentials, strict
  CA/hostname TLS by default, an explicit per-source leaf-certificate pin mode
  for legacy management certificates, index-time checkpoints, pagination,
  adaptive slices and failure without advancing the source cursor.
- Three local detectors: remote-execution characteristics; new launch contexts
  with exact-GUID-attributed outbound activity; sustained application-level
  destination-diversity changes. Findings have deterministic explanations.
- Explainable **automatic peer-group discovery** from bounded behavioral summaries.
  Suggestions begin as soon as useful endpoint observations exist rather than
  waiting for a 28-day baseline. Application prevalence, parent-child process
  relationships, path classes and coarse application network activity form sparse
  similarity profiles; fleet-common and singleton features are reduced or excluded.
  Analysts can approve/rename or reject suggestions, create manual groups and
  inspect/search group members. Rejected group fingerprints are remembered.
  Provisional automatic groups expose peer evidence but cannot suppress
  DS-EXEC-002; only approved mature automatic groups, or explicit manual groups,
  may provide suppressive peer-common evidence. See [Peer groups](docs/peer-groups.md).
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

## Deliberate boundaries

No SSO/MFA, automated remediation, long-term exact IOC inventory, alert email
engine, trained ML model, automatic offline update bundle or GUI disaster-recovery
restore. Automatic peer grouping is similarity discovery rather than a learned
classifier; its first version deliberately leaves full drift/prototype protection
as a follow-up. Observed history is not necessarily benign. Missing joins, limited
history, retention, cardinality and source lag remain important limitations. No
3,000-endpoint throughput claim is made.

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
