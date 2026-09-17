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

The setup token is a one-time bootstrap secret stored under the application data
volume. Complete setup promptly, then treat the data volume as sensitive.

For headless systems behind an outbound build proxy, pass the proxy only to the
build that needs it rather than baking credentials into an image. For example:

```sh
export HTTP_PROXY="${HTTP_PROXY:-${http_proxy:-}}"
export HTTPS_PROXY="${HTTPS_PROXY:-${https_proxy:-}}"
export NO_PROXY="${NO_PROXY:-${no_proxy:-}}"

sudo --preserve-env=HTTP_PROXY,HTTPS_PROXY,NO_PROXY \
  docker compose --progress=plain build \
    --build-arg HTTP_PROXY \
    --build-arg HTTPS_PROXY \
    --build-arg NO_PROXY
sudo docker compose up --no-build -d
```

Configure the Splunk source from **Sources**, test the connection, then enable it.
DeepSnout deliberately does not receive Universal Forwarder/S2S traffic directly.

## Documentation

- [Product brief](docs/product-brief.md)
- [Design](docs/design.md)
- [Detectors](docs/detectors.md)
- [Peer groups](docs/peer-groups.md)
- [Splunk source](docs/splunk.md)
- [Deployment](docs/deployment.md)
- [Enrichment policy](docs/enrichment-policy.md)
- [Testing/verification](docs/testing.md)
- [Publishing](docs/publishing.md)

See `SECURITY.md` before exposing a pilot beyond a trusted management network.
