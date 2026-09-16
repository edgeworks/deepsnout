# Splunk integration

## Topology

Sysmon -> Windows Event Log -> existing UF/WEF/Cribl collection -> Splunk.
DeepSnout then queries selected indexed events via Splunk's management search API.
It is NOT an S2S receiver: do not point UF outputs.conf at its web port.
Other transports can later reuse the same normalization contract.

## Source preparation

DeepSnout accepts XML and JSON Sysmon payloads. Prefer preserving the original
Windows event structure rather than reducing it to a rendered message only.

Typical direct UF XML input:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true
index = YOUR_EXISTING_INDEX
```

The transport-neutral normalizer understands standard XML plus common structured
JSON representations: nested Windows `Event/System/EventData`, flattened dotted
fields, XML-to-JSON `Data` arrays (`Name` plus text/value variants),
`__winEvent` when retained, Elastic-style `winlog.event_id`, and Windows Event
Logs/Get-WinEvent-style fields such as exact-case `Id`, `ProviderName`,
`MachineName`, `RecordId` and `TimeCreated`. If a rendered Sysmon `Message` is
present, named `Key: value` lines are used as a fallback. Rendered messages are
not a substitute for structured event data because they can be localized or
transformed.

### JSON compatibility adapters

Collector/vendor-specific JSON semantics are intentionally kept outside the core
normalizer. Built-in compatibility functions are registered in
`deepsnout/event_adapters.py`: they may contribute canonical fields only when a
narrow source shape matches. Explicit/canonical fields always take precedence.
This is an internal plugin-like seam, not a dynamic third-party code loader; a new
organization-specific dialect should normally be implemented as another small
adapter rather than adding special cases to core EventID logic.

The current pilot includes an adapter for the observed flat Cribl Windows-event
shape where Windows `System` values are promoted to top-level fields such as
`sourceMachineID`, `Name`, `Guid`, `Task`, `SystemTime`, `EventRecordID` and
`Channel`, followed by Sysmon event data. In this environment some records also
contain a symbolic top-level `ID`, for example `IMAGE_LOAD`.

The core parser does **not** treat generic `ID`/`id` or Windows `Task` as EventID.
For the flat Cribl adapter specifically:

- provider/channel/provider GUID must independently identify Sysmon before Sysmon
  compatibility semantics are applied;
- supported symbolic IDs (`PROCESS_CREATE`, `NETWORK_CONNECT`, `DNS_QUERY`) may be
  translated to Event IDs 1, 3 and 22;
- other trusted symbolic/numeric Sysmon IDs are classified as unsupported, so an
  `IMAGE_LOAD` record is ignored rather than reported malformed;
- when `ID` is absent, `Task` is only a compatibility hint for Event 1, 3 or 22 and
  is accepted only when event-specific payload fields corroborate that type (for
  example DestinationIp/DestinationPort for Event 3 or QueryName for Event 22);
- every successful Task/symbolic-ID inference adds a normalization warning.

This deliberately avoids generalizing an unusual Cribl serialization into the
cross-environment parser contract. If that upstream format changes, the adapter
can fail visibly or be revised without changing XML, canonical JSON or another
vendor's `Id` semantics.

If the selected Splunk sourcetype contains a mixed Windows Event Log stream, the
flat-system adapter preserves top-level `Name` as the provider. Non-Sysmon
providers or an explicitly non-Sysmon channel are counted as ignored/unsupported
rather than as malformed Sysmon. Records that cannot be identified safely still
fail the slice instead of being silently discarded.

Verify the actual sourcetype and payload in your deployment. Do not blindly apply
the UF stanza to a WEF or Cribl path: subscription, collector identity and
transformations differ. Preserve original Computer/MachineName/sourceMachineID,
provider, event ID/time, Image and ProcessGuid. Event 3 needs DestinationIp,
DestinationPort and Initiated. Event 22 needs QueryName. Sysmon rules must
actually collect the events; a forwarder alone does not create them. No
additional endpoint software is introduced by DeepSnout.

## GUI setup

Create a dedicated least-privilege Splunk identity allowed to search only the
required indexes. It needs search job create/status/results access. Test connection
also calls server/info; permission configuration depends on the Splunk deployment.
Do not give this tool a Splunk administrator token.

In Sources, set the management origin (for example
`https://splunk.example:8089`), exact comma-separated index names, and the
observed sourcetype. A wildcard is accepted; keep it restricted to Sysmon where
possible. A broader mixed Windows sourcetype is supported only when the upstream
JSON retains enough provider/channel identity for non-Sysmon records to be
classified safely. Arbitrary operator SPL is intentionally not accepted.

Choose the event payload format:

- **Auto detect XML / JSON** is the default and preserves existing behavior.
- **JSON** requires JSON `_raw` (or a JSON event object) and fails the slice if a
  supported event arrives in another payload form.
- **XML** similarly requires XML `_raw`.

Explicit JSON/XML mode is useful during a pilot because an unexpected upstream
serialization change becomes a visible source failure instead of a silent format
switch.

Choose **Bearer** for a Splunk authentication token and **Splunk** for a session
key. Credentials are encrypted and never redisplayed. Long-running sources should
normally use a dedicated Bearer authentication token rather than a manually
copied short-lived session key.

### TLS trust modes

**Strict CA + hostname verification** is the default. Paste internal CA
certificates as PEM when system trust is insufficient. TLS certificate and
hostname checks remain enabled; there is no generic `verify=false` option.

**Pinned leaf certificate SHA-256** is an explicit per-source exception for a
legacy management endpoint whose exact certificate can be verified but whose
certificate has no usable hostname identity (for example the default Splunk
management certificate on port 8089). In this mode DeepSnout identifies the TLS
peer by the exact DER leaf-certificate SHA-256 fingerprint. It performs an
unauthenticated TLS request first and only adds the Splunk Authorization header
after the expected pin matches; every authenticated response is checked again.
The strict-mode CA bundle is not used to establish identity in pinned mode.

Obtain the fingerprint from the exact management endpoint over a trusted network
path and verify it out-of-band before configuring it:

```sh
openssl s_client -connect splunk.example:8089 -servername splunk.example \
  </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 -subject -issuer -dates
```

Paste only the SHA-256 fingerprint into the pinned-fingerprint field. Colons and
whitespace are accepted. Certificate replacement or renewal intentionally causes
a hard failure until an administrator verifies and updates the pin. Pinning is
not intended to make an intercepting TLS proxy transparent; internal Splunk
management endpoints should normally be in `NO_PROXY` when direct routing is
available.

Set a default cohort for NEW endpoints when the source scope is homogeneous.
Existing assignments are preserved; adjust exceptions on endpoint pages.

For a limited pilot, set Computer selection to one original endpoint hostname or
a wildcard such as `test-*.example.org`. This filters AFTER parsing; it does not
reduce the source-side search volume. Filtered counts remain visible in reports.

Save paused, Test connection, Poll now, inspect job report/Operations, then Enable.
Server test does not prove all search permissions or parser compatibility. First
check original endpoint identity vs collector identity and missing-GUID counts.

Default initial index-time lookback is one hour, maximum slice 60s, polling 60s,
and lag 60s. Backlog slices run successively until caught up. Earlier original
events within retention build the reference; only recent events produce findings.
Use a limited sample before increasing scope or history.

## Search guarantees and limits

Create/status/delete: `/services/search/jobs`. Results:
`/services/search/v2/jobs/{sid}/results`, pages of up to 500. The completed job
must report resultCount. Recognized warnings/errors, preview pages, early
finalization, missing results or malformed supported events fail the slice. No
cursor advance occurs on failure. Unsupported event types and recognized
non-Sysmon providers are explicitly counted as ignored.

Malformed Splunk records are grouped by parser-failure signature in the job
Result (up to 50 distinct groups), with counts and up to three Splunk pointers per
group. This prevents one repeated malformed shape from hiding a later failure
class. The full `_raw` and CommandLine are not persisted; the group sample keeps
schema/candidate/adapter diagnostics plus a raw SHA-256 for source lookup.

Index-time scopes are half-open and explicitly checked using `_indextime`.
Original UtcTime/SystemTime/TimeCreated drives comparison. Over-cap slices are
bisected, never silently truncated. If one indexed second exceeds the configured
cap, the job fails until scope/cap is adjusted. A finished result can still be
incomplete due to conditions the server does not report; this is not a collection
certification.

The lag accommodates ordinary indexing/search visibility delay, not arbitrarily
late distributed-search visibility. After an outage, assess lag and deliberately
backfill. Pause stops new scheduling; pending work may finish. Source edits require
a paused state and no pending job. Cursor reset is explicit and subject to
dedup/batch retention; recombined old replays can change aggregate counters.

`HTTP(S)_PROXY`/`NO_PROXY` may be passed to the worker deliberately. No proxy or
credential is embedded. Redirects do not receive the token. Private management
addresses are allowed because this is an administrator configuration surface;
restrict egress.

## Pilot validation

Use the deployed Splunk version and sanitized real events. Check count parity,
original Computer/MachineName/sourceMachineID, time, GUID, invalid token/CA/pin
handling, pause/resume, restart while polling, duplicates and multi-page slices.
For a Cribl path, inspect at least one real Event 1, 3 and 22 payload before
expanding scope; arbitrary organization-specific Cribl renames cannot be inferred
by the normalizer or compatibility adapters without a real sample.

This release has contract/mock tests and local TLS pin tests during development,
not a live Splunk compatibility certification.

Primary references:
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events
- https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.0/search-endpoints/search-endpoint-descriptions
- https://docs.cribl.io/stream/usecase-win-xml/
- https://docs.cribl.io/stream/sources-windows-event-logs/
