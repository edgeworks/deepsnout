# Splunk integration

## Topology

Sysmon -> Windows Event Log -> existing UF/WEF collection -> Splunk.
DeepSnout then queries selected indexed events via Splunk's management search API.
It is NOT an S2S receiver: do not point UF outputs.conf at its web port.
Other transports can later reuse the same normalization contract.

## Source preparation

Prefer XML from the existing collection. Typical direct UF input:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true
index = YOUR_EXISTING_INDEX
```

Verify your actual sourcetype and existing deployment. Do not blindly apply this to
a WEF collector: subscription, channel and original identity differ. Preserve
original Computer, provider, event ID/time, Image and ProcessGuid. Event 3 needs
DestinationIp, DestinationPort and Initiated. Event 22 needs QueryName. Sysmon
rules must actually collect the events; a forwarder alone does not create them.
No additional endpoint software is introduced by DeepSnout.

## GUI setup

Create a dedicated least-privilege Splunk identity allowed to search only the
required indexes. It needs search job create/status/results access. Test connection
also calls server/info; permission configuration depends on the Splunk deployment.
Do not give this tool a Splunk administrator token.

In Sources, set the management origin (e.g. https://splunk.example:8089), exact
comma-separated index names, and observed sourcetype. Default:
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational. A wildcard is accepted; keep
it restricted to Sysmon. Arbitrary operator SPL is intentionally not accepted.

Choose Bearer for a token, Splunk for a session key. Credentials are encrypted and
never redisplayed. Paste internal CA certificates as PEM when system trust is
insufficient; TLS verification/hostname checking remains enabled. No GUI bypass.
Set a default cohort for NEW endpoints when the source scope is homogeneous.
Existing assignments are preserved; adjust exceptions on endpoint pages.

For a limited pilot, set Computer selection to one original endpoint hostname or
a wildcard such as test-*.example.org. This filters AFTER parsing; it does not
reduce the source-side search volume. Filtered counts remain visible in reports.

Save paused, Test connection, Poll now, inspect job report/Operations, then Enable.
Server test does not prove all search permissions or parser compatibility. First
check original endpoint identity vs collector identity and missing-GUID counts.

Default initial index-time lookback one hour, maximum slice 60s, polling 60s, lag60s.
Backlog slices run successively until caught up. Earlier original events within
retention build the reference; only recent events produce findings. Use a limited
sample before increasing scope or history.

## Search guarantees and limits

Create/status/delete: /services/search/jobs. Results:
/services/search/v2/jobs/{sid}/results, pages of up to500. The completed job must
report resultCount. Recognized warnings/errors, preview pages, early finalization,
missing results or malformed supported events fail the slice. No cursor advance
on failure. Unsupported event types are explicitly counted as ignored.

Index-time scopes are half-open and explicitly checked using _indextime. Original
UtcTime/_time drives comparison. Over-cap slices are bisected, never silently
truncated. If one indexed second exceeds the configured cap, the job fails until
scope/cap is adjusted. A finished result can still be incomplete due to conditions
the server does not report; this is not a collection certification.

The lag accommodates ordinary indexing/search visibility delay, not arbitrarily
late distributed-search visibility. After an outage, assess lag and deliberately
backfill. Pause stops new scheduling; pending work may finish. Source edits require
paused state and no pending job. Cursor reset is explicit and subject to dedup/batch
retention; recombined old replays can change aggregate counters.

HTTP(S)_PROXY/NO_PROXY may be passed to the worker deliberately. No proxy/credential
is embedded. Redirects do not receive the token. Private management addresses are
allowed because this is an administrator configuration surface; restrict egress.

## Pilot validation

Use the deployed Splunk version and sanitized real XML examples. Check count parity,
original Computer, time, GUID, invalid token/CA handling, pause/resume, restart while
polling, duplicates and multi-page slices. This release has mock-contract tests,
not a live Splunk compatibility certification.

Primary references:
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events
- https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.0/search-endpoints/search-endpoint-descriptions
