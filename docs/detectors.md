# Exact initial detector semantics

These are seed rules and comparisons, not trained probabilities. Settings affect
future evaluations; open findings keep their evidence snapshot.

## DS-EXEC-001

Recent (24h) process-create, supported script-capable basename (powershell, pwsh,
cmd, mshta, regsvr32, rundll32, cscript, wscript with .exe), HTTP(S) reference and an
execution primitive in inspected command. Examples: IEX, Invoke-Expression,
Start-Process, javascript/vbscript, remote mshta/regsvr32 use. No baseline or external
lookup needed. Encoded arguments alone do not match. Legitimate automation can
match. No complete command parser, sandbox or deobfuscator is implemented.
This detector has no automatic per-context expectation; it can be disabled in
policy, a visible administrator decision rather than an implicit trust label.

## DS-EXEC-002

Requires recent creation, enough prior endpoint process-observation days, a locally
new execution context, and an initiated external connection from the SAME endpoint
and ProcessGuid at/after creation. Supporting characteristic: temporary/download/
user-profile/share path class, Office/browser parent, or encoded argument flag.

Peer grouping augments the established local baseline rather than replacing it.
DeepSnout can discover explainable automatic peer groups immediately from available
behavioral summaries; suggestions have no detector effect until approved. Approved
provisional/growing automatic groups may expose `peer_seen`/`peer_eligible` evidence,
but cannot suppress a DS-EXEC-002 finding. Only a stable approved automatic group
(at least seven median observed days, no current partial day in the discovery run),
or an explicit manual group, may make peer-common behavior suppressive.

When a suppression-eligible group has enough application peers (default minimum 10),
the context must be below the configurable common-peer fraction (default 10%).
Sparse/non-suppressive peers fall back to established local history and show the
missing assurance. Known hashes are not automatically trusted. Missing GUIDs, proxy
representations, absent create events and basename/path ambiguity reduce capability.
One new approved utility may still require a decision. See `docs/peer-groups.md` for
peer discovery and maturity semantics.

## DS-NET-001

Application/location-specific IP and DNS measures. IP requires global routing and
Initiated=true; DNS uses registrable-domain groups. A query does not prove success
or a connection. DNS status is normalized but not yet used as a detector feature.
IP and DNS are not causally joined.

30-minute windows, evaluated at least five minutes after close. Previous 28 days,
excluding today; at least seven observed days and eight eligible active windows.
Threshold = max(floor, prior p95 * multiplier, prior p95 + floor/2). Defaults: floor
30, multiplier 4. TWO adjacent windows must exceed the threshold. A gap is not
sustained activity. Output is approximate (HyperLogLog). Related IP/DNS shifts
share one finding for the application/location rather than double-scoring a host.

This first detector is active-window diversity, not a complete rate-normalized,
peer-adjusted browsing model. Intensive legitimate browsing can match. Low-volume
C2, sparse history and stable malicious behavior can evade it. Learning is shown as
insufficient reference, not clean behavior.

## Feedback and evaluation

Priority is a band. No probability and no additive lifetime rarity score. The first
evidence snapshot stays frozen; repeats update metadata only. Discovery exposes
recent execution contexts but is not yet an automatic stratified sampling engine.

Validate on later held-out periods, different host roles and reviewed benign changes.
Measure useful findings per analyst decision, missed-case discovery, duplicate
work, time to explanation and full-pipeline cost. Do not judge success by fewer
cards alone. Compare a future local ML challenger against the SAME deterministic
baseline and review budget before adopting it.
