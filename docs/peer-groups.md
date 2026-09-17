# Peer groups

Peer groups give contextual detectors a reviewed population of comparable endpoints.
They are similarity groups, not trust labels, asset classifications or proof that
members are benign.

## Immediate discovery and maturity

DeepSnout starts discovering groups as soon as useful endpoint observations exist.
It does not wait for a full 28-day history. If the environment has no completed
observation day yet, the current partial day may be used for **suggestion generation
only** and the GUI shows an early-grouping warning.

Automatic groups have three maturity states:

- **provisional**: current-day data was needed, or the median member has fewer than
  three observed days;
- **growing**: at least three but fewer than seven median observed days;
- **stable**: at least seven median observed days and the discovery run did not use
  today's partial data.

Once completed historical data exists, discovery excludes the current day and uses
up to the previous 28 days. Observed days matter more than wall-clock age, so
intermittently used endpoints can still accumulate useful evidence.

A suggestion has no effect on detectors. After approval, provisional/growing groups
may expose peer counts in DS-EXEC-002 evidence, but **peer-common behavior cannot
suppress a finding until an automatic group is stable and peer-suitable**. Manual
groups are explicit analyst intent and use the existing minimum-peer rule immediately.

## Two kinds of discovered groups

The v2 discovery layer distinguishes **recommended peer groups** from **technical
clusters**.

A technical cluster can be real and useful even when it is not a business/behavioral
peer population. Examples include endpoints sharing a new Windows image, a scanner
suite, a Defender configuration or another narrow product footprint. These clusters
remain visible for analyst context, but approving/tracking one never makes it eligible
to suppress DS-EXEC-002.

A recommended peer group must show broader agreement. In particular, platform-only
similarity cannot establish detector peers, and one rare executable is not enough.
The group must have a sufficiently similar non-Windows application footprint plus
support from another behavioral view.

## Multi-channel host profiles

Discovery uses bounded summaries already stored by DeepSnout. It does not retain raw
events for clustering. Each endpoint is described through several views:

- **application footprint**: a broad set of routinely observed non-Windows executable
  basenames, including common applications with deliberately low weight;
- **application combinations**: recurring pairs of applications observed together on
  endpoints, providing an explainable co-occurrence layer above individual apps;
- **process ecology**: parent -> child relationships for non-Windows applications;
- **network role**: which non-Windows applications show IP or DNS activity;
- **activity pattern**: coarse six-hour UTC activity windows;
- **platform characteristics**: Windows-path applications and their known
  parent-child relationships, retained for technical-cluster discovery only.

Exact destination IPs/domains, usernames and file hashes are not grouping vectors.
Relationships with a missing/unknown parent are also excluded rather than being
interpreted as meaningful `->child.exe` evidence.

Application-set comparison deliberately does not use an unbounded rarity score. Very
common applications retain a small amount of weight so a full software footprint can
be compared, while rarer applications receive only a bounded increase. This reduces
the chance that one Epson helper, one rollout component or one new OS binary dominates
similarity.

## Multi-view decision

Candidate endpoint pairs are generated through bounded inverted indexes. For each
candidate DeepSnout calculates separate weighted-set similarities for applications,
application combinations, process relationships, network-active applications and
activity windows.

The current pilot thresholds require:

- overall multi-channel peer similarity of at least 0.50;
- application-footprint similarity of at least 0.42;
- at least three shared application features in small populations, or four in larger
  populations;
- supporting agreement from at least one additional view (application combinations,
  process ecology, network role or activity pattern).

These are deterministic pilot defaults, not validated universal clustering constants.
The important safety property is structural: **platform characteristics do not
contribute to peer suitability**, even though they can define a technical cluster.

A second distinctive-feature graph is used to retain narrow technical discoveries.
It uses bounded inverse-fleet-frequency features and cosine similarity, but its output
is explicitly marked `technical` and cannot become detector-suppressive automatically.

## Explanations and correlated signals

The UI shows both channel-level similarity and concrete distinguishing signals.
Application co-occurrence can therefore appear as, for example:

```
application bundle saplogon.exe + scannerclient.exe
application bundle saplogon.exe + businessclient.exe
```

Correlated consequences of one executable are collapsed where possible. Rather than
showing an application, its path, its normal parent and its network presence as four
independent reasons, DeepSnout prefers one application reason with supporting detail.
This makes the explanation closer to the number of genuinely distinct reasons behind
the group.

Group/fleet percentages remain visible so an analyst can judge whether a suggestion
has an operationally meaningful identity. The group page also provides a searchable
endpoint list and sample members.

## Approval, rejection and manual groups

Suggested automatic groups receive generated labels. An analyst can:

- approve and rename a recommended suggestion;
- track and rename a technical cluster (still non-suppressive);
- reject a suggestion;
- create a manual group;
- assign an endpoint to any existing approved/manual group or leave it unassigned.

Rejected suggestions are remembered by a fingerprint of their strongest defining
features so the same suggestion is not repeatedly presented. Manual endpoint
assignments are never overwritten by automatic discovery.

Approved automatic groups are refreshed when the same defining fingerprint is
rediscovered. If that fingerprint disappears, the current version deliberately
leaves the approved group unchanged rather than silently redefining its identity.
Full membership/prototype drift scoring and review thresholds remain the next focused
peer-group safety change.

## Detector semantics

DS-EXEC-002 still requires established **local** history before it creates a finding.
Peer groups augment that local comparison; they do not replace it.

For a host in a peer group, DeepSnout counts peers in the same namespace that have
sufficient history for the same application. The existing policy defaults remain:
10 qualified peer hosts and a 10% common-peer fraction.

Peer-common behavior can suppress DS-EXEC-002 only when an automatic group is all of:

- analyst-approved;
- `recommended` by the multi-channel algorithm;
- stable (median at least seven observed days);
- calculated from completed historical days rather than today's partial data.

Technical clusters may expose peer membership/context after approval but are always
non-suppressive. Legacy automatic groups that predate the v2 suitability assessment
also fail closed and cannot suppress until rediscovered/classified by v2.

## Known boundaries

- One active detector peer group per endpoint; arbitrary overlapping tags are not
  implemented.
- Application identity is currently executable-basename based. Product/company and
  reliable OS inventory metadata are not yet retained, so several executables from
  one suite can still look like several applications.
- Automatic group identity uses a defining-feature fingerprint rather than a full
  historical centroid/membership lineage.
- Suggested/approved metadata is stored as bounded application state while
  `Host.cohort` remains the active detector membership. A richer normalized schema
  can follow when drift history and overlapping metadata justify it.
- Similarity thresholds are deterministic pilot defaults, not validated universal
  clustering parameters.
- Fleet size, role mixture and telemetry coverage materially affect discovered
  groups. The UI exposes explanations and requires approval rather than silently
  enabling suggestions.
