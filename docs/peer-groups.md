# Peer groups

Peer groups give contextual detectors a reviewed population of comparable endpoints.
They are similarity groups, not trust labels, asset classifications or proof that
members are benign.

## Immediate discovery and maturity

DeepSnout starts discovering groups as soon as useful endpoint observations exist.
It does not wait for a full 28-day history. If the environment has no completed
observation day yet, the current partial day may be used for **suggestion generation
only** and the GUI shows an early-grouping warning.

Automatic groups have three simple maturity states:

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
suppress a finding until an automatic group is stable**. Manual groups are explicit
analyst intent and use the existing minimum-peer rule immediately.

## Current similarity features

The first algorithm uses bounded summaries already held by DeepSnout; it does not
retain raw events for clustering. Per-host sparse vectors include:

- application presence/prevalence over observed days;
- parent -> child application relationships;
- application + normalized path/location class;
- whether an application has IP or DNS activity.

Exact destination IPs/domains, usernames and file hashes are not peer-group
features. Singleton features are excluded, very fleet-common features are reduced
or excluded, and the remaining features receive inverse-fleet-frequency weighting.
This keeps ubiquitous Windows activity from dominating similarity and reduces the
chance that one new/rare executable becomes a group definition.

The implementation keeps each host's highest-weight bounded feature set, generates
candidate pairs through an inverted feature index, applies cosine similarity, then
forms connected similarity components. Groups need at least three members and a
minimum cohesion. This is deterministic unsupervised similarity grouping, not a
trained classifier or probability model.

## Explanations

The Peer Groups page shows the signals that distinguish a group from the fleet, for
example:

```
acad.exe                  92% group / 3% fleet
explorer.exe -> acad.exe  76% group / 1% fleet
acad.exe network activity 54% group / 4% fleet
```

The percentages are intended to let an analyst judge whether the generated group
has an operationally meaningful identity. The group page also provides a searchable
endpoint list and sample members.

## Approval, rejection and manual groups

Suggested automatic groups receive generated labels. An analyst can:

- approve and rename a suggestion;
- reject a suggestion;
- create a manual group;
- assign an endpoint to any existing approved/manual group or leave it unassigned.

Rejected suggestions are remembered by a fingerprint of their strongest defining
features so the same suggestion is not repeatedly presented. Manual endpoint
assignments are never overwritten by automatic discovery.

Approved automatic groups are refreshed when the same defining fingerprint is
rediscovered. If that fingerprint disappears, the current version deliberately
leaves the approved group unchanged rather than silently redefining its identity.
Full membership/prototype drift scoring and review thresholds are the next focused
peer-group safety change.

## Detector semantics

DS-EXEC-002 still requires established **local** history before it creates a finding.
Peer groups augment that local comparison; they do not replace it.

For a host in a peer group, DeepSnout counts peers in the same namespace that have
sufficient history for the same application. The existing policy defaults remain:
10 qualified peer hosts and a 10% common-peer fraction. If the peer group is
eligible to suppress and at least 10 peers qualify, a context observed on 10% or
more of those peers is no longer considered peer-rare.

For an immature automatic group, DeepSnout may record `peer_seen` and
`peer_eligible`, but marks the peer population non-suppressive. Therefore an early
or unstable grouping cannot make a new execution context disappear from
DS-EXEC-002 merely because the clustering system has only limited evidence.

## Known first-version boundaries

- One active detector peer group per endpoint; arbitrary overlapping tags are not
  implemented.
- Automatic group identity currently uses a defining-feature fingerprint rather
  than a full historical centroid/membership lineage.
- Suggested/approved metadata is stored as bounded application state while
  `Host.cohort` remains the active detector membership. A richer normalized schema
  can follow when drift history and overlapping metadata justify it.
- Similarity thresholds are deterministic pilot defaults, not validated universal
  clustering parameters.
- Fleet size, role mixture and telemetry coverage can materially affect discovered
  groups. The UI therefore exposes explanations and requires approval rather than
  silently enabling suggestions.
