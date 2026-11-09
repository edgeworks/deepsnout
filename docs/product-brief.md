# Product brief and first milestone

DeepSnout is a clean-slate project, not a renamed Greycode. Its purpose is to help
analysts explain meaningful changes without the noise of lifetime rare-indicator
scores. The original idea was tested in a several-thousand-endpoint environment;
that does not establish this implementation's capacity or detection performance.

## Owner requirements

Prefer Python for readability. Containers and a turnkey application stack.
Application setup, collection, analysis controls, users and investigations in the
GUI. Standard Sysmon, Splunk first, no new endpoint agents. Limited central state,
not another log archive. Core useful offline without mandatory enrichment.
CPU-local ML is allowed when measured value justifies it.

Latest clarification: enrichment is a byproduct, not a first-release requirement.
Do not let it distract from contextual comparison. Future VirusTotal integration
must be optional, use one account, obey entitlement and rate limits, and never
market or implement a free-license/quotas workaround. The user's provider discussion
is not assumed to license every downstream operator.

## First working path

Containers -> first-run GUI -> Splunk connection -> standard events -> bounded
context and prior references -> explainable findings -> analyst decisions.

This pilot implements that path plus source health, roles, retention, demo and
tests. It is narrower than the earlier concept: no trained ML, no automatic
fleetwide clustering and no claim that all false positives are solved.

## Definition of improvement

Useful findings per analyst decision, fewer repeated decisions, retained known-case
coverage, discovery below the threshold, transparent comparisons and affordable
operation. A prettier screen or fewer cards alone is not success. Validate on
later held-out telemetry and a limited pilot before scaling up.

## Owner direction: environment understanding, not known-pattern copying

The owner emphasizes discovering what is unusual in DeepSnout's actual
environment, including behavior not documented by MITRE ATT&CK or a known
adversary technique. ATT&CK is useful for subsequent analyst interpretation,
not a discovery prerequisite. Explain routine versus unusual observed
execution and activity before trying to infer attacker intent. Preserve
novelty and rarity as observations, not maliciousness probabilities.

The first event-time implementation of this direction is DS-BEH-001:
environment-relative application and launch-pattern novelty with an
optional learned cohort comparison. Broader unsupervised, multivariate
discovery and detector-specific historical peer quality remain next steps.

## Findings should diagnose their own redundancy

A self-diagnostic shadow process now groups related original findings
from learned filename structure, parent processes, execution location,
category and fleet repetition. It identifies excessive concentration
without vendor-specific allowlisting or interpreting a widespread
campaign as harmless. Analyst assessment and temporal validation are
necessary before any future prioritization or automatic grouping of
individual tickets. This is Phase 1 of a broader environment-understanding
loop: make the structure and quality of discovery visible first.

## Next iterations

Better application identity; richer pairwise novelty; process role/port change;
activity-normalized network features; shared rollout findings; stratified discovery
samples; approved-case learning; local Isolation Forest in shadow mode; optional
entitlement-aware enrichment; more transports; SSO/MFA; versioned migrations and
portable offline releases. Preserve source attribution and bounded evidence.
