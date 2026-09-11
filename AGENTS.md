# DeepSnout contributor/agent handoff

Read docs/product-brief.md, docs/design.md and docs/testing.md first. The latest
owner direction prioritizes meaningful behavioral findings and Python readability.
Enrichment is optional FUTURE work, not a gate for useful local analysis. Single
account pacing is not license permission; no provider circumvention.

Use the source as written, not old Greycode assumptions. Standard Sysmon ingestion,
original timestamps, exact process attribution, prior-day references, bounded
state and visible uncertainty are invariants. Do not invent causal chains, call
an anomaly score a compromise probability, or silently truncate source results.

Run `python -m pytest`. The PostgreSQL test fixture DROPS TABLES: use only a
disposable test DB. Do not publish customer telemetry/secrets or committed instance
state. Add migrations before changing a deployed schema. Maintain a runnable
Docker Compose path and a GUI that reflects real state, not hardcoded mock data.

The initial remote publish was denied with integration HTTP403. A packaged source
artifact is not a remote commit. Do not claim GitHub CI/Docker/PostgreSQL checks
passed until their actual results are available. Keep docs/testing.md honest.
