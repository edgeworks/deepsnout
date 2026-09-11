# Contributing

Read docs/product-brief.md and docs/design.md. Keep Python approachable, evidence
explainable, state bounded and core analysis independent of outside services.
Avoid new telemetry or model complexity without measured analyst value.

Use Python3.12+ and `pip install -e '.[test]'`, then `python -m pytest`. Add synthetic
fixtures and regressions for source and detector changes; never commit customer
telemetry or credentials. Preserve source time, attribution, idempotency and
visible coverage limits.

DEEPSNOUT_TEST_DATABASE_URL must name a DISPOSABLE test DB: the fixture drops and
recreates application tables. Never use a pilot/production database. Before schema
changes after deployment, provide explicit versioned migrations and recovery tests.

Keep assets self-contained and keyboard usable. Exercise setup, demo, finding
decisions and configuration in the UI. A low anomaly score is not proof of benign
behavior. Describe operational value, failure modes and costs in each contribution.
MIT applies to project code; keep third-party notices where applicable.
