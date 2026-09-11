# Future optional enrichment

No enrichment adapter is implemented in this pilot. Local analysis must remain
useful when every provider is unavailable, disabled or no longer licensed.
Missing reputation is not evidence of safety or maliciousness.

A possible VirusTotal adapter must use one configured account, deduplicate/cache,
provide explicit request budgets/pacing/backoff/Retry-After and report provider
health. No multi-account rotation, proxy tricks or marketing a free-license loophole.
No automatic binary upload. Even a hash lookup discloses information externally
and requires operator approval.

Published terms and the operator's agreement must permit the actual use. Respecting
a numeric rate limit is not a license. The maintainer's discussion with Google is
not represented as a general permission grant for every downstream deployment.
Public VT guidance includes restrictions on commercial use and business workflows
not contributing files. A separate written agreement may matter; this application
must not assume that permission. Policy changes must allow clean disable without
breaking core behavior analysis.

Primary source checked during implementation:
https://docs.virustotal.com/reference/public-vs-premium-api
