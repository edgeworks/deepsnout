# Retire legacy detectors and use Finding-Family for analyst cleanup

This release keeps DS-BEH-001 (rare execution) active and disables DS-EXEC-001
and DS-EXEC-002 by default on new installations. DS-NET-001 is no longer
evaluated. Network windows remain usable as historical features for other
analyses; Sysmon collection and Splunk are unchanged.

## Existing deployments: one-time operator action

Existing analysis policy is saved in the database, so changing application
defaults does **not** disable previously enabled DS-EXEC-001/002 settings.

**Take a coordinated PostgreSQL and DeepSnout-secrets backup first.**
Stop all worker containers before the cleanup so no detections race the update.
Deploy the new code, then run from the updated web container:

\`\`\`bash
docker compose stop ingest-worker analysis-worker analysis-worker-b insight-worker
docker compose up -d --no-deps web
docker compose exec -T web deepsnout retire-legacy-detectors
# Inspect preview counts; this does not change any data.
docker compose exec -T web deepsnout retire-legacy-detectors --confirm
docker compose up -d
\`\`\`

The confirmed action permanently deletes only findings and exact-scope
expectations belonging to DS-NET-001. DS-EXEC-001 and DS-EXEC-002 findings
remain for review, but their detectors are disabled. It clears the cached
Finding-Family snapshot; refresh after restarting.

The operation is audited, repeatable, and requires explicit confirmation.
It does not delete Splunk events, host histories, or network summaries.
If there is no verified backup, **do not run the --confirm step**.

## Finding-Family production workflow

1. Open **Finding quality**; refresh the snapshot after deploying.
2. The snapshot includes **all open findings** (up to a bounded 20,000), not
   only the last seven days. It groups compatible process findings by scope,
   parent, executable-name shape, location, and flags.
3. Open a family and inspect representative findings, hosts, and variants.
4. For confirmed benign families, provide a reason and type MARK EXPECTED.
   This marks only new/non-high-priority members expected. It does not
   delete evidence or modify malicious, investigating, or high-priority items.
5. Optional: expect future exact family matches for 7, 14, or 30 days.
   Only DS-BEH-001 can receive future expectations. The system refuses
   this option if a member is under investigation or flagged high/malicious.
6. Active family expectations appear in **Finding quality** and can be revoked.
   Every change is recorded in the audit trail.

Shared behavior does not imply benign behavior. Confirm that family members
are legitimate before marking them expected. No automatic group approval is
implemented. A fresh snapshot is queued after every bulk review.

## Deployment and performance notes

- No database schema migration is required.
- Restart the updated web and workers after taking a backup.
- Bulk cleanup is done in 400-finding chunks within an atomic transaction.
- The analysis scan remains bounded to 20,000 open findings; if exceeded,
  refresh fails visibly rather than silently omitting unreviewed findings.
- Default future expectation duration is 14 days if opted in. No future
  suppression occurs without an explicit analyst checkbox.
