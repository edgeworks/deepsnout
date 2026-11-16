"""Explicit retirement of legacy detectors. Requires backup and operator confirmation.

Never executed by a migration or automatic application startup.
"""
from sqlalchemy import select, func, delete
from .db import Finding, Expectation, policy, set_state, audit


def preview_retirement(db):
    return {
        "ds_net_findings_to_delete": db.scalar(
            select(func.count()).select_from(Finding)
            .where(Finding.detector == "DS-NET-001")) or 0,
        "ds_net_expectations_to_delete": db.scalar(
            select(func.count()).select_from(Expectation)
            .where(Expectation.detector == "DS-NET-001")) or 0,
        "ds_exec_001_and_002": "disable future detections; existing findings retained",
        "historical_network_features": "retained for fleet analysis",
    }


def retire_legacy_detectors(db):
    before = preview_retirement(db)
    cfg = policy(db)
    cfg.execution_enabled = False
    cfg.contextual_enabled = False
    cfg.network_enabled = False
    set_state(db, "policy", cfg.model_dump())
    deleted_expectations = db.execute(
        delete(Expectation).where(Expectation.detector == "DS-NET-001")
    ).rowcount
    deleted_findings = db.execute(
        delete(Finding).where(Finding.detector == "DS-NET-001")
    ).rowcount
    # Cached family membership can reference deleted findings.
    set_state(db, "finding_quality_snapshot", None)
    audit(db, "host-admin", "detectors.retired", "DS-NET-001",
          "Deleted {} DS-NET-001 findings and {} expectations; "
          "disabled DS-EXEC-001 and DS-EXEC-002".format(
              deleted_findings, deleted_expectations))
    return {**before, "deleted_findings": deleted_findings,
            "deleted_expectations": deleted_expectations,
            "disabled": ["DS-EXEC-001", "DS-EXEC-002", "DS-NET-001"]}
