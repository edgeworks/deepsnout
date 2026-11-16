"""Retired detector cleanup is explicit, auditable, and schema-compatible."""
from sqlalchemy import select, func
from deepsnout.config import Policy
from deepsnout.db import (
    Host, Finding, Expectation, State, policy, now, transaction,
)
from deepsnout.cleanup import preview_retirement, retire_legacy_detectors


def test_new_deployment_defaults_disable_legacy_detectors():
    config = Policy()
    assert not config.execution_enabled
    assert not config.contextual_enabled
    assert not config.network_enabled
    assert config.behavioral_enabled


def test_retirement_disables_detectors_but_only_deletes_network_findings(engine):
    with transaction(engine) as db:
        stamp = now()
        host = Host(id="retirement-host", name="test-host.example", namespace="test",
                    first_seen=stamp - 3600, last_seen=stamp)
        db.add(host)
        db.flush()
        for detector in ("DS-EXEC-001", "DS-EXEC-002",
                         "DS-NET-001", "DS-BEH-001"):
            db.add(Finding(
                host_id=host.id, detector=detector,
                context=detector, title="Synthetic", summary="Test",
                first_seen=stamp, last_seen=stamp,
                evidence={"process": {"image": "fake.exe"}},
            ))
        db.add(Expectation(
            host_id=host.id, detector="DS-NET-001", context="net",
            reason="Synthetic existing", owner="tester", expires=stamp + 86400,
        ))
        db.flush()
        before = preview_retirement(db)
        assert before["ds_net_findings_to_delete"] == 1
        assert before["ds_net_expectations_to_delete"] == 1
        report = retire_legacy_detectors(db)
        assert report["deleted_findings"] == 1
        assert report["deleted_expectations"] == 1
        assert policy(db).execution_enabled is False
        assert policy(db).contextual_enabled is False
        assert policy(db).network_enabled is False
        assert {f.detector for f in db.scalars(select(Finding))} == {
            "DS-EXEC-001", "DS-EXEC-002", "DS-BEH-001"
        }
        assert db.scalar(select(func.count()).select_from(Expectation)) == 0
        assert db.get(State, "finding_quality_snapshot").value is None
        # Safe to repeat; cleanup is idempotent.
        again = retire_legacy_detectors(db)
        assert again["deleted_findings"] == 0
