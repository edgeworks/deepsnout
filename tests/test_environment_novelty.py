"""Synthetic tests for environmental rarity, not ATT&CK or threat signatures."""
from sqlalchemy import select

from conftest import CLOCK, DAY, DAY_START, baseline, evt
from deepsnout.db import BehaviorDay, Coverage, Finding, Host, policy, set_state
from deepsnout.engine import ingest, host_key
from deepsnout.normalize import digest


def seed_fleet(db, *, count=50, namespace="default", days=1):
    """Populate synthetic endpoint summaries; never real SOC telemetry."""
    for i in range(count):
        hostname = f"fleet-{i:03d}.example"
        hid = host_key(namespace, hostname)
        db.add(Host(id=hid, name=hostname, namespace=namespace,
                    first_seen=DAY_START-days*DAY+3600,
                    last_seen=DAY_START-DAY+3600, cohort="unassigned"))
    # SQLAlchemy has no ORM relationships declaring the insert dependency;
    # flush parent hosts before inserting child coverage/behavior rows.
    db.flush()
    for i in range(count):
        hid = host_key(namespace, f"fleet-{i:03d}.example")
        for offset in range(1, days+1):
            day = DAY_START // DAY - offset
            db.add(Coverage(id=digest(hid, day, 1), host_id=hid,
                            day=day, event_id=1, count=1))
            db.add(BehaviorDay(
                id=digest(hid, day, "normal-context"), host_id=hid, day=day,
                context="normal-context", app="utility.exe", parent="explorer.exe",
                location="program-files", count=1,
                first_seen=day*DAY+3600, last_seen=day*DAY+3600, sample={}))
    db.flush()


def findings(db, detector="DS-BEH-001"):
    return list(db.scalars(select(Finding).where(Finding.detector == detector)))


def test_locally_new_application_is_discovered_without_network_or_signature(db):
    seed_fleet(db)
    ingest(db, baseline("subject"), clock=CLOCK)
    ingest(db, [evt(host="subject", n=900,
                    Image=r"C:\Program Files\NovelTool\newtool.exe")], clock=CLOCK)
    results = findings(db)
    assert len(results) == 1
    f = results[0]
    assert f.priority == "review"
    assert f.evidence["environment"]["category"] == "rare_application"
    assert f.evidence["environment"]["reference"]["fleet_hosts_with_process_coverage"] == 51
    assert f.evidence["environment"]["reference"]["fleet_application_hosts"] == 0
    assert f.evidence["reference"]["prior_observed_days"] == 8
    assert "network" not in f.evidence
    assert f.evidence["environment"]["cohort_reference"]["available"] is False
    assert "ATT&CK" not in f.summary


def test_new_parent_for_common_application_is_discovered_without_outbound(db):
    seed_fleet(db)
    ingest(db, baseline("subject"), clock=CLOCK)
    ingest(db, [evt(host="subject", n=901,
                    ParentImage=r"C:\Program Files\Office\winword.exe")], clock=CLOCK)
    results = findings(db)
    assert len(results) == 1
    evidence = results[0].evidence["environment"]
    assert evidence["category"] == "rare_launch_relationship"
    assert evidence["reference"]["fleet_application_hosts"] == 51
    assert evidence["reference"]["fleet_launch_relationship_hosts"] == 0
    assert evidence["prior_local_app_days"] == 8


def test_new_command_flags_with_common_fleet_behavior_are_not_outliers(db):
    seed_fleet(db)
    ingest(db, baseline("subject"), clock=CLOCK)
    ingest(db, [evt(host="subject", n=902,
                    CommandLine="utility.exe -EncodedCommand abc")], clock=CLOCK)
    assert findings(db) == []


def test_insufficient_fleet_or_local_history_stays_uncertain(db):
    seed_fleet(db, count=45)
    ingest(db, baseline("subject"), clock=CLOCK)
    ingest(db, [evt(host="subject", n=903,
                    Image=r"C:\Tools\unfamiliar.exe")], clock=CLOCK)
    assert findings(db) == []
    seed_fleet(db, count=6, namespace="other")
    ingest(db, [evt(host="brand-new-host", n=904,
                    Image=r"C:\Tools\unfamiliar.exe")], clock=CLOCK)
    assert findings(db) == []


def test_one_application_rarety_finding_for_multiple_new_contexts(db):
    seed_fleet(db)
    ingest(db, baseline("subject"), clock=CLOCK)
    records = [
        evt(host="subject", n=905,
            Image=r"C:\Tools\random-app.exe"),
        evt(host="subject", n=906,
            Image=r"C:\Tools\random-app.exe",
            ParentImage=r"C:\Program Files\Office\winword.exe"),
    ]
    ingest(db, records, clock=CLOCK)
    assert len(findings(db)) == 1
    assert findings(db)[0].occurrences == 2


def test_behavioral_discovery_respects_policy_switch(db):
    seed_fleet(db)
    ingest(db, baseline("subject"), clock=CLOCK)
    config = policy(db)
    config.behavioral_enabled = False
    set_state(db, "policy", config.model_dump())
    ingest(db, [evt(host="subject", n=907,
                    Image=r"C:\Tools\random-app.exe")], clock=CLOCK)
    assert findings(db) == []


def test_peer_reference_is_evidence_and_cannot_dismiss_outlier(db):
    seed_fleet(db, days=7)
    ingest(db, baseline("subject"), clock=CLOCK)
    subject = host_key("default", "subject")
    peers = [host_key("default", f"fleet-{i:03d}.example") for i in range(12)]
    set_state(db, "analytical_cohorts", {
        "similarity_groups": [{
            "id": "synthetic-cohort", "namespace": "default",
            "members": [subject, *peers], "size": 13, "status": "supported",
            "residual_quality": {
                "process": {"delta": 0.24}, "network": {"delta": 0.20}},
        }],
    })
    ingest(db, [evt(host="subject", n=908,
                    ParentImage=r"C:\Program Files\Office\winword.exe")], clock=CLOCK)
    result = findings(db)
    assert len(result) == 1
    peers = result[0].evidence["environment"]["cohort_reference"]
    assert peers["available"]
    assert peers["application_qualified_peers"] == 12
    assert peers["peers_with_same_parent_and_location"] == 0
    assert peers["use_for_suppression"] is False



def test_accepted_process_creates_explain_finding_pipeline(db):
    from deepsnout.db import State
    seed_fleet(db)
    baseline_report = ingest(db, baseline("subject"), clock=CLOCK)
    assert baseline_report["behavioral_pipeline"]["event1_outside_live_horizon"] >= 7
    record = evt(host="subject", n=991, Image=r"C:\Tools\unusual.exe")
    report = ingest(db, [record], clock=CLOCK)
    counters = report["behavioral_pipeline"]
    assert counters["event1_accepted"] == 1
    assert counters["event1_recent"] == 1
    assert counters["locally_new_with_established_history"] == 1
    assert counters["fleet_reference_eligible"] == 1
    assert counters["rare_application_candidates"] == 1
    state = db.get(State, "behavioral_discovery_pipeline").value
    day = str(int(CLOCK) // DAY)
    assert state["by_day"][day]["rare_application_candidates"] == 1
    assert "subject" not in str(state)
    assert "unusual.exe" not in str(state)


def test_duplicate_batch_does_not_inflate_diagnostic_counters(db):
    from deepsnout.db import State
    seed_fleet(db)
    event = evt(host="one-new-host", n=992)
    first = ingest(db, [event], batch_id="test-counters-id", clock=CLOCK)
    before = dict(db.get(State, "behavioral_discovery_pipeline").value)
    replay = ingest(db, [event], batch_id="test-counters-id", clock=CLOCK)
    assert first["behavioral_pipeline"]["event1_recent"] == 1
    assert replay["batch_replay"] is True
    assert db.get(State, "behavioral_discovery_pipeline").value == before


def test_disabled_detector_still_reports_live_ingest(db):
    seed_fleet(db)
    current = policy(db)
    current.behavioral_enabled = False
    set_state(db, "policy", current.model_dump())
    report = ingest(db, [evt(host="test-new", n=993)], clock=CLOCK)
    assert report["behavioral_pipeline"]["event1_recent"] == 1
    assert report["behavioral_pipeline"]["detector_disabled"] == 1


def test_learning_and_familiar_context_are_counted(db):
    seed_fleet(db)
    report = ingest(db, [evt(host="new-host", n=994)], clock=CLOCK)
    assert report["behavioral_pipeline"]["insufficient_local_history"] == 1
    ingest(db, baseline("subject"), clock=CLOCK)
    report = ingest(db, [evt(host="subject", n=995)], clock=CLOCK)
    assert report["behavioral_pipeline"]["locally_familiar_context"] == 1
