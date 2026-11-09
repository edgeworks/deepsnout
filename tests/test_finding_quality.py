"""Finding self-diagnosis uses only synthetic observations, no org identities."""
from types import SimpleNamespace

from deepsnout.finding_quality import (
    summarize_finding_rows, metrics_from_snapshot, _name_shape, _consensus,
    MIN_FAMILY_FINDINGS,
)


def _row(i, *, name, parent="update-agent.exe", namespace="fleet",
         location="windows", detector="DS-BEH-001",
         category="rare_application", high=False):
    host = SimpleNamespace(id=f"host-{i%149}", namespace=namespace)
    finding = SimpleNamespace(
        id=f"finding-{i:05d}",
        detector=detector, priority="high" if high else "review",
        state="new", first_seen=1000+i, last_seen=1000+i,
        evidence={
            "process": {"image": rf"C:\Windows\{name}",
                        "parent": parent, "location": location},
            "environment": {"category": category},
            "flags": {"remote_reference": False},
        },
    )
    return finding, host


def test_discovers_one_large_version_family_without_vendor_signatures():
    # Mirrors the *shape and scale* of a real batch, not its real names.
    rows = [
        _row(i, name=f"Fleet_Updater_9.18.{i%8}.0.exe")
        for i in range(442)
    ]
    rows.extend(
        _row(442+i, name=f"unrelated-{i}.exe",
             parent="other-agent.exe") for i in range(15)
    )
    snapshot = summarize_finding_rows(rows, clock=2000)
    assert snapshot["source_findings"] == 457
    assert snapshot["dominant_family_findings"] == 442
    assert snapshot["dominant_family_share"] == round(442/457, 4)
    assert snapshot["self_diagnosis"] == "one-family-dominance"
    family = snapshot["families"][0]
    assert family["host_count"] == 149
    assert family["variant_count"] == 8
    assert family["version_churn"] is True
    assert family["family_pattern"] == "fleet_updater_9.18.*.0.exe"
    assert len(family["member_ids"]) == 442
    assert "dominates-findings-stream" in family["quality_signals"]
    assert snapshot["read_only"] and not snapshot["suppression_allowed"]
    assert snapshot["findings_not_in_displayed_families"] == 15
    assert all("unrelated" not in item["family_pattern"] for item in snapshot["families"])
    # This endpoint response must not leak the synthetically named application.
    assert "updater" not in str(metrics_from_snapshot(snapshot))
    assert "host-" not in str(metrics_from_snapshot(snapshot))


def test_identical_names_can_be_repetitive_without_a_numeric_version():
    rows = [_row(i, name="stable.exe") for i in range(12)]
    snapshot = summarize_finding_rows(rows, clock=2000)
    family = snapshot["families"][0]
    assert family["variant_count"] == 1
    assert not family["version_churn"]
    assert family["host_count"] == 12
    assert snapshot["self_diagnosis"] == "one-family-dominance"


def test_parent_location_detector_category_and_namespace_are_boundaries():
    rows = []
    for i in range(4):
        rows.append(_row(i, name=f"Updater_2.{i}.exe"))
        rows.append(_row(i+5, name=f"Updater_2.{i}.exe", parent="cmd.exe"))
        rows.append(_row(i+10, name=f"Updater_2.{i}.exe", location="temporary"))
        rows.append(_row(i+20, name=f"Updater_2.{i}.exe", detector="DS-EXEC-001"))
        rows.append(_row(i+30, name=f"Updater_2.{i}.exe", category="rare_launch_relationship"))
        rows.append(_row(i+40, name=f"Updater_2.{i}.exe", namespace="different"))
    snapshot = summarize_finding_rows(rows, clock=2000)
    assert snapshot["source_findings"] == 24
    assert snapshot["families_discovered"] == 0
    assert snapshot["findings_not_in_displayed_families"] == 24


def test_short_random_names_do_not_fuse_and_missing_evidence_is_ignored():
    assert _name_shape(r"C:\Temp\x123.exe", "") == ("x123.exe", "x123.exe")
    assert _name_shape(r"C:\Temp\x124.exe", "") == ("x124.exe", "x124.exe")
    rows = [_row(i, name=f"x{i:04d}.exe") for i in range(30)]
    no_process = SimpleNamespace(id="no", detector="DS-NET-001", priority="review",
                                 state="new", first_seen=1, last_seen=1,
                                 evidence={"app": "edge.exe"})
    rows.append((no_process, SimpleNamespace(namespace="fleet", id="host-100")))
    snapshot = summarize_finding_rows(rows, clock=2000)
    assert snapshot["families_discovered"] == 0
    assert snapshot["source_findings"] == 31
    assert snapshot["findings_with_process_evidence"] == 30


def test_widespread_behavior_may_be_malicious_and_remains_unchanged():
    rows = [_row(i, name="RedTeam.exe", high=True) for i in range(20)]
    rows[0][0].state = "malicious"
    snapshot = summarize_finding_rows(rows, clock=2000)
    family = snapshot["families"][0]
    assert family["high_priority_findings"] == 20
    assert family["malicious_findings"] == 1
    assert rows[0][0].state == "malicious"
    assert "malicious activity" in family["interpretation"]
    assert not snapshot["changes_finding_states"]
    assert len(family["member_ids"]) == 20


def test_no_findings_and_empty_source_are_valid_diagnostics():
    assert summarize_finding_rows([], clock=20)["self_diagnosis"] == "no-dominant-family"
    assert metrics_from_snapshot(None)["updated_at"] is None
