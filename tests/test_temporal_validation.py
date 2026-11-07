"""Synthetic disjoint-time-window tests; no internal fleet telemetry."""
import pytest
from deepsnout.temporal_validation import (
    evaluate_temporal_cohorts, run_temporal_shadow_validation,
)
from deepsnout.peer_groups import _namespace_profiles, MAX_REFERENCE_DAYS
from deepsnout.db import Host
from conftest import DAY_START, DAY
from test_peer_groups import seed_two_groups


def synthetic_profiles(later_same=True, days=14):
    result = {}
    for family in ("office", "cad"):
        for i in range(100):
            apps = {f"app:{family}-{j}.exe": 1.0 for j in range(4)}
            apps["app:universal.exe"] = 1.0
            process = {f"pc:{family}-service.exe>{family}-helper.exe": 1.0}
            network = {f"net:{family}-other.exe:ip": 1.0}
            if not later_same:
                # All hosts share the same later behavior. Historic groups
                # must lose their apparent discriminatory advantage.
                apps = {f"app:common-{j}.exe": 1.0 for j in range(5)}
                process = {"pc:shared.exe>common.exe": 1.0}
                network = {"net:shared.exe:ip": 1.0}
            raw = {"applications": apps, "process": process,
                   "network": network,
                   "activity": {"activity:12-18utc": 1.0}}
            result[f"{family}-{i:03d}"] = {
                "raw": raw, "channels": raw, "observed_days": days}
    return result


def test_genuine_stable_cohorts_survive_later_period():
    report = evaluate_temporal_cohorts(
        "synthetic", synthetic_profiles(), synthetic_profiles(days=5), DAY_START)
    assert report["training_groups_displayed"] > 0
    assert report["groups_with_later_residual_support"] > 0
    assert all(item["seed_persistence_fraction"] == 1.0
               for item in report["groups"])
    assert "synthetic" not in str(report)
    assert "office-" not in str(report)
    assert "cad-" not in str(report)


def test_training_only_signals_cannot_prove_later_support():
    report = evaluate_temporal_cohorts(
        "synthetic", synthetic_profiles(),
        synthetic_profiles(later_same=False, days=5), DAY_START)
    assert report["training_groups_displayed"] > 0
    assert report["groups_with_later_residual_support"] == 0
    assert all(row["seed_persistence_fraction"] == 0
               for row in report["groups"])


def test_sparse_later_history_is_not_support():
    report = evaluate_temporal_cohorts(
        "synthetic", synthetic_profiles(), synthetic_profiles(days=2),
        DAY_START)
    assert report["later_hosts_with_3_days"] == 0
    assert report["groups_with_later_residual_support"] == 0
    assert all(row["observed_later"] == 0 for row in report["groups"])


def test_explicit_windows_are_disjoint_and_bounded(db):
    seed_two_groups(db, [1, 2, 3, 10, 11, 12, 20, 21])
    today = DAY_START // DAY
    test, _, _, _, partial, _ = _namespace_profiles(
        db, "default", DAY_START + 60,
        day_start=today-7, day_end=today-1)
    train, _, _, _, train_partial, _ = _namespace_profiles(
        db, "default", DAY_START + 60,
        day_start=today-28, day_end=today-8)
    assert not partial and not train_partial
    assert test["cad0"]["observed_days"] == 3
    assert train["cad0"]["observed_days"] == 5
    with pytest.raises(ValueError):
        _namespace_profiles(db, "default", DAY_START+60,
                            day_start=today-MAX_REFERENCE_DAYS-1,
                            day_end=today-8)
    with pytest.raises(ValueError):
        _namespace_profiles(db, "default", DAY_START+60,
                            day_start=today-7, day_end=today)


def test_temporal_command_makes_no_group_changes(db):
    seed_two_groups(db, [1, 2, 3, 10, 11, 12, 20, 21])
    before = [host.cohort for host in db.query(Host).order_by(Host.id)]
    report = run_temporal_shadow_validation(db, DAY_START+60)
    assert before == [host.cohort for host in db.query(Host).order_by(Host.id)]
    assert report["read_only"] and not report["changes_detection_policy"]
    assert report["training_completed_days"] == 21
    assert report["later_completed_days"] == 7
    assert report["populations"][0]["training_hosts_profiled"] == 6
    assert "cad0" not in str(report)
    assert "default" not in str(report)
