"""Synthetic cohort checks; no live fleet or organization telemetry."""
from deepsnout.analytical_cohorts import (
    discover_analytical_cohorts, anonymized_cohort_metrics, analytical_cohort_state,
    assess_cohort_quality,
)
from deepsnout.peer_groups import _candidate_pairs, refresh_peer_groups
from deepsnout.db import Host
from conftest import DAY_START
from test_peer_groups import seed_two_groups


def profiles_for(count):
    profiles = {}
    for number in range(count):
        profiles[f"host-{number:05d}"] = {
            "raw": {
                "applications": {f"app:a{i}.exe": 1.0 for i in range(1 + number % 9)},
                "process": {f"pc:p{i}>c.exe": 1.0 for i in range(1 + number % 5)},
                "network": {f"net:a{i}.exe:ip": 1.0 for i in range(number % 4)},
                "activity": {f"activity:utc{i}": 1.0 for i in range(1 + number % 3)},
            }, "observed_days": 14,
        }
    return profiles


def test_overlapping_shadows_with_5000_synthetic_hosts():
    profiles = profiles_for(5000)
    groups, summary = discover_analytical_cohorts("synthetic", profiles, False, DAY_START)
    assert summary["hosts_profiled"] == 5000
    assert summary["hosts_covered"] >= 4000
    assert summary["member_assignments"] > 5000
    assert all(group["size"] >= 250 for group in groups)
    assert all(group["maturity"] == "stable" for group in groups)
    assert all(group["peer_suppression_allowed"] is False for group in groups)
    updated, _ = discover_analytical_cohorts("synthetic", profiles, False, DAY_START + 60)
    assert [(g["id"], g["members"]) for g in updated] == [(g["id"], g["members"]) for g in groups]
    report = anonymized_cohort_metrics({"algorithm": "analytical-strata-v1",
        "groups": groups, "summaries": [summary]})
    assert "synthetic" not in str(report) and "host-" not in str(report)
    assert report["namespace_statistics"][0]["hosts_profiled"] == 5000


def test_equal_values_not_arbitrarily_separated():
    profiles = profiles_for(90)
    for profile in profiles.values():
        profile["raw"]["applications"] = {"app:same.exe": 1.0}
    groups, _ = discover_analytical_cohorts("demo", profiles, True, DAY_START)
    assert not any(g["dimension"] == "applications" for g in groups)
    assert all(g["maturity"] == "provisional" for g in groups)


def test_pair_search_bounded_at_5000():
    profiles = {}
    for number in range(5000):
        features = {f"app:family-{number // 250}-{i}.exe": 1.0 for i in range(6)}
        profiles[f"host-{number:05d}"] = {
            "channels": {"applications": features, "bundles": {},
                         "process": {}, "network": {}}, "technical": {},
        }
    pairs = _candidate_pairs(profiles)
    assert pairs
    assert len(pairs) < 100000
    assert all(left != right for left, right in pairs)


def test_refresh_preserves_detector_group_assignments(db):
    seed_two_groups(db, [1, 2, 3, 4, 5, 6, 7, 8])
    before = [h.cohort for h in db.query(Host).order_by(Host.id)]
    result = refresh_peer_groups(db, clock=DAY_START + 3600)
    assert result["analytical_cohorts"] >= 0
    after = [h.cohort for h in db.query(Host).order_by(Host.id)]
    assert before == after
    state = analytical_cohort_state(db)
    assert state["algorithm"] == "analytical-strata-v1"
    assert state["summaries"][0]["hosts_profiled"] == 6



def test_sampled_similarity_distinguishes_real_features_from_breadth():
    # Identical feature count across every host; actual application identities
    # distinguish the two populations. A feature *count* alone cannot do this.
    profiles = {}
    for i in range(120):
        label = "alpha" if i < 60 else "beta"
        profiles[f"host{i:03d}"] = {
            "channels": {
                "applications": {f"app:{label}-{j}.exe": 1.0 for j in range(3)},
                "network": {f"net:{label}-agent:ip": 1.0},
                "process": {},
                "activity": {"activity:utc1": 1.0},
            },
            "observed_days": 20,
        }
    sample = [{"id": "ac-test", "dimension": "activity",
               "members": [f"host{i:03d}" for i in range(60)]}]
    assess_cohort_quality(profiles, sample)
    quality = sample[0]["quality"]
    assert quality["applications"]["within"] == 1.0
    assert quality["applications"]["delta"] > 0.2
    assert quality["network"]["delta"] > 0.2
    assert sample[0]["independent_support_channels"] == 2
    assert quality["process"]["within"] is None
    assert quality["process"]["fleet"] is None


def test_quality_has_no_false_support_when_all_profiles_identical():
    profiles = {
        f"host{i:03d}": {"channels": {"applications": {"app:same.exe": 1.0}},
                          "observed_days": 8}
        for i in range(60)
    }
    groups = [{"id": "ac-same", "dimension": "applications",
               "members": [f"host{i:03d}" for i in range(30)]}]
    assess_cohort_quality(profiles, groups)
    assert groups[0]["independent_support_channels"] == 0
    assert groups[0]["quality"]["applications"]["delta"] == 0
    assert groups[0]["quality"]["network"]["within"] is None


def test_counts_only_report_contains_no_identifiers_or_features(db):
    seed_two_groups(db, [1, 2, 3, 4, 5, 6, 7, 8])
    refresh_peer_groups(db, clock=DAY_START + 3600)
    from deepsnout.peer_groups import suggestion_state
    report = anonymized_cohort_metrics(analytical_cohort_state(db), suggestion_state(db))
    assert "default" not in str(report)
    assert "cad0" not in str(report)
    assert "acad.exe" not in str(report)
    assert "legacy_unreviewed_group_sizes" in report
    assert report["namespace_statistics"][0]["hosts_known"] == 6
    assert sum(report["namespace_statistics"][0]["observed_day_bands"].values()) == 6



def test_similarity_snapshot_does_not_change_detector_memberships(db):
    seed_two_groups(db, [1, 2, 3, 4, 5, 6, 7, 8])
    before = [h.cohort for h in db.query(Host).order_by(Host.id)]
    report = refresh_peer_groups(db, clock=DAY_START + 3600)
    assert "behavioral_similarity_cohorts" in report
    assert before == [h.cohort for h in db.query(Host).order_by(Host.id)]
    state = analytical_cohort_state(db)
    assert "similarity_groups" in state
    assert "similarity_summaries" in state
    safe = anonymized_cohort_metrics(state)
    assert "default" not in str(safe)
    assert "cad" not in str(safe)
