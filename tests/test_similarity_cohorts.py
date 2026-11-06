"""Synthetic tests only; no live telemetry or organizational data."""
from deepsnout.similarity_cohorts import discover_similarity_cohorts


def make_profiles(populations, supported=True):
    profiles = {}
    for family, size in populations.items():
        for number in range(size):
            apps = {f"app:{family}-{j}.exe": 1.0 for j in range(5)}
            apps["app:universal.exe"] = 1.0
            process = {f"pc:{family}>child.exe": 1.0} if supported else {}
            network = {f"net:{family}.exe:ip": 1.0} if supported else {}
            raw = {"applications": apps, "process": process,
                   "network": network, "activity": {"activity:utc12": 1.0}}
            profiles[f"{family}-{number:05d}"] = {
                "raw": raw, "channels": raw, "observed_days": 21}
    return profiles


def test_recurring_shared_features_form_supported_groups():
    profiles = make_profiles({"office": 180, "cad": 160, "server": 160})
    groups, report = discover_similarity_cohorts("synthetic", profiles, False, 100)
    assert report["hosts_eligible"] == 500
    assert groups and max(g["size"] for g in groups) >= 150
    assert any(g["status"] == "supported" for g in groups)
    assert all(g["quality"]["applications"]["delta"] > 0.1 for g in groups)
    assert all(g["peer_suppression_allowed"] is False for g in groups)
    assert all(len(g["anchors"]) == 2 for g in groups)


def test_equal_counts_without_shared_features_do_not_form_groups():
    profiles = {}
    for number in range(200):
        raw = {"applications": {f"app:unique-{number}-{j}.exe": 1.0 for j in range(5)}}
        profiles[str(number)] = {"raw": raw, "channels": raw, "observed_days": 14}
    groups, report = discover_similarity_cohorts("synthetic", profiles, False, 100)
    assert groups == [] and report["candidate_pairs"] == 0


def test_same_applications_without_other_evidence_do_not_gain_support():
    profiles = make_profiles({"office": 100, "cad": 100}, supported=False)
    groups, report = discover_similarity_cohorts("synthetic", profiles, False, 100)
    assert groups
    assert report["supported_groups"] == 0
    assert all(g["status"] == "exploratory" for g in groups)


def test_sparse_hosts_remain_ungrouped():
    profiles = make_profiles({"office": 80, "cad": 80})
    for host in sorted(profiles)[:70]:
        profiles[host]["observed_days"] = 2
    groups, report = discover_similarity_cohorts("synthetic", profiles, False, 100)
    assert report["hosts_eligible"] == 90
    assert all(profiles[host]["observed_days"] >= 7
               for group in groups for host in group["members"])


def test_bounded_5000_host_discovery_is_deterministic():
    profiles = make_profiles({"office": 1200, "cad": 1300, "server": 2500})
    groups, report = discover_similarity_cohorts("synthetic", profiles, False, 100)
    assert report["hosts_eligible"] == 5000
    assert report["quality_evaluated"] <= 80
    assert len(groups) <= 32
    assert all(group["peer_suppression_allowed"] is False for group in groups)
    another, _ = discover_similarity_cohorts("synthetic", profiles, False, 200)
    assert [(g["id"], g["members"], g["status"]) for g in groups] == [
        (g["id"], g["members"], g["status"]) for g in another]
