"""Synthetic negative controls for non-suppressive similarity validation."""
from deepsnout.similarity_validation import assess_residual_quality, overlap_stats
from deepsnout.similarity_cohorts import discover_similarity_cohorts


def _profiles(derived_only=False):
    profiles = {}
    for family in ("cad", "office"):
        for i in range(100):
            apps = {f"app:{family}-a.exe": 1.0,
                    f"app:{family}-b.exe": 1.0,
                    "app:common.exe": 1.0}
            # If derived_only, all process/network agreement comes from the
            # two seed executables. It must not count as residual support.
            process = {f"pc:explorer.exe>{family}-a.exe": 1.0}
            network = {f"net:{family}-b.exe:ip": 1.0}
            if not derived_only:
                process[f"pc:{family}-service.exe>shared-helper.exe"] = 1.0
                network[f"net:{family}-agent.exe:ip"] = 1.0
            raw = {"applications": apps, "process": process,
                   "network": network, "activity": {"activity:utc12": 1.0}}
            profiles[f"{family}-{i:03d}"] = {
                "raw": raw, "channels": raw, "observed_days": 21}
    return profiles


def test_seed_derived_process_network_agreement_is_not_support():
    groups, report = discover_similarity_cohorts(
        "synthetic", _profiles(derived_only=True), False, 100)
    assert groups
    assert report["supported_groups"] == 0
    assert all(group["status"] == "exploratory" for group in groups)
    assert all(group["residual_supporting_views"] == [] for group in groups)
    assert all(group["peer_suppression_allowed"] is False for group in groups)


def test_nonseed_cross_view_patterns_can_support_candidates():
    groups, report = discover_similarity_cohorts(
        "synthetic", _profiles(), False, 100)
    assert groups
    assert report["quality_evaluated"] >= report["groups"]
    assert report["residual_evaluated_supported"] >= report["supported_groups"]
    assert any(group["status"] == "supported" for group in groups)
    assert all(group["residual_matched_pairs"] > 0 for group in groups)
    assert sum(report["member_multiplicity"].values()) == report["hosts_covered"]


def test_unmatched_telemetry_fails_closed():
    data = _profiles()
    for host, profile in data.items():
        if host.startswith("office"):
            profile["raw"]["applications"] = {
                f"app:unrelated-{i}.exe": 1.0 for i in range(60)}
            profile["observed_days"] = 7
    group = {"id": "bs-test", "anchors": ["cad-a.exe", "cad-b.exe"],
             "members": [host for host in data if host.startswith("cad")]}
    assess_residual_quality(data, [group])
    assert group["residual_matched_pairs"] == 0
    assert group["residual_supporting_views"] == []


def test_overlap_counts_contain_no_identifiers():
    groups = [{"members": ["a", "b", "c"]},
              {"members": ["b", "c", "d"]},
              {"members": ["a", "b", "c"]}]
    counts = overlap_stats(groups)
    assert counts["hosts_with_multiple_memberships"] == 3
    assert counts["max_memberships_per_host"] == 3
    assert counts["member_multiplicity"] == {
        "1": 1, "2": 1, "3": 2, "4": 0, "5+": 0}
    assert counts["group_pairs_over_75pct_jaccard"] == 1
    assert "secret-hostname" not in str(counts)
