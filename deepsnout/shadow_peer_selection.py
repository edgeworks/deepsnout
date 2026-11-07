"""Pure shadow-mode selection of candidate peer reference pools.

Inputs are frozen training memberships and a separate later-window assessment.
For each host and comparison view, retain one highest-evidence group rather
than treating every overlapping software-derived group as interchangeable.
The report contains aggregate counts only and is NOT a detector policy,
benign classification, validated anomaly score, or suppression decision.
"""
from collections import Counter

SCREENING_DELTA = 0.08
SENSITIVITY_DELTA = 0.12
MIN_LATER_PEERS = 10
MIN_MATCHED_PAIRS = 24


def _sensitivity_case(groups, rows, later_host_ids, minimum_delta):
    """Choose one qualifying comparison group per host and feature channel.

    A group must have satisfied both its training screening and later-window
    residual screening. The application candidates are frozen from training;
    current window observations only determine whether the host has adequate
    coverage and how its already-discovered group compares to outside controls.
    This is a descriptive retrospective ranking for *future* use, not an
    independent evaluation of the ranking itself.
    """
    qualified = {"process": {}, "network": {}}
    potential = {"process": 0, "network": 0}
    for index, (group, row) in enumerate(zip(groups, rows)):
        if not row["training_screening_support"] or not row["later_residual_support"]:
            continue
        members = sorted(set(group["members"]) & later_host_ids)
        if len(members) < MIN_LATER_PEERS + 1:
            continue
        if row["seed_persistence_fraction"] is None or row["seed_persistence_fraction"] < 0.50:
            continue
        for channel in ("process", "network"):
            metrics = row["residual_" + channel]
            if (metrics["comparable_pairs"] < MIN_MATCHED_PAIRS
                    or metrics["within"] is None or metrics["within"] < 0.12
                    or metrics["delta"] is None or metrics["delta"] < minimum_delta):
                continue
            potential[channel] += len(members)
            # This is a ranking heuristic, not a calibrated score. Prefer
            # higher held-out advantage, then better supported pair sample,
            # then larger qualifying groups. Stable ordinal breaks ties.
            priority = (metrics["delta"], metrics["comparable_pairs"],
                        len(members), -index)
            for host in members:
                current = qualified[channel].get(host)
                if current is None or priority > current[0]:
                    qualified[channel][host] = (priority, index)
    process_hosts = set(qualified["process"])
    network_hosts = set(qualified["network"])
    selected = process_hosts | network_hosts
    usage = Counter(index for winners in qualified.values()
                    for _, index in winners.values())
    return {
        "minimum_residual_delta": minimum_delta,
        "process_hosts_with_preferred_pool": len(process_hosts),
        "network_hosts_with_preferred_pool": len(network_hosts),
        "hosts_with_any_preferred_pool": len(selected),
        "hosts_with_both_views": len(process_hosts & network_hosts),
        "distinct_pools_preferred": len(usage),
        "potential_view_memberships": sum(potential.values()),
        "preferred_view_assignments": len(process_hosts) + len(network_hosts),
        "maximum_preferred_view_assignments_per_host": 2,
        "highest_pool_assignment_count": max(usage.values(), default=0),
        "assumes_same_app_peer_qualification": False,
    }


def shadow_peer_selection_summary(groups, rows, later_profiles, minimum_later_days=3):
    """Aggregate two sensitivity scenarios without releasing host/group IDs.

    All validation labels and thresholds are exploratory. In particular,
    application-specific minimum-peer counts required by DS-EXEC-002 have not
    been checked and nothing here can alter live detector behavior.
    """
    if len(groups) != len(rows):
        raise ValueError("Training groups and validation rows must align")
    later_host_ids = {
        host for host, p in later_profiles.items()
        if p.get("observed_days", 0) >= minimum_later_days
    }
    return {
        "method": "future-reference-pool-shadow-v1",
        "detector_changes": False,
        "suppression_allowed": False,
        "application_specific_qualification_checked": False,
        "later_eligible_hosts": len(later_host_ids),
        "scenarios": [
            _sensitivity_case(groups, rows, later_host_ids, cutoff)
            for cutoff in (SCREENING_DELTA, SENSITIVITY_DELTA)
        ],
    }
