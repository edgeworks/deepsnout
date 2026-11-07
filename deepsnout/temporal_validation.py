"""Read-only retrospective test of application-seeded similarity cohorts.

Discovery uses the oldest 21 of the last 28 completed UTC days and freezes
group memberships before scoring the subsequent seven completed days.
No detector, approval, group assignment or database state is changed.
The returned report includes only counts and rounded similarity measures.
"""
from sqlalchemy import select

from .db import Host
from .peer_groups import DAY, MAX_REFERENCE_DAYS, _namespace_profiles
from .similarity_cohorts import ALGORITHM, discover_similarity_cohorts
from .similarity_validation import assess_residual_quality
from .shadow_peer_selection import shadow_peer_selection_summary

TRAINING_DAYS = 21
HOLDOUT_DAYS = 7
MIN_LATER_DAYS = 3
MIN_GROUP_MEMBERS = 12
MIN_SEED_PERSISTENCE = 0.50


def evaluate_temporal_cohorts(namespace, training_profiles, later_profiles, clock):
    """Compare training-selected groups with disjoint later-period observations."""
    groups, training = discover_similarity_cohorts(
        namespace, training_profiles, False, clock)
    later = {host: p for host, p in later_profiles.items()
             if p.get("observed_days", 0) >= MIN_LATER_DAYS}
    rows = []
    for index, group in enumerate(groups, 1):
        # Membership is fixed from training. Later features cannot recruit peers.
        eligible = [host for host in group["members"] if host in later]
        comparison = {"id": group["id"], "anchors": group["anchors"],
                      "members": eligible}
        if len(eligible) >= MIN_GROUP_MEMBERS:
            assess_residual_quality(later, [comparison])
        else:
            comparison["residual_matched_pairs"] = 0
            comparison["residual_supporting_views"] = []
            comparison["residual_quality"] = {
                k: {"within": None, "matched_control": None,
                    "delta": None, "comparable_pairs": 0}
                for k in ("process", "network")}
        seen_seeds = sum(
            all(later[host].get("raw", {}).get("applications", {}).get(
                "app:" + anchor, 0) >= 0.30 for anchor in group["anchors"])
            for host in eligible
        )
        persistence = round(seen_seeds / len(eligible), 3) if eligible else None
        supported_later = (bool(comparison["residual_supporting_views"])
                           and persistence is not None
                           and persistence >= MIN_SEED_PERSISTENCE)
        rows.append({
            "group_number": index,
            "training_members": group["size"],
            "observed_later": len(eligible),
            "later_member_fraction": round(len(eligible) / group["size"], 3),
            "seed_persistence_fraction": persistence,
            "training_screening_support": group["status"] == "supported",
            "later_residual_support": supported_later,
            "residual_matched_pairs": comparison["residual_matched_pairs"],
            "residual_process": comparison["residual_quality"]["process"],
            "residual_network": comparison["residual_quality"]["network"],
        })
    return {
        "training_hosts_profiled": len(training_profiles),
        "training_hosts_eligible": training["hosts_eligible"],
        "later_hosts_profiled": len(later_profiles),
        "later_hosts_with_3_days": len(later),
        "training_groups_displayed": len(groups),
        "training_groups_screened_supported": training["supported_groups"],
        "groups_with_12_later_hosts": sum(
            row["observed_later"] >= MIN_GROUP_MEMBERS for row in rows),
        "groups_with_later_residual_support": sum(
            row["later_residual_support"] for row in rows),
        "shadow_reference_pools": shadow_peer_selection_summary(
            groups, rows, later, minimum_later_days=MIN_LATER_DAYS),
        "groups": rows,
    }


def run_temporal_shadow_validation(db, clock):
    """Scan disjoint historical windows without writing back to the database."""
    if TRAINING_DAYS + HOLDOUT_DAYS != MAX_REFERENCE_DAYS:
        raise RuntimeError("Temporal split must use the bounded reference period")
    today = int(clock) // DAY
    train_start, train_end = today - MAX_REFERENCE_DAYS, today - HOLDOUT_DAYS - 1
    test_start, test_end = today - HOLDOUT_DAYS, today - 1
    namespaces = db.scalars(select(Host.namespace).distinct()).all()
    populations = []
    for namespace in sorted(namespaces):
        training, _, _, _, _, _ = _namespace_profiles(
            db, namespace, clock, day_start=train_start, day_end=train_end)
        test, _, _, _, _, _ = _namespace_profiles(
            db, namespace, clock, day_start=test_start, day_end=test_end)
        populations.append(evaluate_temporal_cohorts(
            namespace, training, test, clock))
    return {
        "method": "disjoint-utc-days-v1",
        "algorithm": ALGORITHM,
        "training_completed_days": TRAINING_DAYS,
        "later_completed_days": HOLDOUT_DAYS,
        "minimum_later_observed_days": MIN_LATER_DAYS,
        "read_only": True,
        "changes_detection_policy": False,
        "populations": populations,
    }
