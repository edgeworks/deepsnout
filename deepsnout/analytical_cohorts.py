"""Machine-managed overlapping comparison strata (non-suppressive shadow mode).

Cohorts use coarse behavioral breadth from bounded 28-day host profiles.
They are neither approved organizational identities nor trusted benign baselines.
"""
import hashlib
import math
import random
import statistics
from itertools import combinations

ALGORITHM = "analytical-strata-v1"
DIMENSIONS = (
    ("applications", "Application breadth", "Routine non-Windows application names"),
    ("process", "Process relationship breadth", "Routine non-Windows parent-child relationships"),
    ("network", "Network-role breadth", "Routine application/network event types"),
    ("activity", "Activity-window breadth", "Observed six-hour UTC activity windows"),
)


def _bands(values):
    """Fleet tertiles, never split hosts with identical observations."""
    ordered = sorted(values.values())
    if len(set(ordered)) < 2:
        return ()
    lower = ordered[(len(ordered) - 1) // 3]
    upper = ordered[(2 * (len(ordered) - 1)) // 3]
    if lower == upper:
        return (("lower", lambda value: value <= lower),
                ("higher", lambda value: value > lower))
    return (("lower", lambda value: value <= lower),
            ("middle", lambda value: lower < value <= upper),
            ("higher", lambda value: value > upper))


def discover_analytical_cohorts(namespace, profiles, includes_current_day, clock):
    """Create broad overlapping pools; no host assignments or alert changes."""
    n = len(profiles)
    minimum_size = max(3, math.ceil(n * 0.05))
    groups = []
    covered = set()
    for channel, title, description in DIMENSIONS:
        values = {
            host_id: sum(weight >= 0.20
                         for weight in profile.get("raw", {}).get(channel, {}).values())
            for host_id, profile in profiles.items()
        }
        if len(values) < 3:
            continue
        for band, contains in _bands(values):
            members = sorted(host_id for host_id, value in values.items() if contains(value))
            if not minimum_size <= len(members) <= n * 0.95:
                continue
            days = int(statistics.median(
                profiles[host_id].get("observed_days", 0) for host_id in members))
            maturity = ("provisional" if includes_current_day or days < 3
                        else "growing" if days < 7 else "stable")
            numbers = [values[host_id] for host_id in members]
            identifier = hashlib.sha256(
                (namespace + "\0" + channel + "\0" + band).encode()
            ).hexdigest()[:16]
            groups.append({
                "id": "ac-" + identifier, "namespace": namespace,
                "label": title + ": " + band, "dimension": channel,
                "description": description, "band": band,
                "size": len(members), "members": members,
                "min_value": min(numbers), "max_value": max(numbers),
                "median_value": statistics.median(numbers),
                "median_observed_days": days, "maturity": maturity,
                "includes_current_day": bool(includes_current_day),
                "fraction": round(len(members) / n, 4),
                "peer_suppression_allowed": False, "calculated_at": clock,
            })
            covered.update(members)
    groups.sort(key=lambda item: (item["dimension"], item["band"], item["id"]))
    return groups, {
        "namespace": namespace, "hosts_profiled": n,
        "cohorts": len(groups), "hosts_covered": len(covered),
        "coverage_percent": round(100 * len(covered) / n, 1) if n else 0.0,
        "member_assignments": sum(item["size"] for item in groups),
        "includes_current_day": bool(includes_current_day),
    }


# Bound all quality comparisons regardless of population size. This function is
# invoked once per completed discovery job, never per ingested event.
MAX_QUALITY_PAIRS = 160
QUALITY_CHANNELS = ("applications", "process", "network", "activity")


def _sample_pairs(host_ids, seed):
    """Stable, uniformly sampled unordered host pairs without replacement."""
    host_ids = sorted(host_ids)
    population = len(host_ids)
    if population < 2:
        return []
    goal = min(MAX_QUALITY_PAIRS, population * (population - 1) // 2)
    if population <= 18:
        return list(combinations(host_ids, 2))
    rng = random.Random(int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16], 16))
    pairs = set()
    while len(pairs) < goal:
        left, right = sorted(rng.sample(host_ids, 2))
        pairs.add((left, right))
    return sorted(pairs)


def _overlap(first, second):
    """Weighted Jaccard. Two empty profiles are not comparable, not identical."""
    if not first and not second:
        return None
    if not first or not second:
        return 0.0
    both = set(first) & set(second)
    numerator = sum(min(first[item], second[item]) for item in both)
    denominator = sum(max(first.get(item, 0), second.get(item, 0))
                      for item in set(first) | set(second))
    return numerator / denominator if denominator else None


def assess_cohort_quality(profiles, groups):
    """Annotate shadow cohorts with sampled feature overlap versus fleet pairs.

    The defining dimension is NOT independent evidence of quality. We report all
    four channels separately so an analyst can evaluate cross-view agreement.
    These are descriptive, potentially biased overlap estimates, not p-values,
    security confidence, or approval for peer-based suppression.
    """
    if not groups:
        return
    fleet_pairs = _sample_pairs(profiles, "fleet-quality-v1")
    # The same fleet reference is reused across cohorts, ensuring that their
    # comparisons share a baseline rather than different random control groups.
    def average(pairs, channel):
        values = []
        for left, right in pairs:
            lp = profiles[left].get("channels") or profiles[left].get("raw", {})
            rp = profiles[right].get("channels") or profiles[right].get("raw", {})
            score = _overlap(lp.get(channel, {}), rp.get(channel, {}))
            if score is not None:
                values.append(score)
        return (sum(values) / len(values) if values else None, len(values))

    fleet = {channel: average(fleet_pairs, channel) for channel in QUALITY_CHANNELS}
    for group in groups:
        within_pairs = _sample_pairs(group["members"], group["id"] + ":quality-v1")
        comparisons = {}
        independent = 0
        for channel in QUALITY_CHANNELS:
            inside, inside_count = average(within_pairs, channel)
            outside, outside_count = fleet[channel]
            delta = (inside - outside if inside is not None and outside is not None
                     else None)
            comparisons[channel] = {
                "within": round(inside, 3) if inside is not None else None,
                "fleet": round(outside, 3) if outside is not None else None,
                "delta": round(delta, 3) if delta is not None else None,
                "within_pairs": inside_count,
                "fleet_pairs": outside_count,
            }
            if (channel != group["dimension"] and inside_count >= 12
                    and outside_count >= 12 and delta is not None
                    and inside is not None and inside >= 0.10 and delta >= 0.08):
                independent += 1
        group["quality"] = comparisons
        group["independent_support_channels"] = independent
        group["quality_pair_budget"] = MAX_QUALITY_PAIRS


def analytical_cohort_state(db):
    """Snapshot kept separately from legacy analyst-approved peer groups."""
    from .db import State
    entry = db.get(State, "analytical_cohorts")
    return (entry.value if entry and isinstance(entry.value, dict)
            else {"algorithm": ALGORITHM, "updated_at": 0,
                  "groups": [], "summaries": []})


def anonymized_cohort_metrics(state, suggestions=None):
    """Counts only; no source namespaces, host IDs, or executable labels."""
    summary_rows = []
    for summary in state.get("summaries", []):
        groups = [g for g in state.get("groups", [])
                  if g.get("namespace") == summary.get("namespace")]
        by_dimension = {}
        for group in groups:
            by_dimension.setdefault(group["dimension"], []).append(group["size"])
        summary_rows.append({
            "hosts_profiled": summary.get("hosts_profiled", 0),
            "hosts_covered": summary.get("hosts_covered", 0),
            "coverage_percent": summary.get("coverage_percent", 0),
            "cohorts": len(groups),
            "member_assignments": summary.get("member_assignments", 0),
            "size_distribution": sorted(g["size"] for g in groups),
            "dimensions": {key: sorted(vals) for key, vals in sorted(by_dimension.items())},
            "uses_partial_day": summary.get("includes_current_day", False),
            "hosts_known": summary.get("hosts_known"),
            "observed_day_bands": summary.get("observed_day_bands", {}),
            "cohort_quality": [
                {"dimension": group["dimension"],
                 "band": group["band"],
                 "size": group["size"],
                 "independent_support_channels": group.get("independent_support_channels", 0),
                 "similarity": group.get("quality", {})}
                for group in sorted(groups, key=lambda g: (g["dimension"], g["band"]))
            ],
        })
    result = {"algorithm": state.get("algorithm", ALGORITHM),
              "behavioral_similarity": {
                  "algorithm": state.get("similarity_algorithm"),
                  "populations": [
                      {"hosts_profiled": item.get("hosts_profiled", 0),
                       "hosts_eligible": item.get("hosts_eligible", 0),
                       "min_group_size": item.get("min_group_size", 20),
                       "candidate_pairs": item.get("candidate_pairs", 0),
                       "quality_evaluated": item.get("quality_evaluated", 0),
                       "groups": item.get("groups", 0),
                       "supported_groups": item.get("supported_groups", 0),
                       "hosts_covered": item.get("hosts_covered", 0),
                       "member_assignments": item.get("member_assignments", 0),
                       "group_details": [
                           {"size": group["size"], "status": group["status"],
                            "days_median": group["median_observed_days"],
                            "supporting_dimensions": group["supporting_views"],
                            "similarity": {
                                channel: {"within": val["within"],
                                          "fleet": val["fleet"], "delta": val["delta"],
                                          "within_pairs": val["within_pairs"],
                                          "fleet_pairs": val["fleet_pairs"]}
                                for channel, val in group["quality"].items()}}
                           for group in state.get("similarity_groups", [])
                           if group.get("namespace") == item.get("namespace")
                       ]}
                      for item in state.get("similarity_summaries", [])
                  ],
              },
              "quality_method": "sampled-weighted-jaccard-v1",
              "quality_pair_budget_per_cohort": MAX_QUALITY_PAIRS,
              "namespace_statistics": summary_rows}
    if suggestions is not None:
        legacy_sizes = {"recommended": [], "technical": []}
        for group in suggestions.get("groups", []):
            kind = group.get("peer_suitability")
            if kind in legacy_sizes:
                legacy_sizes[kind].append(group.get("size", 0))
        result["legacy_unreviewed_group_sizes"] = {
            kind: sorted(sizes) for kind, sizes in legacy_sizes.items()
        }
    return result
