"""Machine-managed overlapping comparison strata (non-suppressive shadow mode).

Cohorts use coarse behavioral breadth from bounded 28-day host profiles.
They are neither approved organizational identities nor trusted benign baselines.
"""
import hashlib
import math
import statistics

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


def analytical_cohort_state(db):
    """Snapshot kept separately from legacy analyst-approved peer groups."""
    from .db import State
    entry = db.get(State, "analytical_cohorts")
    return (entry.value if entry and isinstance(entry.value, dict)
            else {"algorithm": ALGORITHM, "updated_at": 0,
                  "groups": [], "summaries": []})


def anonymized_cohort_metrics(state):
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
        })
    return {"algorithm": state.get("algorithm", ALGORITHM),
            "namespace_statistics": summary_rows}
