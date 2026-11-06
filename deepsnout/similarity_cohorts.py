"""Exploratory multi-view similarity groups (never suppressive).

Seeds are recurring shared application identities, not application counts.
Process and network feature overlap are evaluated separately against the fleet.
This is bounded candidate mining, not complete clustering or asset classification.
"""
from collections import Counter
from itertools import combinations
import hashlib
import math
import statistics

from .analytical_cohorts import assess_cohort_quality

ALGORITHM = "app-bundle-multiview-shadow-v1"
MIN_DAYS = 7
MAX_APPS = 16
MAX_EVALUATED = 80
MAX_GROUPS = 32


def discover_similarity_cohorts(namespace, profiles, partial_day, clock):
    """Generate overlapping shadow groups for established host profiles."""
    eligible = {host: data for host, data in profiles.items()
                if data.get("observed_days", 0) >= MIN_DAYS}
    n = len(eligible)
    minimum = max(20, math.ceil(n * 0.01))
    report = {"namespace": namespace, "hosts_profiled": len(profiles),
              "hosts_eligible": n, "min_group_size": minimum,
              "candidate_pairs": 0, "quality_evaluated": 0,
              "groups": 0, "supported_groups": 0,
              "hosts_covered": 0, "member_assignments": 0}
    if n < 40:
        return [], report

    seen_apps = {}
    df = Counter()
    for host, data in eligible.items():
        apps = {app: fraction
                for app, fraction in data.get("raw", {}).get("applications", {}).items()
                if app.startswith("app:") and fraction >= 0.30}
        seen_apps[host] = apps
        df.update(apps)
    # Ignore fleet-wide agents and very rare products as group *seeds*;
    # retain their observations in other feature comparisons.
    allowed = {app for app, freq in df.items()
               if minimum <= freq <= int(n * 0.80)}
    if len(allowed) < 2:
        return [], report

    by_host = {}
    for host, apps in seen_apps.items():
        ranked = sorted(
            (app for app in apps if app in allowed),
            key=lambda app: (-apps[app] * (1 - df[app] / n), app),
        )[:MAX_APPS]
        by_host[host] = tuple(sorted(ranked))

    counts = Counter()
    for apps in by_host.values():
        counts.update(combinations(apps, 2))
    ranked_pairs = []
    for pair, members in counts.items():
        if not minimum <= members <= n * 0.65:
            continue
        lift = members * n / (df[pair[0]] * df[pair[1]])
        if lift >= 1.25:
            ranked_pairs.append((members * math.log2(lift), members, pair))
    ranked_pairs.sort(key=lambda row: (-row[0], -row[1], row[2]))
    report["candidate_pairs"] = len(ranked_pairs)
    if not ranked_pairs:
        return [], report

    # Materialize memberships only for bounded high-ranking proposals.
    proposed = [pair for _, _, pair in ranked_pairs[:max(256, MAX_EVALUATED * 6)]]
    membership = {pair: [] for pair in proposed}
    for host, apps in by_host.items():
        app_set = set(apps)
        for pair in proposed:
            if pair[0] in app_set and pair[1] in app_set:
                membership[pair].append(host)

    candidates, selected_sets = [], []
    for utility, _, pair in ranked_pairs:
        members = membership.get(pair)
        if members is None or len(members) < minimum:
            continue
        cohort_set = set(members)
        # A software suite can produce numerous duplicate product-pair labels.
        if any(len(cohort_set & other) / len(cohort_set | other) >= 0.85
               for other in selected_sets):
            continue
        days = int(statistics.median(eligible[host]["observed_days"] for host in members))
        digest = hashlib.sha256(
            (namespace + "\0" + pair[0] + "\0" + pair[1]).encode()
        ).hexdigest()[:16]
        candidates.append({
            "id": "bs-" + digest, "namespace": namespace,
            "label": "Similarity cohort " + digest[:8],
            "description": "Shared recurring applications, assessed against process and network behavior.",
            "dimension": "applications",
            "anchors": [app.removeprefix("app:") for app in pair],
            "members": sorted(members), "size": len(members),
            "fraction": round(len(members) / n, 4),
            "median_observed_days": days,
            "maturity": "provisional" if partial_day else "stable",
            "peer_suppression_allowed": False,
            "calculated_at": clock,
            "candidate_utility": round(utility, 2),
        })
        selected_sets.append(cohort_set)
        if len(candidates) >= MAX_EVALUATED:
            break
    report["quality_evaluated"] = len(candidates)

    assess_cohort_quality(eligible, candidates)
    for group in candidates:
        quality = group["quality"]
        app_delta = quality["applications"]["delta"]
        support = [
            channel for channel in ("process", "network")
            if (quality[channel]["within_pairs"] >= 12 and
                quality[channel]["fleet_pairs"] >= 12 and
                quality[channel]["within"] is not None and
                quality[channel]["within"] >= 0.12 and
                quality[channel]["delta"] is not None and
                quality[channel]["delta"] >= 0.08)
        ]
        group["supporting_views"] = support
        group["independent_support_channels"] = len(support)
        group["application_delta"] = app_delta
        group["status"] = ("supported" if support and app_delta is not None
                           and app_delta >= 0.10 else "exploratory")
    candidates.sort(key=lambda g: (
        g["status"] != "supported",
        -(g["application_delta"] if g["application_delta"] is not None else -1),
        -len(g["supporting_views"]), -g["size"], g["id"],
    ))
    groups = candidates[:MAX_GROUPS]
    covered = set().union(*(set(g["members"]) for g in groups)) if groups else set()
    report.update(groups=len(groups),
                  supported_groups=sum(g["status"] == "supported" for g in groups),
                  hosts_covered=len(covered),
                  member_assignments=sum(g["size"] for g in groups))
    return groups, report
