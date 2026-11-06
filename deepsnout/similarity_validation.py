"""Conservative shadow quality checks for application-seeded similarity cohorts.

No trusted labels, detector suppression, or organizational role inference.
This module intentionally excludes direct seed-executable contributions from
process/network overlap and compares peers to telemetry-depth matched outsiders.
"""
from collections import Counter, defaultdict
from itertools import combinations
import hashlib

from .analytical_cohorts import _overlap, _sample_pairs


MIN_COMPARISONS = 24
MAX_SAMPLE_PAIRS = 160


def _app_breadth(profile):
    return sum(weight >= 0.30 for weight
               in profile.get("raw", {}).get("applications", {}).values())


def _bucket(profile):
    applications = _app_breadth(profile)
    days = profile.get("observed_days", 0)
    return ((applications + 1).bit_length() - 1, max(0, (days - 7) // 7))


def _outside_index(profiles, members):
    buckets = defaultdict(list)
    for host in sorted(set(profiles) - set(members)):
        buckets[_bucket(profiles[host])].append(host)
    return buckets


def _controls(buckets, profile):
    app_bin, day_bin = _bucket(profile)
    exact = buckets.get((app_bin, day_bin), [])
    if exact:
        return exact
    candidates = []
    # Permit a single adjacent bin, never a distant/unmatched host.
    for coordinate in ((app_bin - 1, day_bin), (app_bin + 1, day_bin),
                       (app_bin, day_bin - 1), (app_bin, day_bin + 1)):
        candidates.extend(buckets.get(coordinate, []))
    return sorted(candidates)


def _nonanchor_features(profile, channel, anchors):
    features = profile.get("channels") or profile.get("raw", {})
    values = features.get(channel, {})
    if channel == "process":
        return {key: weight for key, weight in values.items()
                if not (key.startswith("pc:")
                        and any(part in anchors for part in key[3:].split(">", 1)))}
    if channel == "network":
        return {key: weight for key, weight in values.items()
                if not (key.startswith("net:")
                        and key.split(":", 2)[1] in anchors)}
    return values


def assess_residual_quality(profiles, groups):
    """Assess non-seed evidence using same-host matched-control comparisons.

    For each sampled (A, B) within the group, find an outside host C with
    similar application breadth and observation history. Compare A-B with
    A-C after masking process/network features of the two seed executables.
    This limits obvious circularity; other suite-related features may remain.
    It is NOT a held-out temporal evaluation or a confidence interval.
    """
    for group in groups:
        anchors = set(group["anchors"])
        control_index = _outside_index(profiles, group["members"])
        pairs = _sample_pairs(group["members"], group["id"] + ":residual-v2")
        comparisons = {"process": [], "network": []}
        matched = 0
        for index, (a, b) in enumerate(pairs):
            subject, other = (a, b) if index % 2 == 0 else (b, a)
            candidates = _controls(control_index, profiles[subject])
            if not candidates:
                continue
            selector = hashlib.sha256(
                (group["id"] + ":" + str(index)).encode()).digest()
            control = candidates[int.from_bytes(selector[:4], "big") % len(candidates)]
            matched += 1
            for channel, samples in comparisons.items():
                subject_features = _nonanchor_features(profiles[subject], channel, anchors)
                inside_features = _nonanchor_features(profiles[other], channel, anchors)
                outside_features = _nonanchor_features(profiles[control], channel, anchors)
                within = _overlap(subject_features, inside_features)
                baseline = _overlap(subject_features, outside_features)
                if within is not None and baseline is not None:
                    samples.append((within, baseline))

        evidence, supporting = {}, []
        for channel, values in comparisons.items():
            inside = sum(x for x, _ in values) / len(values) if values else None
            outside = sum(y for _, y in values) / len(values) if values else None
            delta = inside - outside if inside is not None else None
            evidence[channel] = {
                "within": round(inside, 3) if inside is not None else None,
                "matched_control": round(outside, 3) if outside is not None else None,
                "delta": round(delta, 3) if delta is not None else None,
                "comparable_pairs": len(values),
            }
            if (len(values) >= MIN_COMPARISONS and inside is not None
                    and inside >= 0.12 and delta is not None and delta >= 0.08):
                supporting.append(channel)

        group["residual_quality"] = evidence
        group["residual_matched_pairs"] = matched
        group["residual_sampled_pairs"] = len(pairs)
        group["residual_supporting_views"] = supporting


def overlap_stats(groups, covered=None):
    """Only aggregate cardinalities; no user, host, app or group identities."""
    frequency = Counter(host for group in groups for host in group["members"])
    bins = {"1": 0, "2": 0, "3": 0, "4": 0, "5+": 0}
    for memberships in frequency.values():
        bins[str(memberships) if memberships < 5 else "5+"] += 1
    populations = [set(group["members"]) for group in groups]
    overlaps = []
    for first, second in combinations(populations, 2):
        union = len(first | second)
        overlaps.append(len(first & second) / union if union else 0.0)
    covered_count = len(covered) if covered is not None else len(frequency)
    return {
        "hosts_with_multiple_memberships": sum(v > 1 for v in frequency.values()),
        "max_memberships_per_host": max(frequency.values(), default=0),
        "member_multiplicity": bins,
        "group_pairs_over_50pct_jaccard": sum(v >= 0.5 for v in overlaps),
        "group_pairs_over_75pct_jaccard": sum(v >= 0.75 for v in overlaps),
        "max_group_overlap_jaccard": round(max(overlaps, default=0), 3),
        "mean_memberships_per_covered_host": (
            round(sum(frequency.values()) / covered_count, 2)
            if covered_count else 0.0),
    }
