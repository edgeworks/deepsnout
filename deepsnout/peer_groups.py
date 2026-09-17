"""Explainable peer-group discovery from bounded behavioral summaries.

Peer grouping is deliberately separate from trust. The discovery layer builds several
bounded views of each endpoint, discovers broad behavioral peer candidates, and also
keeps narrower technical clusters visible for analyst context. Suggestions are
available immediately; today's partial observations may bootstrap suggestions, but
immature automatic groups cannot suppress DS-EXEC-002 findings.

The v2 algorithm avoids treating several consequences of one installed product or OS
image as independent reasons to be peers. A detector-capable automatic group must show
broad application-footprint similarity plus support from another behavioral view.
Platform-only and single-dimension clusters remain visible as technical clusters.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
import math
import re
import statistics
from itertools import combinations

from sqlalchemy import select, func

from .db import State, Host, BehaviorDay, Window, now, set_state

DAY = 86400
MAX_REFERENCE_DAYS = 28
MAX_REJECTIONS = 500
BUNDLE_APPS_PER_HOST = 18
TECHNICAL_FEATURES_PER_HOST = 36

# Peer suitability deliberately gives platform characteristics no vote. They remain
# useful for explaining technical clusters but cannot establish behavioral peers.
PEER_CHANNEL_WEIGHTS = {
    "applications": 0.40,
    "bundles": 0.15,
    "process": 0.20,
    "network": 0.15,
    "activity": 0.10,
}
CHANNEL_LIMITS = {
    "applications": 160,
    "bundles": 96,
    "process": 96,
    "network": 64,
    "activity": 8,
    "platform": 96,
}
PEER_OVERALL_THRESHOLD = 0.50
PEER_APPLICATION_THRESHOLD = 0.42
PEER_SUPPORT_THRESHOLDS = {
    "bundles": 0.28,
    "process": 0.30,
    "network": 0.30,
    "activity": 0.55,
}
TECHNICAL_SIMILARITY_THRESHOLD = 0.72


def _state_value(db, key, default):
    row = db.get(State, key)
    return row.value if row else default


def _slug(value):
    value = str(value).strip().lower()
    if not re.fullmatch(r"[a-z0-9_-]{1,80}", value) or value == "unassigned":
        raise ValueError("Use 1-80 lowercase letters, numbers, - or _; unassigned is reserved")
    return value


def _cosine(a, b):
    if len(a) > len(b):
        a, b = b, a
    return sum(value * b.get(key, 0.0) for key, value in a.items())


def _weighted_jaccard(a, b):
    if not a and not b:
        return 0.0
    keys = set(a) | set(b)
    denominator = sum(max(a.get(key, 0.0), b.get(key, 0.0)) for key in keys)
    if not denominator:
        return 0.0
    return sum(min(a.get(key, 0.0), b.get(key, 0.0)) for key in keys) / denominator


def _fingerprint(namespace, features):
    material = namespace + "\n" + "\n".join(features[:6])
    return hashlib.sha256(material.encode()).hexdigest()


def _activity_key(timestamp):
    hour = int(timestamp // 3600) % 24
    start = (hour // 6) * 6
    return f"activity:{start:02d}-{start + 6:02d}utc"


def _valid_app(value):
    return bool(value and value not in {"unknown", "-"})


def _valid_parent(value):
    return bool(value and value not in {"unknown", "-"})


def _feature_label(channel, feature):
    if feature.startswith("app:"):
        app = feature[4:]
        return ("platform component " if channel == "platform" else "application ") + app
    if feature.startswith("pc:"):
        return ("platform parent-child " if channel == "platform" else "parent-child ") + feature[3:]
    if feature.startswith("net:"):
        _, app, kind = feature.split(":", 2)
        return f"{app} with {kind} network activity"
    if feature.startswith("bundle:"):
        apps = feature[7:].split("|")
        return "application bundle " + " + ".join(apps)
    if feature.startswith("activity:"):
        return feature.replace("activity:", "activity ").replace("utc", " UTC")
    return feature


def _feature_anchor(channel, feature):
    if feature.startswith("app:"):
        return feature[4:]
    if feature.startswith("pc:"):
        return feature[3:].split(">", 1)[-1]
    if feature.startswith("net:"):
        parts = feature.split(":", 2)
        return parts[1] if len(parts) > 1 else ""
    return ""


def _add_feature(store, host_id, channel, feature, day):
    store[host_id][channel][feature].add(day)


def _namespace_profiles(db, namespace, clock):
    """Build multi-channel endpoint profiles for one source namespace."""
    current_day = int(clock) // DAY
    first_day = current_day - (MAX_REFERENCE_DAYS - 1)
    host_rows = db.scalars(select(Host).where(Host.namespace == namespace)).all()
    hosts = {host.id: host for host in host_rows}
    if len(hosts) < 3:
        return {}, {}, hosts, {}, False, 0

    behavior = db.scalars(select(BehaviorDay).where(
        BehaviorDay.host_id.in_(hosts), BehaviorDay.day >= first_day,
        BehaviorDay.day <= current_day)).all()
    have_completed_day = any(row.day < current_day for row in behavior)
    allowed_end = current_day - 1 if have_completed_day else current_day
    behavior = [row for row in behavior if row.day <= allowed_end]

    feature_days = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
    host_days = defaultdict(set)
    for row in behavior:
        host_days[row.host_id].add(row.day)
        app = str(row.app or "").lower()
        parent = str(row.parent or "").lower()
        location = str(row.location or "unknown").lower()
        platform = location == "windows"
        if _valid_app(app):
            channel = "platform" if platform else "applications"
            _add_feature(feature_days, row.host_id, channel, "app:" + app, row.day)
            if _valid_parent(parent):
                edge_channel = "platform" if platform else "process"
                _add_feature(feature_days, row.host_id, edge_channel,
                             "pc:" + parent + ">" + app, row.day)
        # Missing/unknown parents intentionally do not become a relationship feature.
        if row.first_seen:
            _add_feature(feature_days, row.host_id, "activity", _activity_key(row.first_seen), row.day)
        if row.last_seen:
            _add_feature(feature_days, row.host_id, "activity", _activity_key(row.last_seen), row.day)

    start = first_day * DAY
    end = (allowed_end + 1) * DAY
    windows = db.scalars(select(Window).where(
        Window.host_id.in_(hosts), Window.start >= start, Window.start < end)).all()
    for row in windows:
        day = row.start // DAY
        host_days[row.host_id].add(day)
        app = str(row.app or "").lower()
        location = str(row.location or "unknown").lower()
        if _valid_app(app) and location != "windows":
            _add_feature(feature_days, row.host_id, "network", f"net:{app}:{row.kind}", day)
        _add_feature(feature_days, row.host_id, "activity", _activity_key(row.start), day)

    raw = {}
    for host_id, days in host_days.items():
        denominator = max(1, len(days))
        raw[host_id] = {}
        for channel, features in feature_days[host_id].items():
            raw[host_id][channel] = {
                feature: len(observed) / denominator for feature, observed in features.items()
            }

    n = len(raw)
    if n < 3:
        return {}, raw, hosts, {}, not have_completed_day, max((len(v) for v in host_days.values()), default=0)

    # Discover recurring application pairs. These are deliberately derived from a
    # broader application footprint rather than from the highest-IDF individual app.
    pair_hosts = defaultdict(set)
    host_pairs = defaultdict(dict)
    for host_id, channels in raw.items():
        applications = channels.get("applications", {})
        selected = sorted(applications.items(), key=lambda item: (-item[1], item[0]))[:BUNDLE_APPS_PER_HOST]
        selected = [(app[4:] if app.startswith("app:") else app, value) for app, value in selected if value >= 0.20]
        for (left, left_value), (right, right_value) in combinations(selected, 2):
            first, second = sorted((left, right))
            key = f"bundle:{first}|{second}"
            pair_hosts[key].add(host_id)
            host_pairs[host_id][key] = min(left_value, right_value)
    minimum_pair_hosts = 2 if n < 20 else 3
    maximum_pair_fraction = 0.80 if n < 20 else 0.65
    valid_pairs = {key for key, members in pair_hosts.items()
                   if len(members) >= minimum_pair_hosts and len(members) / n <= maximum_pair_fraction}
    for host_id, pairs in host_pairs.items():
        raw[host_id]["bundles"] = {key: value for key, value in pairs.items() if key in valid_pairs}

    fleet_df = defaultdict(lambda: defaultdict(int))
    for channels in raw.values():
        for channel, features in channels.items():
            for feature in features:
                fleet_df[channel][feature] += 1

    profiles = {}
    for host_id, channels in raw.items():
        weighted_channels = {}
        for channel in CHANNEL_LIMITS:
            values = {}
            for feature, prevalence in channels.get(channel, {}).items():
                frequency = fleet_df[channel][feature]
                # Keep common applications in the footprint with low weight so one
                # rare product cannot dominate the set comparison. Rare features are
                # bounded at 2x rather than receiving unbounded IDF influence.
                if channel == "activity":
                    feature_weight = 1.0
                else:
                    idf = max(0.0, math.log((n + 1) / (frequency + 1)))
                    feature_weight = min(2.0, 0.25 + idf)
                values[feature] = prevalence * feature_weight
            limit = CHANNEL_LIMITS[channel]
            weighted_channels[channel] = dict(
                sorted(values.items(), key=lambda item: (-item[1], item[0]))[:limit]
            )

        # A separate distinctive vector preserves narrow technical discoveries such
        # as an image generation, scanner suite or Defender configuration. It is not
        # used directly to qualify detector peer groups.
        technical_values = {}
        minimum_df = 2 if n < 20 else 3
        for channel in ("platform", "applications", "process", "network", "bundles"):
            for feature, prevalence in channels.get(channel, {}).items():
                frequency = fleet_df[channel][feature]
                if frequency < minimum_df or frequency / n > 0.55:
                    continue
                technical_values[f"{channel}:{feature}"] = prevalence * (
                    math.log((n + 1) / (frequency + 1)) + 0.15
                )
        technical_values = dict(sorted(technical_values.items(), key=lambda item: (-item[1], item[0]))
                                [:TECHNICAL_FEATURES_PER_HOST])
        norm = math.sqrt(sum(value * value for value in technical_values.values()))
        technical = ({key: value / norm for key, value in technical_values.items()} if norm else {})
        profiles[host_id] = {
            "channels": weighted_channels,
            "raw": channels,
            "technical": technical,
            "observed_days": len(host_days[host_id]),
        }

    return profiles, raw, hosts, fleet_df, not have_completed_day, max((len(v) for v in host_days.values()), default=0)


def _peer_scores(left, right):
    scores = {}
    for channel in PEER_CHANNEL_WEIGHTS:
        scores[channel] = _weighted_jaccard(
            left["channels"].get(channel, {}), right["channels"].get(channel, {})
        )
    overall = sum(PEER_CHANNEL_WEIGHTS[channel] * scores[channel] for channel in PEER_CHANNEL_WEIGHTS)
    return scores, overall


def _peer_pair_eligible(left, right, n):
    scores, overall = _peer_scores(left, right)
    shared_apps = set(left["channels"].get("applications", {})) & set(right["channels"].get("applications", {}))
    required_apps = 3 if n < 20 else 4
    support = sum(scores[channel] >= threshold for channel, threshold in PEER_SUPPORT_THRESHOLDS.items())
    return (overall >= PEER_OVERALL_THRESHOLD
            and scores["applications"] >= PEER_APPLICATION_THRESHOLD
            and len(shared_apps) >= required_apps
            and support >= 1), scores, overall


def _components(nodes, edges):
    parent = {item: item for item in nodes}
    rank = {item: 0 for item in nodes}

    def find(item):
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    def union(left, right):
        left, right = find(left), find(right)
        if left == right:
            return
        if rank[left] < rank[right]:
            left, right = right, left
        parent[right] = left
        if rank[left] == rank[right]:
            rank[left] += 1

    for left, right in edges:
        union(left, right)
    grouped = defaultdict(list)
    for item in nodes:
        grouped[find(item)].append(item)
    return list(grouped.values())


def _candidate_pairs(profiles, technical=False):
    n = len(profiles)
    buckets = defaultdict(list)
    if technical:
        for host_id, profile in profiles.items():
            for feature in profile["technical"]:
                buckets[feature].append(host_id)
    else:
        for host_id, profile in profiles.items():
            for channel in ("applications", "bundles", "process", "network"):
                for feature in profile["channels"].get(channel, {}):
                    buckets[f"{channel}:{feature}"].append(host_id)

    candidate_hits = defaultdict(int)
    maximum_bucket = n if n < 20 else max(16, min(300, int(n * 0.45)))
    for members in buckets.values():
        if not 2 <= len(members) <= maximum_bucket:
            continue
        for left, right in combinations(sorted(members), 2):
            candidate_hits[(left, right)] += 1
    minimum_shared = 1 if n < 20 else 2
    return [pair for pair, hits in candidate_hits.items() if hits >= minimum_shared]


def _group_channel_scores(members, profiles):
    centroids = {}
    for channel in PEER_CHANNEL_WEIGHTS:
        values = defaultdict(float)
        for host_id in members:
            for feature, value in profiles[host_id]["channels"].get(channel, {}).items():
                values[feature] += value / len(members)
        centroids[channel] = dict(values)
    channel_scores = {}
    for channel in PEER_CHANNEL_WEIGHTS:
        scores = [_weighted_jaccard(profiles[host_id]["channels"].get(channel, {}), centroids[channel])
                  for host_id in members]
        channel_scores[channel] = sum(scores) / len(scores) if scores else 0.0
    overall = sum(PEER_CHANNEL_WEIGHTS[channel] * channel_scores[channel] for channel in PEER_CHANNEL_WEIGHTS)
    return channel_scores, overall


def _technical_cohesion(members, profiles):
    centroid = defaultdict(float)
    for host_id in members:
        for feature, value in profiles[host_id]["technical"].items():
            centroid[feature] += value / len(members)
    norm = math.sqrt(sum(value * value for value in centroid.values())) or 1.0
    centroid = {key: value / norm for key, value in centroid.items()}
    similarities = [_cosine(profiles[host_id]["technical"], centroid) for host_id in members]
    return sum(similarities) / len(similarities) if similarities else 0.0


def _group_app_count(members, raw):
    apps = set().union(*(raw[host_id].get("applications", {}) for host_id in members))
    return sum(sum(app in raw[host_id].get("applications", {}) for host_id in members) / len(members) >= 0.50
               for app in apps)


def _group_peer_ready(members, profiles, raw, n):
    channel_scores, overall = _group_channel_scores(members, profiles)
    required_apps = 3 if n < 20 else 4
    support = sum(channel_scores[channel] >= threshold
                  for channel, threshold in PEER_SUPPORT_THRESHOLDS.items())
    ready = (overall >= PEER_OVERALL_THRESHOLD
             and channel_scores["applications"] >= PEER_APPLICATION_THRESHOLD
             and _group_app_count(members, raw) >= required_apps
             and support >= 1)
    return ready, channel_scores, overall


def _feature_statistics(members, raw, fleet_df, channel, feature, fleet_size):
    group_count = sum(feature in raw[host_id].get(channel, {}) for host_id in members)
    group_fraction = group_count / len(members)
    fleet_fraction = fleet_df[channel].get(feature, 0) / max(1, fleet_size)
    return group_fraction, fleet_fraction


def _group_explanations(members, raw, fleet_df, fleet_size):
    """Return bounded, de-correlated human explanations for a group."""
    candidates = defaultdict(list)
    for channel in ("bundles", "applications", "process", "network", "activity", "platform"):
        features = set().union(*(raw[host_id].get(channel, {}) for host_id in members))
        for feature in features:
            group_fraction, fleet_fraction = _feature_statistics(
                members, raw, fleet_df, channel, feature, fleet_size
            )
            if group_fraction < 0.50 or group_fraction <= fleet_fraction:
                continue
            rarity = math.log((fleet_size + 1) / (fleet_df[channel].get(feature, 0) + 1)) + 0.15
            score = (group_fraction - fleet_fraction) * rarity
            candidates[channel].append((score, feature, group_fraction, fleet_fraction))
        candidates[channel].sort(key=lambda item: (-item[0], item[1]))

    selected = []
    represented_apps = set()

    # Application combinations are first-class v2 explanations.
    for item in candidates["bundles"][:2]:
        selected.append(("bundles", *item, []))

    # Collapse app + parent + network consequences into one application reason where
    # possible, instead of presenting them as several independent signals.
    app_like = [("applications", *item) for item in candidates["applications"]]
    app_like += [("platform", *item) for item in candidates["platform"] if item[1].startswith("app:")]
    app_like.sort(key=lambda item: (-item[1], item[2]))
    for channel, score, feature, group_fraction, fleet_fraction in app_like:
        app = _feature_anchor(channel, feature)
        if not app or app in represented_apps or len(represented_apps) >= 4:
            continue
        details = []
        edge_channel = "platform" if channel == "platform" else "process"
        for edge in candidates[edge_channel]:
            if _feature_anchor(edge_channel, edge[1]) == app:
                parent = edge[1][3:].split(">", 1)[0]
                details.append(f"usually launched by {parent}")
                break
        if channel != "platform":
            network_kinds = []
            for network in candidates["network"]:
                if _feature_anchor("network", network[1]) == app:
                    network_kinds.append(network[1].rsplit(":", 1)[-1])
            if network_kinds:
                details.append("network activity: " + "/".join(sorted(set(network_kinds))))
        selected.append((channel, score, feature, group_fraction, fleet_fraction, details))
        represented_apps.add(app)

    # Remaining process/network reasons are useful only when they add a different
    # application anchor rather than repeating an already displayed product.
    for channel in ("process", "network"):
        for score, feature, group_fraction, fleet_fraction in candidates[channel]:
            anchor = _feature_anchor(channel, feature)
            if anchor in represented_apps:
                continue
            selected.append((channel, score, feature, group_fraction, fleet_fraction, []))
            if anchor:
                represented_apps.add(anchor)
            if sum(item[0] == channel for item in selected) >= 2:
                break

    if candidates["activity"]:
        selected.append(("activity", *candidates["activity"][0], []))

    # Prefer diverse explanation families, but keep the list small enough to review.
    selected = sorted(selected, key=lambda item: (-item[1], item[0], item[2]))[:10]
    return [{
        "channel": channel,
        "key": feature,
        "label": _feature_label(channel, feature),
        "group_fraction": round(group_fraction, 3),
        "fleet_fraction": round(fleet_fraction, 3),
        "score": round(score, 3),
        "details": details,
    } for channel, score, feature, group_fraction, fleet_fraction, details in selected]


def _build_group(namespace, members, profiles, raw, hosts, fleet_df, includes_current_day,
                 clock, suitability, technical_cohesion=None):
    channel_scores, overall = _group_channel_scores(members, profiles)
    explanations = _group_explanations(members, raw, fleet_df, len(raw))
    if not explanations:
        return None
    defining = [item["channel"] + ":" + item["key"] for item in explanations[:6]]
    fingerprint = _fingerprint(namespace, defining)
    observed = [profiles[host_id]["observed_days"] for host_id in members]
    observed_days = int(statistics.median(observed)) if observed else 0
    if includes_current_day or observed_days < 3:
        maturity = "provisional"
    elif observed_days < 7:
        maturity = "growing"
    else:
        maturity = "stable"
    cohesion = overall if suitability == "recommended" else (technical_cohesion or overall)
    confidence = min(1.0, cohesion * min(1.0, max(1, observed_days) / 7) * min(1.0, len(members) / 15))
    dominant_channel = max(channel_scores, key=channel_scores.get) if channel_scores else "applications"
    if suitability == "recommended":
        reason = "Broad application-footprint similarity with support from another behavioral view."
    elif dominant_channel == "applications":
        reason = "Narrow software similarity; broader behavioral agreement is insufficient for detector peers."
    elif dominant_channel == "platform":
        reason = "Platform/image similarity is informative but does not establish a behavioral peer population."
    else:
        reason = "Strong narrow technical similarity, but insufficient multi-view agreement for detector peers."
    group_id = fingerprint[:12]
    return {
        "id": group_id,
        "generated_label": "auto-" + group_id[:8],
        "namespace": namespace,
        "fingerprint": fingerprint,
        "size": len(members),
        "members": sorted(members),
        "sample_clients": sorted(hosts[item].name for item in members)[:8],
        "maturity": maturity,
        "observed_days": observed_days,
        "cohesion": round(cohesion, 3),
        "confidence": round(confidence, 3),
        "includes_current_day": includes_current_day,
        "peer_suitability": suitability,
        "suitability_reason": reason,
        "dominant_channel": dominant_channel,
        "overall_peer_similarity": round(overall, 3),
        "channel_scores": {key: round(value, 3) for key, value in channel_scores.items()},
        "features": explanations,
        "algorithm": "multi-channel-profile-v2",
        "calculated_at": clock,
    }


def _discover_namespace(db, namespace, clock):
    profiles, raw, hosts, fleet_df, includes_current_day, namespace_days = _namespace_profiles(db, namespace, clock)
    n = len(profiles)
    if n < 3:
        return [], {"namespace": namespace, "hosts_profiled": n, "observed_days": namespace_days,
                    "includes_current_day": includes_current_day, "recommended": 0, "technical": 0}

    peer_edges = []
    for left, right in _candidate_pairs(profiles, technical=False):
        eligible, _, _ = _peer_pair_eligible(profiles[left], profiles[right], n)
        if eligible:
            peer_edges.append((left, right))

    groups = []
    recommended_sets = []
    for members in _components(profiles, peer_edges):
        if len(members) < 3 or (n >= 10 and len(members) / n > 0.90):
            continue
        ready, _, _ = _group_peer_ready(members, profiles, raw, n)
        if not ready:
            continue
        group = _build_group(namespace, members, profiles, raw, hosts, fleet_df,
                             includes_current_day, clock, "recommended")
        if group:
            groups.append(group)
            recommended_sets.append(set(members))

    # A second graph intentionally preserves useful narrow technical discoveries.
    # They are shown to the analyst but never become suppressive automatic peers.
    technical_edges = []
    for left, right in _candidate_pairs(profiles, technical=True):
        if _cosine(profiles[left]["technical"], profiles[right]["technical"]) >= TECHNICAL_SIMILARITY_THRESHOLD:
            technical_edges.append((left, right))
    seen_member_sets = {frozenset(group["members"]) for group in groups}
    for members in _components(profiles, technical_edges):
        member_set = set(members)
        if len(members) < 3 or (n >= 10 and len(members) / n > 0.90):
            continue
        if frozenset(members) in seen_member_sets:
            continue
        if any(len(member_set & peer_set) / len(member_set) >= 0.80 for peer_set in recommended_sets):
            continue
        cohesion = _technical_cohesion(members, profiles)
        if cohesion < 0.68:
            continue
        group = _build_group(namespace, members, profiles, raw, hosts, fleet_df,
                             includes_current_day, clock, "technical", cohesion)
        if group:
            groups.append(group)

    groups.sort(key=lambda group: (0 if group["peer_suitability"] == "recommended" else 1,
                                   -group["size"], group["id"]))
    return groups, {
        "namespace": namespace,
        "hosts_profiled": n,
        "observed_days": namespace_days,
        "includes_current_day": includes_current_day,
        "recommended": sum(group["peer_suitability"] == "recommended" for group in groups),
        "technical": sum(group["peer_suitability"] == "technical" for group in groups),
    }


def refresh_peer_groups(db, clock=None):
    """Discover suggestions and refresh membership of matching approved auto groups."""
    clock = now() if clock is None else clock
    registry_state = _state_value(db, "peer_group_registry", {"groups": {}})
    registry = dict(registry_state.get("groups", {}))
    rejected = set(_state_value(db, "peer_group_rejections", {"fingerprints": []}).get("fingerprints", []))
    namespaces = db.scalars(select(Host.namespace).distinct()).all()
    suggestions, summaries = [], []
    matched_auto = set()

    by_fingerprint = {value.get("fingerprint"): (key, value) for key, value in registry.items()
                      if value.get("kind") == "auto" and value.get("status") == "approved" and value.get("fingerprint")}

    for namespace in namespaces:
        groups, summary = _discover_namespace(db, namespace, clock)
        summaries.append(summary)
        for group in groups:
            approved = by_fingerprint.get(group["fingerprint"])
            if approved:
                label, metadata = approved
                matched_auto.add(label)
                desired = set(group["members"])
                automatic_labels = {name for name, item in registry.items() if item.get("kind") == "auto"}
                for host in db.scalars(select(Host).where(Host.namespace == namespace)).all():
                    if host.id in desired and (host.cohort == "unassigned" or host.cohort in automatic_labels):
                        host.cohort = label
                    elif host.cohort == label and host.id not in desired:
                        host.cohort = "unassigned"
                metadata = {**metadata, **{key: group[key] for key in
                    ("size", "members", "sample_clients", "maturity", "observed_days", "cohesion",
                     "confidence", "includes_current_day", "features", "peer_suitability",
                     "suitability_reason", "dominant_channel", "overall_peer_similarity",
                     "channel_scores", "algorithm")}, "updated_at": clock}
                registry[label] = metadata
            elif group["fingerprint"] not in rejected:
                suggestions.append(group)

    # Approved automatic groups whose defining fingerprint disappeared are kept as
    # they were. Drift/prototype lineage remains an explicit follow-up rather than
    # silently redefining an analyst-approved identity.
    set_state(db, "peer_group_registry", {"groups": registry, "updated_at": clock})
    learning = any(item.get("includes_current_day") or item.get("observed_days", 0) < 7 for item in summaries)
    value = {"updated_at": clock, "learning": learning, "summaries": summaries,
             "groups": suggestions, "algorithm": "multi-channel-profile-v2"}
    set_state(db, "peer_group_suggestions", value)
    return {"suggestions": len(suggestions), "approved_auto_matched": len(matched_auto),
            "namespaces": len(summaries), "learning": learning,
            "recommended": sum(group.get("peer_suitability") == "recommended" for group in suggestions),
            "technical": sum(group.get("peer_suitability") == "technical" for group in suggestions)}


def peer_group_catalog(db):
    registry = dict(_state_value(db, "peer_group_registry", {"groups": {}}).get("groups", {}))
    labels = db.scalars(select(Host.cohort).where(Host.cohort != "unassigned").distinct()).all()
    for label in labels:
        registry.setdefault(label, {"label": label, "kind": "manual", "status": "approved",
                                    "maturity": "manual", "created_at": 0})
    return registry


def group_options(db):
    return sorted(peer_group_catalog(db))


def suggestion_state(db):
    return _state_value(db, "peer_group_suggestions",
                        {"updated_at": 0, "learning": True, "summaries": [], "groups": [],
                         "algorithm": "multi-channel-profile-v2"})


def approve_suggestion(db, suggestion_id, label, actor):
    label = _slug(label)
    suggestions = suggestion_state(db)
    group = next((item for item in suggestions.get("groups", []) if item.get("id") == suggestion_id), None)
    if not group:
        raise ValueError("Peer-group suggestion no longer exists; refresh and review the current suggestions")
    registry_state = _state_value(db, "peer_group_registry", {"groups": {}})
    registry = dict(registry_state.get("groups", {}))
    if label in registry and registry[label].get("kind") != "auto":
        raise ValueError("That peer-group label already exists")
    existing_labels = set(db.scalars(select(Host.cohort).where(Host.cohort != "unassigned").distinct()).all())
    if label in existing_labels and label not in registry:
        raise ValueError("That cohort label already exists; choose another name")
    automatic_labels = {name for name, item in registry.items() if item.get("kind") == "auto"}
    desired = set(group["members"])
    for host in db.scalars(select(Host).where(Host.namespace == group["namespace"])).all():
        if host.id in desired and (host.cohort == "unassigned" or host.cohort in automatic_labels):
            host.cohort = label
    registry[label] = {**group, "label": label, "kind": "auto", "status": "approved",
                       "approved_by": actor, "approved_at": now(), "updated_at": now()}
    set_state(db, "peer_group_registry", {"groups": registry, "updated_at": now()})
    suggestions["groups"] = [item for item in suggestions.get("groups", []) if item.get("id") != suggestion_id]
    set_state(db, "peer_group_suggestions", suggestions)
    return label


def reject_suggestion(db, suggestion_id):
    suggestions = suggestion_state(db)
    group = next((item for item in suggestions.get("groups", []) if item.get("id") == suggestion_id), None)
    if not group:
        raise ValueError("Peer-group suggestion no longer exists")
    state = _state_value(db, "peer_group_rejections", {"fingerprints": []})
    fingerprints = list(dict.fromkeys([*state.get("fingerprints", []), group["fingerprint"]]))[-MAX_REJECTIONS:]
    set_state(db, "peer_group_rejections", {"fingerprints": fingerprints, "updated_at": now()})
    suggestions["groups"] = [item for item in suggestions.get("groups", []) if item.get("id") != suggestion_id]
    set_state(db, "peer_group_suggestions", suggestions)


def create_manual_group(db, label, actor):
    label = _slug(label)
    registry_state = _state_value(db, "peer_group_registry", {"groups": {}})
    registry = dict(registry_state.get("groups", {}))
    if label in registry:
        raise ValueError("That peer-group label already exists")
    registry[label] = {"label": label, "kind": "manual", "status": "approved", "maturity": "manual",
                       "peer_suitability": "manual", "created_by": actor, "created_at": now(), "updated_at": now()}
    set_state(db, "peer_group_registry", {"groups": registry, "updated_at": now()})
    return label


def assign_host_group(db, host, label):
    label = str(label).strip().lower()
    if label == "unassigned":
        host.cohort = label
        return
    label = _slug(label)
    if label not in peer_group_catalog(db):
        raise ValueError("Select an existing peer group or create it on the Peer Groups page")
    host.cohort = label


def peer_group_suppression_allowed(db, label):
    """Whether peer-common behavior may suppress DS-EXEC-002 novelty.

    Manual groups are explicit analyst intent. Automatic groups must be approved,
    broad/multi-channel peer recommendations, stable, and based on completed days.
    Technical clusters and legacy auto groups without a v2 suitability assessment are
    deliberately non-suppressive.
    """
    if not label or label == "unassigned":
        return False
    item = peer_group_catalog(db).get(label, {})
    if item.get("kind") == "manual":
        return True
    return (item.get("kind") == "auto" and item.get("status") == "approved"
            and item.get("peer_suitability") == "recommended"
            and item.get("maturity") == "stable" and not item.get("includes_current_day", False))


def group_detail(db, identifier):
    registry = peer_group_catalog(db)
    if identifier in registry:
        item = {**registry[identifier], "label": identifier, "source": "approved"}
        item["members"] = [host.id for host in db.scalars(select(Host).where(Host.cohort == identifier)).all()]
        return item
    return next(({**item, "source": "suggested"} for item in suggestion_state(db).get("groups", [])
                 if item.get("id") == identifier), None)
