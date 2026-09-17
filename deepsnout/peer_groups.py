"""Explainable peer-group discovery from bounded behavioral summaries.

This module deliberately avoids raw-event storage and opaque trained models. It builds
sparse host profiles from BehaviorDay and Window summaries, downweights fleet-common
features, discovers similarity components, and stores suggestions/approvals in State.

Suggestions are available immediately. When no completed day exists yet, today's
observations may be used for suggestion generation only and the result is marked
provisional. Approved provisional automatic groups may provide peer counts, but the
engine must not use them to suppress a DS-EXEC-002 finding until the group matures.
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
MAX_FEATURES_PER_HOST = 24
SIMILARITY_THRESHOLD = 0.68
MAX_REJECTIONS = 500


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


def _fingerprint(namespace, features):
    material = namespace + "\n" + "\n".join(features[:6])
    return hashlib.sha256(material.encode()).hexdigest()


def _feature_label(feature):
    if feature.startswith("app:"):
        return "application " + feature[4:]
    if feature.startswith("pc:"):
        return "parent-child " + feature[3:]
    if feature.startswith("loc:"):
        _, location, app = feature.split(":", 2)
        return f"{app} from {location}"
    if feature.startswith("net:"):
        _, app, kind = feature.split(":", 2)
        return f"{app} with {kind} network activity"
    return feature


def _namespace_profiles(db, namespace, clock):
    """Return sparse profiles and explainable support data for one namespace."""
    current_day = int(clock) // DAY
    first_day = current_day - (MAX_REFERENCE_DAYS - 1)
    host_rows = db.scalars(select(Host).where(Host.namespace == namespace)).all()
    hosts = {host.id: host for host in host_rows}
    if len(hosts) < 3:
        return {}, {}, {}, False, 0

    behavior = db.scalars(select(BehaviorDay).where(
        BehaviorDay.host_id.in_(hosts), BehaviorDay.day >= first_day,
        BehaviorDay.day <= current_day)).all()
    have_completed_day = any(row.day < current_day for row in behavior)
    allowed_end = current_day - 1 if have_completed_day else current_day
    behavior = [row for row in behavior if row.day <= allowed_end]

    feature_days = defaultdict(lambda: defaultdict(set))
    host_days = defaultdict(set)
    for row in behavior:
        host_days[row.host_id].add(row.day)
        feature_days[row.host_id]["app:" + row.app].add(row.day)
        feature_days[row.host_id]["pc:" + row.parent + ">" + row.app].add(row.day)
        feature_days[row.host_id]["loc:" + row.location + ":" + row.app].add(row.day)

    # Network summaries are useful role signals, but exact destinations are never
    # grouping features. We retain only which application/location has IP/DNS activity.
    start = first_day * DAY
    end = (allowed_end + 1) * DAY
    windows = db.scalars(select(Window).where(
        Window.host_id.in_(hosts), Window.start >= start, Window.start < end)).all()
    for row in windows:
        day = row.start // DAY
        host_days[row.host_id].add(day)
        feature_days[row.host_id][f"net:{row.app}:{row.kind}"].add(day)
        feature_days[row.host_id][f"loc:{row.location}:{row.app}"].add(day)

    raw = {}
    for host_id, days in host_days.items():
        denominator = max(1, len(days))
        raw[host_id] = {feature: len(observed) / denominator
                        for feature, observed in feature_days[host_id].items()}

    n = len(raw)
    if n < 3:
        return {}, raw, hosts, not have_completed_day, max((len(v) for v in host_days.values()), default=0)
    df = defaultdict(int)
    for vector in raw.values():
        for feature in vector:
            df[feature] += 1

    min_df = 2 if n < 20 else 3
    weighted = {}
    for host_id, vector in raw.items():
        values = {}
        for feature, prevalence in vector.items():
            frequency = df[feature]
            if frequency < min_df or frequency / n > 0.95:
                continue
            idf = math.log((n + 1) / (frequency + 1)) + 0.15
            values[feature] = prevalence * idf
        top = dict(sorted(values.items(), key=lambda item: (-item[1], item[0]))[:MAX_FEATURES_PER_HOST])
        norm = math.sqrt(sum(value * value for value in top.values()))
        if norm:
            weighted[host_id] = {key: value / norm for key, value in top.items()}

    return weighted, raw, hosts, not have_completed_day, max((len(v) for v in host_days.values()), default=0)


def _discover_namespace(db, namespace, clock):
    vectors, raw, hosts, includes_current_day, namespace_days = _namespace_profiles(db, namespace, clock)
    n = len(vectors)
    if n < 3:
        return [], {"namespace": namespace, "hosts_profiled": n, "observed_days": namespace_days,
                    "includes_current_day": includes_current_day}

    buckets = defaultdict(list)
    for host_id, vector in vectors.items():
        for feature in vector:
            buckets[feature].append(host_id)

    # Candidate generation is inverted-index based rather than O(n^2). Fleet-wide
    # features never create candidate pairs; they also carry little IDF weight.
    candidate_hits = defaultdict(int)
    maximum_bucket = n if n < 20 else max(12, min(300, int(n * 0.40)))
    for members in buckets.values():
        if not 2 <= len(members) <= maximum_bucket:
            continue
        for left, right in combinations(sorted(members), 2):
            candidate_hits[(left, right)] += 1

    parent = {host_id: host_id for host_id in vectors}
    rank = {host_id: 0 for host_id in vectors}

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

    minimum_shared = 1 if n < 20 else 2
    for (left, right), hits in candidate_hits.items():
        if hits >= minimum_shared and _cosine(vectors[left], vectors[right]) >= SIMILARITY_THRESHOLD:
            union(left, right)

    components = defaultdict(list)
    for host_id in vectors:
        components[find(host_id)].append(host_id)

    fleet_presence = defaultdict(int)
    for vector in raw.values():
        for feature in vector:
            fleet_presence[feature] += 1

    groups = []
    for members in components.values():
        if len(members) < 3 or (n >= 10 and len(members) / n > 0.90):
            continue
        centroid = defaultdict(float)
        for host_id in members:
            for feature, value in vectors[host_id].items():
                centroid[feature] += value / len(members)
        centroid_norm = math.sqrt(sum(value * value for value in centroid.values())) or 1.0
        centroid = {key: value / centroid_norm for key, value in centroid.items()}
        similarities = [_cosine(vectors[host_id], centroid) for host_id in members]
        cohesion = sum(similarities) / len(similarities)
        if cohesion < 0.66:
            continue

        explanations = []
        candidate_features = set().union(*(raw[host_id] for host_id in members))
        for feature in candidate_features:
            group_count = sum(feature in raw[host_id] for host_id in members)
            group_fraction = group_count / len(members)
            fleet_fraction = fleet_presence[feature] / max(1, len(raw))
            if group_fraction < 0.50 or group_fraction <= fleet_fraction:
                continue
            score = (group_fraction - fleet_fraction) * (math.log((len(raw) + 1) / (fleet_presence[feature] + 1)) + 0.15)
            explanations.append((score, feature, group_fraction, fleet_fraction))
        explanations.sort(key=lambda item: (-item[0], item[1]))
        top = explanations[:8]
        if not top:
            continue

        defining = [item[1] for item in top[:6]]
        fingerprint = _fingerprint(namespace, defining)
        member_days = []
        current_day = int(clock) // DAY
        first_day = current_day - (MAX_REFERENCE_DAYS - 1)
        for host_id in members:
            member_days.append(db.scalar(select(func.count(func.distinct(BehaviorDay.day))).where(
                BehaviorDay.host_id == host_id, BehaviorDay.day >= first_day,
                BehaviorDay.day <= current_day)) or 0)
        observed_days = int(statistics.median(member_days)) if member_days else 0
        if includes_current_day or observed_days < 3:
            maturity = "provisional"
        elif observed_days < 7:
            maturity = "growing"
        else:
            maturity = "stable"
        confidence = min(1.0, cohesion * min(1.0, max(1, observed_days) / 7) * min(1.0, len(members) / 15))
        group_id = fingerprint[:12]
        groups.append({
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
            "features": [{"key": feature, "label": _feature_label(feature),
                          "group_fraction": round(group_fraction, 3),
                          "fleet_fraction": round(fleet_fraction, 3),
                          "score": round(score, 3)}
                         for score, feature, group_fraction, fleet_fraction in top],
        })
    groups.sort(key=lambda group: (-group["size"], group["id"]))
    return groups, {"namespace": namespace, "hosts_profiled": n, "observed_days": namespace_days,
                    "includes_current_day": includes_current_day}


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
                # Only automatic membership is mutable. Manual assignments are never
                # overwritten by the discovery process.
                automatic_labels = {name for name, item in registry.items() if item.get("kind") == "auto"}
                for host in db.scalars(select(Host).where(Host.namespace == namespace)).all():
                    if host.id in desired and (host.cohort == "unassigned" or host.cohort in automatic_labels):
                        host.cohort = label
                    elif host.cohort == label and host.id not in desired:
                        host.cohort = "unassigned"
                metadata = {**metadata, **{key: group[key] for key in
                    ("size", "members", "sample_clients", "maturity", "observed_days", "cohesion",
                     "confidence", "includes_current_day", "features")}, "updated_at": clock}
                registry[label] = metadata
            elif group["fingerprint"] not in rejected:
                suggestions.append(group)

    # Approved automatic groups whose defining fingerprint disappeared are kept as
    # they were. We deliberately do not relabel them yet; drift handling is the next
    # focused safety step rather than silently changing group identity.
    set_state(db, "peer_group_registry", {"groups": registry, "updated_at": clock})
    learning = any(item.get("includes_current_day") or item.get("observed_days", 0) < 7 for item in summaries)
    value = {"updated_at": clock, "learning": learning, "summaries": summaries,
             "groups": suggestions, "algorithm": "sparse-behavior-cosine-v1"}
    set_state(db, "peer_group_suggestions", value)
    return {"suggestions": len(suggestions), "approved_auto_matched": len(matched_auto),
            "namespaces": len(summaries), "learning": learning}


def peer_group_catalog(db):
    registry = dict(_state_value(db, "peer_group_registry", {"groups": {}}).get("groups", {}))
    # Preserve legacy/manual cohort labels even if they predate this feature.
    labels = db.scalars(select(Host.cohort).where(Host.cohort != "unassigned").distinct()).all()
    for label in labels:
        registry.setdefault(label, {"label": label, "kind": "manual", "status": "approved",
                                    "maturity": "manual", "created_at": 0})
    return registry


def group_options(db):
    return sorted(peer_group_catalog(db))


def suggestion_state(db):
    return _state_value(db, "peer_group_suggestions",
                        {"updated_at": 0, "learning": True, "summaries": [], "groups": []})


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
                       "created_by": actor, "created_at": now(), "updated_at": now()}
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

    Manual groups are explicit analyst intent. Automatic groups must be approved and
    stable (median >=7 observed days, and not based on today's partial data). Earlier
    groups still expose peer counts but are deliberately non-suppressive.
    """
    if not label or label == "unassigned":
        return False
    item = peer_group_catalog(db).get(label, {})
    if item.get("kind") == "manual":
        return True
    return (item.get("kind") == "auto" and item.get("status") == "approved"
            and item.get("maturity") == "stable" and not item.get("includes_current_day", False))


def group_detail(db, identifier):
    registry = peer_group_catalog(db)
    if identifier in registry:
        item = {**registry[identifier], "label": identifier, "source": "approved"}
        item["members"] = [host.id for host in db.scalars(select(Host).where(Host.cohort == identifier)).all()]
        return item
    return next(({**item, "source": "suggested"} for item in suggestion_state(db).get("groups", [])
                 if item.get("id") == identifier), None)
