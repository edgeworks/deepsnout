"""Explainable environment-relative behavioral novelty discovery.

This detector deliberately has no ATT&CK, network-connection, threat-intel or
suspicious-parent prerequisite. A locally novel behavior is interesting when
the observed fleet also makes it rare. Counts come from *previous* UTC days,
within the same ingestion namespace, never from the triggering event.

Rarity is an observation, not evidence of maliciousness. Readable evidence
reports cohort quality and coverage limitations, rather than a fake probability
of compromise. All lookups are cached per ingestion batch where possible.
"""
import math
from sqlalchemy import select, func

from .db import BehaviorDay, Coverage, Host, State

DAY = 86400
UNKNOWN_APPS = {"", "unknown"}
UNKNOWN_PARENTS = {"", "unknown"}
MAX_COHORT_MEMBERS = 500


def _record(cache, reason):
    """Anonymous count of why an accepted EID 1 did or did not qualify."""
    counters = cache.setdefault("behavioral_counts", {})
    counters[reason] = counters.get(reason, 0) + 1


def _count(db, query):
    return int(db.scalar(query) or 0)


def _host_count(db, namespace, first_day, last_day, cache):
    """Hosts with any Sysmon EID1 coverage in the *prior* reference window."""
    key = (namespace, first_day, last_day)
    active = cache.setdefault("fleet_active", {})
    if key not in active:
        active[key] = _count(db, select(func.count(func.distinct(Coverage.host_id)))
                             .select_from(Coverage).join(Host, Coverage.host_id == Host.id)
                             .where(Host.namespace == namespace, Coverage.event_id == 1,
                                    Coverage.day >= first_day, Coverage.day < last_day))
    return active[key]


def _app_support(db, namespace, app, first_day, last_day, cache):
    key = (namespace, app, first_day, last_day)
    values = cache.setdefault("fleet_app", {})
    if key not in values:
        values[key] = _count(db, select(func.count(func.distinct(BehaviorDay.host_id)))
                             .select_from(BehaviorDay).join(
                                 Host, BehaviorDay.host_id == Host.id)
                             .where(Host.namespace == namespace, BehaviorDay.app == app,
                                    BehaviorDay.day >= first_day,
                                    BehaviorDay.day < last_day))
    return values[key]


def _pattern_support(db, namespace, app, parent, location, first_day, last_day, cache):
    key = (namespace, app, parent, location, first_day, last_day)
    values = cache.setdefault("fleet_pattern", {})
    if key not in values:
        values[key] = _count(db, select(func.count(func.distinct(BehaviorDay.host_id)))
                             .select_from(BehaviorDay).join(
                                 Host, BehaviorDay.host_id == Host.id)
                             .where(Host.namespace == namespace,
                                    BehaviorDay.app == app, BehaviorDay.parent == parent,
                                    BehaviorDay.location == location,
                                    BehaviorDay.day >= first_day,
                                    BehaviorDay.day < last_day))
    return values[key]


def _local_app_days(db, host_id, app, first_day, last_day, cache):
    key = (host_id, app, first_day, last_day)
    values = cache.setdefault("local_app_days", {})
    if key not in values:
        values[key] = _count(db, select(func.count(func.distinct(BehaviorDay.day)))
                             .where(BehaviorDay.host_id == host_id,
                                    BehaviorDay.app == app,
                                    BehaviorDay.day >= first_day,
                                    BehaviorDay.day < last_day))
    return values[key]


def _observational_cohort(db, host, app, parent, location,
                          first_day, last_day, cfg, cache):
    """Optional, non-suppressive comparison with *one* discovered peer pool.

    Group membership and its screening score are learned in-sample and may
    overlap. Only genuinely application-qualified peers enter the denominator.
    No comparison is interpreted as independently validated, and missing
    suitable peers never blocks the fleet-relative detector.
    """
    if "cohort_snapshot" not in cache:
        state = db.get(State, "analytical_cohorts")
        cache["cohort_snapshot"] = state.value if state else {}
    snapshot = cache["cohort_snapshot"]
    candidates = []
    for group in snapshot.get("similarity_groups", []):
        if (group.get("namespace") != host.namespace or
                group.get("status") != "supported" or
                host.id not in group.get("members", ()) or
                not 1 < group.get("size", 0) <= MAX_COHORT_MEMBERS):
            continue
        residual = group.get("residual_quality", {})
        process = residual.get("process", {}).get("delta") or 0.0
        network = residual.get("network", {}).get("delta") or 0.0
        if max(process, network) >= 0.08:
            candidates.append((process, network, group))
    if not candidates:
        return {"available": False, "reason": "no screened cohort for this host"}
    # Process-view relevance takes precedence for execution novelty.
    group = max(candidates, key=lambda item: (item[0], item[1], item[2]["id"]))[2]
    members = sorted(set(group["members"]) - {host.id})
    cache_key = (group["id"], app, first_day, last_day, cfg.minimum_days)
    qualified = cache.setdefault("qualified_cohort_peers", {})
    if cache_key not in qualified:
        query = (select(BehaviorDay.host_id)
                 .where(BehaviorDay.host_id.in_(members),
                        BehaviorDay.app == app,
                        BehaviorDay.day >= first_day, BehaviorDay.day < last_day)
                 .group_by(BehaviorDay.host_id)
                 .having(func.count(func.distinct(BehaviorDay.day)) >= cfg.minimum_days))
        qualified[cache_key] = tuple(db.scalars(query))
    peers = qualified[cache_key]
    pattern_key = (cache_key, parent, location)
    seen = cache.setdefault("cohort_pattern", {})
    if pattern_key not in seen:
        seen[pattern_key] = (
            _count(db, select(func.count(func.distinct(BehaviorDay.host_id))).where(
                BehaviorDay.host_id.in_(peers), BehaviorDay.app == app,
                BehaviorDay.parent == parent, BehaviorDay.location == location,
                BehaviorDay.day >= first_day, BehaviorDay.day < last_day))
            if peers else 0
        )
    return {
        "available": bool(peers),
        "source": "in-sample screened behavioral similarity cohort",
        "group_id": group["id"],
        "candidate_member_hosts": group["size"],
        "application_qualified_peers": len(peers),
        "peers_with_same_parent_and_location": seen[pattern_key],
        "minimum_observed_application_days_per_peer": cfg.minimum_days,
        "use_for_suppression": False,
        "limitations": "Current overlapping cohort membership is not temporally validated for this event.",
    }


def environment_novelty(db, host, app, parent, location, ref, ts, cfg, cache):
    """Return finding rationale or None. Do not require outbound traffic.

    Two independently described discoveries:
      * an application rarely observed on any covered endpoint;
      * an application common across endpoints launched in an uncommon
        parent/image-location pairing.

    A minimum of local and fleet reference observations limits cold-start
    noise. A rare event may still be completely legitimate.
    """
    if not cfg.behavioral_enabled:
        _record(cache, "detector_disabled")
        return None
    if ref.get("confidence") != "established":
        _record(cache, "insufficient_local_history")
        return None
    if not ref.get("local_new"):
        _record(cache, "locally_familiar_context")
        return None
    if app in UNKNOWN_APPS:
        _record(cache, "unknown_application")
        return None
    _record(cache, "locally_new_with_established_history")
    day = int(ts) // DAY
    first = day - cfg.baseline_days
    fleet = _host_count(db, host.namespace, first, day, cache)
    if fleet < cfg.behavioral_min_fleet_hosts:
        _record(cache, "insufficient_fleet_coverage")
        return None
    _record(cache, "fleet_reference_eligible")
    app_hosts = _app_support(db, host.namespace, app, first, day, cache)
    rare_max = max(2, math.floor(fleet * cfg.behavioral_rare_app_fraction))
    common_min = max(cfg.behavioral_min_common_app_hosts,
                     math.ceil(fleet * 0.03))
    rare_app = app_hosts <= rare_max
    pattern_hosts = None
    relation_max = None
    rare_relation = False
    if (not rare_app and app_hosts >= common_min
            and parent not in UNKNOWN_PARENTS and location != "unknown"):
        pattern_hosts = _pattern_support(
            db, host.namespace, app, parent, location, first, day, cache)
        relation_max = max(2, math.floor(app_hosts * cfg.behavioral_rare_relation_fraction))
        rare_relation = pattern_hosts <= relation_max
    if not rare_app and not rare_relation:
        _record(cache, "not_rare_by_fleet_reference")
        return None
    _record(cache, "rare_application_candidates" if rare_app
            else "rare_launch_relationship_candidates")
    category = "rare_application" if rare_app else "rare_launch_relationship"
    reasons = (
        ["New locally and previously seen on very few covered fleet hosts."]
        if rare_app else
        ["New locally and an uncommon parent/application/location relationship "
         "among hosts observed running this application."]
    )
    local_app_days = _local_app_days(db, host.id, app, first, day, cache)
    if rare_app:
        identity = ("application", app)
    else:
        identity = ("launch", app, parent, location)
    return {
        "category": category,
        "identity": identity,
        "reasons": reasons,
        "prior_local_app_days": local_app_days,
        "reference": {
            "fleet_hosts_with_process_coverage": fleet,
            "fleet_application_hosts": app_hosts,
            "fleet_launch_relationship_hosts": pattern_hosts,
            "rare_application_max_hosts": rare_max,
            "rare_relation_max_hosts": relation_max,
            "minimum_common_application_hosts": common_min,
            "reference_days": cfg.baseline_days,
            "reference_before": day * DAY,
            "current_day_excluded": True,
            "observation_definition": (
                "Distinct hosts with any Sysmon process-create coverage on prior UTC days; "
                "coverage is not proof that every execution was logged."
            ),
        },
        "cohort_reference": _observational_cohort(
            db, host, app, parent, location, first, day, cfg, cache
        ),
        "uncertainty": (
            "Rarity is relative to available Sysmon data and current namespace, not "
            "a calibrated probability or a malicious verdict. "
            "Coverage gaps, software rollouts, and host identity churn can affect rarity."
        ),
    }
