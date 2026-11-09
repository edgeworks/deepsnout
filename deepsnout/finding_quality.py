"""Read-only self-diagnosis of finding repetition and filename variant churn.

This analyzes already-created findings, not raw Sysmon events. It learns
filename structure from the observed data, in addition to a stable parent,
location, namespace, detector, context type and execution flags. Nothing
here marks software trusted, changes finding state, or suppresses detections.

Do not interpret a shared filename shape or a fleet-wide wave as benign:
a coordinated intrusion can produce exactly the same observations.
"""
from collections import Counter, defaultdict
import hashlib
import ntpath
import re

from sqlalchemy import select

from .db import Finding, Host, State, now, set_state

METHOD = "finding-family-shadow-v1"
STATE_KEY = "finding_quality_snapshot"
ATTEMPT_KEY = "finding_quality_last_attempt"
WINDOW_DAYS = 7
MAX_SOURCE_FINDINGS = 20000
MAX_VISIBLE_FAMILIES = 30
MIN_FAMILY_FINDINGS = 5
MIN_FAMILY_HOSTS = 2
VERSION_CHURN_MIN_VARIANTS = 2
DOMINANT_FRACTION = 0.35

_DIGITS = re.compile(r"\d+")
_NAME_PARTS = re.compile(r"(\d+)")


def _name_shape(image, app):
    """Observed executable basename plus generic numeric-token shape.

    No vendor names, known updaters, allowlists or IOC definitions. Numeric
    tokens vary only if multiple observed basenames support that inference.
    A short alphabetic anchor cannot form a speculative pattern, so random
    short filenames remain distinct.
    """
    raw = str(image or app or "").replace("/", "\\")
    name = ntpath.basename(raw).strip().lower()[:255]
    if not name or name in ("unknown", "-"):
        return None
    stem, ext = ntpath.splitext(name)
    letters = sum(ch.isalpha() for ch in stem)
    if letters >= 5 and _DIGITS.search(stem):
        shape = _DIGITS.sub("{number}", stem) + ext
    else:
        shape = name
    return name, shape


def _consensus(basenames, shape):
    """Wildcard only those numeric runs demonstrated to vary in the group."""
    if "{number}" not in shape or len(basenames) < 2:
        return sorted(basenames)[0]
    parts = [_NAME_PARTS.split(name) for name in sorted(basenames)]
    if len({len(value) for value in parts}) != 1:
        return shape.replace("{number}", "*")
    output = []
    for index in range(len(parts[0])):
        variants = {part[index] for part in parts}
        output.append("*" if index % 2 == 1 and len(variants) > 1
                      else parts[0][index])
    return "".join(output)


def _candidate(finding, host):
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    process = evidence.get("process")
    if not isinstance(process, dict):
        return None
    parsed = _name_shape(process.get("image"), process.get("app"))
    if parsed is None:
        return None
    basename, shape = parsed
    environment = evidence.get("environment")
    environment = environment if isinstance(environment, dict) else {}
    parent = str(process.get("parent") or "unknown").lower()[:255]
    location = str(process.get("location") or "unknown").lower()[:32]
    category = str(environment.get("category") or "other")[:80]
    flags = evidence.get("flags")
    flags = tuple(sorted(str(k) for k, v in flags.items() if v)) if isinstance(flags, dict) else ()
    key = (str(host.namespace), str(finding.detector), category,
           parent, location, flags, shape)
    return key, basename


def summarize_finding_rows(rows, clock):
    """Deterministic, bounded snapshot. The input must already be time-scoped."""
    by_shape = defaultdict(list)
    source_count, in_scope = 0, 0
    for finding, host in rows:
        source_count += 1
        candidate = _candidate(finding, host)
        if candidate is not None:
            key, basename = candidate
            in_scope += 1
            by_shape[key].append((finding, host, basename))

    families = []
    for key, members in by_shape.items():
        host_count = len({host.id for _, host, _ in members})
        if len(members) < MIN_FAMILY_FINDINGS or host_count < MIN_FAMILY_HOSTS:
            continue
        namespace, detector, category, parent, location, flags, shape = key
        filenames = Counter(name for _, _, name in members)
        representative = _consensus(filenames, shape)
        variant_count = len(filenames)
        version_churn = "{number}" in shape and variant_count >= VERSION_CHURN_MIN_VARIANTS
        fingerprint = hashlib.sha256(
            repr(key).encode("utf-8")).hexdigest()[:24]
        members.sort(key=lambda item: (-item[0].last_seen, item[0].id))
        families.append({
            "id": fingerprint,
            "namespace": namespace,
            "detector": detector,
            "category": category,
            "parent": parent,
            "location": location,
            "flags": list(flags),
            "family_pattern": representative,
            "finding_count": len(members),
            "host_count": host_count,
            "variant_count": variant_count,
            "version_churn": version_churn,
            "variant_examples": [
                {"name": name, "findings": n}
                for name, n in sorted(filenames.items(), key=lambda item: (-item[1], item[0]))[:8]
            ],
            "more_variants": max(0, variant_count - 8),
            "first_event": min(f.first_seen for f, _, _ in members),
            "last_event": max(f.last_seen for f, _, _ in members),
            "high_priority_findings": sum(f.priority == "high" for f, _, _ in members),
            "malicious_findings": sum(f.state == "malicious" for f, _, _ in members),
            # These are already-owned finding IDs, not copies of the telemetry.
            # The maximum source size bounds all stored IDs in the snapshot.
            "member_ids": [f.id for f, _, _ in members],
            "interpretation": (
                "Matching filename structure, parent, location and flags; "
                "a fleet-wide pattern may be legitimate or coordinated malicious activity."
            ),
        })
    families.sort(key=lambda g: (-g["finding_count"], -g["host_count"], g["id"]))
    top = families[:MAX_VISIBLE_FAMILIES]
    for family in top:
        family["share_of_findings"] = round(
            family["finding_count"] / max(1, source_count), 4)
        family["quality_signals"] = [
            * (["filename-version-churn"] if family["version_churn"] else []),
            * (["multi-host-repetition"] if family["host_count"] >= 10 else []),
            * (["dominates-findings-stream"]
               if family["share_of_findings"] >= DOMINANT_FRACTION
               and source_count >= 20 else []),
        ]
    dominant = top[0] if top else None
    shown = sum(f["finding_count"] for f in top)
    snapshot = {
        "method": METHOD,
        "updated_at": clock,
        "window_start": clock - WINDOW_DAYS * 86400,
        "window_end": clock,
        "window_days": WINDOW_DAYS,
        "source_findings": source_count,
        "findings_with_process_evidence": in_scope,
        "families_discovered": len(families),
        "families_displayed": len(top),
        "families_omitted": max(0, len(families) - len(top)),
        "findings_in_displayed_families": shown,
        "findings_not_in_displayed_families": source_count - shown,
        "dominant_family_findings": dominant["finding_count"] if dominant else 0,
        "dominant_family_share": dominant["share_of_findings"] if dominant else 0.0,
        "version_churn_families": sum(g["version_churn"] for g in families),
        "self_diagnosis": (
            "one-family-dominance"
            if dominant and dominant["share_of_findings"] >= DOMINANT_FRACTION
            and source_count >= 20 else "no-dominant-family"
        ),
        "families": top,
        "read_only": True,
        "suppression_allowed": False,
        "changes_detector_policy": False,
        "changes_finding_states": False,
        "known_limitations": (
            "Structure and shared distribution alone do not identify benign activity. "
            "A finding is counted once, even if it summarizes multiple occurrences; "
            "only the original frozen evidence is clustered. No raw events are reprocessed."
        ),
    }
    return snapshot


def refresh_finding_quality(db, clock=None):
    clock = now() if clock is None else clock
    query = (select(Finding, Host)
             .join(Host, Finding.host_id == Host.id)
             .where(Finding.created >= clock - WINDOW_DAYS * 86400,
                    Finding.created <= clock,
                    Host.namespace != "demo")
             .order_by(Finding.last_seen.desc(), Finding.id.asc())
             .limit(MAX_SOURCE_FINDINGS + 1))
    rows = db.execute(query).all()
    if len(rows) > MAX_SOURCE_FINDINGS:
        raise ValueError(
            "Finding-quality scan exceeds 20,000 recent findings. "
            "No partial or misleading concentration snapshot was written.")
    snapshot = summarize_finding_rows(rows, clock)
    set_state(db, STATE_KEY, snapshot)
    return metrics_from_snapshot(snapshot)


def finding_quality_state(db):
    state = db.get(State, STATE_KEY)
    return state.value if state else None


def metrics_from_snapshot(snapshot):
    """Shareable counts only: never include names, group IDs or endpoint IDs."""
    if not snapshot:
        return {
            "method": METHOD, "updated_at": None,
            "read_only": True, "suppression_allowed": False,
            "changes_detector_policy": False,
        }
    fields = (
        "method", "updated_at", "window_days", "source_findings",
        "findings_with_process_evidence", "families_discovered",
        "families_displayed", "families_omitted",
        "findings_in_displayed_families",
        "findings_not_in_displayed_families",
        "dominant_family_findings", "dominant_family_share",
        "version_churn_families", "self_diagnosis", "read_only",
        "suppression_allowed", "changes_detector_policy",
        "changes_finding_states",
    )
    return {name: snapshot.get(name) for name in fields}
