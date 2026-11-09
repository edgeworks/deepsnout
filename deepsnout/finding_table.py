"""Compact, safe presentation of existing finding evidence.

No new telemetry is collected. Parent paths are not retained in the source
model, and network-diversity findings have no process image path. Be explicit
about both limitations instead of fabricating a path.

The privacy-reduced CSV pseudonymizes hosts within each file and collapses
directory paths to coarse location classes. Executable basenames and dates
are still potentially identifying, so analysts must review before sharing.
"""
import csv
from datetime import datetime, timezone
import hashlib
import hmac
import io
import ntpath
import secrets


HEADERS = ("Last seen (UTC)", "Detector", "Hostname", "Parent", "Process (path)", "Trigger")


def _value(value, fallback="—"):
    return str(value) if value not in (None, "") else fallback


def _trigger(detector, evidence, title):
    environment = evidence.get("environment") or {}
    if detector == "DS-BEH-001" and isinstance(environment, dict):
        category = environment.get("category")
        reference = environment.get("reference") or {}
        if category == "rare_application":
            return ("Rare application ("
                    + _value(reference.get("fleet_application_hosts"), "?") + "/"
                    + _value(reference.get("fleet_hosts_with_process_coverage"), "?")
                    + " hosts)")
        if category == "rare_launch_relationship":
            return ("Rare launch ("
                    + _value(reference.get("fleet_launch_relationship_hosts"), "?") + "/"
                    + _value(reference.get("fleet_application_hosts"), "?")
                    + " app hosts)")
        return "Unusual local behavior"
    if detector == "DS-EXEC-001":
        return "Remote execution characteristics"
    if detector == "DS-EXEC-002":
        return "New context + outbound activity"
    if detector == "DS-NET-001":
        current = evidence.get("current")
        p95 = evidence.get("baseline_p95")
        if current is not None and p95 is not None:
            return "Network diversity (" + str(current) + " vs prior p95 " + str(p95) + ")"
        return "Network diversity shift"
    return _value(title)


def _privacy_path(image, location):
    """Retain basename and broad location class, never an original directory."""
    basename = ntpath.basename(str(image).replace("/", "\\"))
    if not basename:
        basename = "unknown"
    # Locations are normalized by the event adapter, not learned from path.
    allowed = {"windows", "program-files", "user-profile", "downloads",
               "temporary", "network-share", "other", "unknown"}
    class_name = location if location in allowed else "unknown"
    return class_name + "\\" + basename


def finding_table_row(finding, host, *, privacy_key=None):
    """Convert one finding into the same six columns for HTML and both CSVs."""
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    process = evidence.get("process")
    process = process if isinstance(process, dict) else {}
    parent = _value(process.get("parent"))
    image = process.get("image")
    app = evidence.get("app") or process.get("app")
    has_image = bool(image)
    full_image = str(image) if has_image else (
        str(app) + " (path unavailable)" if app else "—")
    when = datetime.fromtimestamp(float(finding.last_seen), timezone.utc)
    host_name = host.name
    if privacy_key is not None:
        identity = (host.namespace + "\0" + host.id).encode("utf-8")
        digest = hmac.new(privacy_key, identity, hashlib.sha256).hexdigest()[:10]
        host_name = "host-" + digest
        if has_image:
            full_image = _privacy_path(image, process.get("location"))
        elif app:
            full_image = _privacy_path(app, evidence.get("location"))
        when_text = when.strftime("%Y-%m-%d")
    else:
        when_text = when.strftime("%Y-%m-%d %H:%M:%S")
    return {
        "when": when_text,
        "detector": finding.detector,
        "hostname": host_name,
        "parent": parent,
        "process": full_image,
        "trigger": _trigger(finding.detector, evidence, finding.title),
        "finding_id": finding.id,
    }


def _csv_safe(value):
    """Prevent spreadsheet formula injection from path or hostname fields."""
    text = str(value)
    stripped = text.lstrip("\ufeff \t\r\n")
    if stripped.startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n", "\ufeff")):
        return "'" + text
    return text


def finding_csv(rows, *, privacy_reduced=False):
    """Encode a bounded collection; host aliases are stable within this file.

    A fresh random HMAC key per export prevents a reusable hostname lookup
    across separate exports. The key is neither exported nor persisted.
    """
    key = secrets.token_bytes(32) if privacy_reduced else None
    result = io.StringIO(newline="")
    writer = csv.writer(result, lineterminator="\r\n")
    writer.writerow(HEADERS)
    for finding, host in rows:
        item = finding_table_row(finding, host, privacy_key=key)
        writer.writerow([_csv_safe(item[column]) for column in (
            "when", "detector", "hostname", "parent", "process", "trigger")])
    return "\ufeff" + result.getvalue()
