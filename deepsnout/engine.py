"""Deterministic findings from contextual novelty and behavioral change.

One analysis writer. Observation writes, batch receipts and Splunk checkpoints are
committed together. Baselines use previous days, not the current activity itself.
"""
import ipaddress
import math
import statistics
from sqlalchemy import select, func, delete, update
from .db import (Host, Coverage, Seen, BatchReceipt, Process, BehaviorDay, Window,
                 Finding, Expectation, Job, Audit, LoginSession, policy, now, set_state)
from .normalize import digest, VERSION
from .features import Diversity, service_group
from .peer_groups import peer_group_suppression_allowed

DAY = 86400
WINDOW = 1800
ENGINE_VERSION = "behavior-v1"
SCRIPT_APPS = {"powershell.exe", "pwsh.exe", "mshta.exe", "regsvr32.exe", "cmd.exe",
               "cscript.exe", "wscript.exe", "rundll32.exe"}
USER_LOCATIONS = {"temporary", "downloads", "user-profile", "network-share"}
UNUSUAL_PARENTS = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe",
                   "chrome.exe", "msedge.exe", "firefox.exe"}
EXPECTABLE = {"DS-EXEC-002", "DS-NET-001"}


class CapacityError(RuntimeError):
    pass


def host_key(namespace, host):
    return digest(namespace, host)[:32]


def execution_context(e):
    # A hash/version change alone is not a new behavior.
    return digest(e.app, e.parent, e.location, e.flags)


def reference(db, host, context, app, ts, cfg):
    day = int(ts) // DAY
    since = day - cfg.baseline_days
    observed = db.scalar(select(func.count(func.distinct(Coverage.day))).where(
        Coverage.host_id == host.id, Coverage.event_id == 1,
        Coverage.day >= since, Coverage.day < day)) or 0
    familiar = db.scalar(select(func.count()).select_from(BehaviorDay).where(
        BehaviorDay.host_id == host.id, BehaviorDay.context == context,
        BehaviorDay.day >= since, BehaviorDay.day < day)) or 0
    eligible, seen = 0, 0
    suppressive = False
    if host.cohort != "unassigned":
        qualified = select(BehaviorDay.host_id).where(BehaviorDay.app == app,
            BehaviorDay.day >= since, BehaviorDay.day < day).group_by(BehaviorDay.host_id).having(
            func.count(func.distinct(BehaviorDay.day)) >= cfg.minimum_days)
        shared = [Host.id.in_(qualified), Host.namespace == host.namespace,
                  Host.cohort == host.cohort, Host.id != host.id,
                  BehaviorDay.day >= since, BehaviorDay.day < day, BehaviorDay.app == app]
        eligible = db.scalar(select(func.count(func.distinct(Host.id))).join(
            BehaviorDay, BehaviorDay.host_id == Host.id).where(*shared)) or 0
        seen = db.scalar(select(func.count(func.distinct(Host.id))).join(
            BehaviorDay, BehaviorDay.host_id == Host.id).where(
            *shared, BehaviorDay.context == context)) or 0
        suppressive = peer_group_suppression_allowed(db, host.cohort)
    return {"prior_observed_days": observed, "prior_context_days": familiar,
            "local_new": familiar == 0, "peer_seen": seen, "peer_eligible": eligible,
            "peer_evidence_available": eligible > 0,
            "peer_group_suppression_allowed": suppressive,
            "peer_qualified": suppressive and eligible >= cfg.minimum_peer_hosts,
            "cohort": host.cohort,
            "reference_days": cfg.baseline_days, "reference_before": day * DAY,
            "confidence": "established" if observed >= cfg.minimum_days else "learning"}


def make_finding(db, host, detector, context, ts, title, summary, evidence, priority="review"):
    active_key = digest(host.id, detector, context)
    existing = db.scalar(select(Finding).where(Finding.active_key == active_key))
    if existing:
        existing.last_seen = max(existing.last_seen, ts)
        existing.occurrences += 1
        return existing
    if detector in EXPECTABLE:
        expectation = db.scalar(select(Expectation).where(
            Expectation.host_id == host.id, Expectation.detector == detector,
            Expectation.context == context, Expectation.revoked.is_(False),
            Expectation.created <= now(), Expectation.expires > now()))
        if expectation:
            return None
    evidence = {**evidence, "normalizer": VERSION, "engine": ENGINE_VERSION,
                "interpretation": "Investigation lead, not a verdict of compromise"}
    finding = Finding(active_key=active_key, host_id=host.id, detector=detector,
        context=context, title=title, summary=summary, priority=priority,
        first_seen=ts, last_seen=ts, evidence=evidence)
    db.add(finding)
    db.flush()
    return finding


def execution_findings(db, host, process, cfg, clock):
    if process.created is None or process.created < clock - DAY:
        return
    meta = process.metadata_json
    flags, ref = meta.get("flags", {}), meta.get("reference", {})
    sample = {"process": {"guid": process.guid, "app": process.app,
              "image": meta.get("image", ""), "location": process.location,
              "parent": meta.get("parent", "unknown"), "parent_guid": meta.get("parent_guid", ""),
              "sha256": meta.get("sha256", ""), "event_time": process.created},
              "flags": flags, "reference": ref, "source": meta.get("pointer", {}),
              "limitations": meta.get("warnings", [])}
    if (cfg.execution_enabled and process.app in SCRIPT_APPS
            and flags.get("remote_reference") and flags.get("execution_primitive")):
        make_finding(db, host, "DS-EXEC-001", process.context, process.created,
            "Remote execution characteristics in " + process.app,
            "A scripting-capable process combines a remote reference with an execution primitive. "
            "Review the original command and launch context; automation can also produce this pattern.",
            sample, "high")
    network = process.network
    if (cfg.contextual_enabled and ref.get("confidence") == "established" and ref.get("local_new")
            and network.get("external") and network.get("initiated") is True
            and network.get("event_time", 0) >= process.created
            and (not ref.get("peer_qualified") or ref.get("peer_seen", 0) / max(1, ref.get("peer_eligible", 0)) < cfg.peer_common_fraction)
            and (process.location in USER_LOCATIONS or meta.get("parent") in UNUSUAL_PARENTS
                 or flags.get("encoded_argument"))):
        sample["network"] = network
        make_finding(db, host, "DS-EXEC-002", process.context,
            max(process.created, network.get("event_time", process.created)),
            "New launch context with outbound activity",
            f"{process.app} ran in a context not seen on this endpoint in the prior reference window, "
            "then initiated an external connection attributed to the same ProcessGuid.", sample)


def ingest(db, events, namespace="default", batch_id=None, clock=None, cohort="unassigned"):
    clock = now() if clock is None else clock
    cfg = policy(db)
    report = {"accepted": 0, "duplicates": 0, "outside_retention": 0,
              "future": 0, "context_limit": 0, "missing_guid": 0, "warnings": 0}
    if batch_id and db.get(BatchReceipt, batch_id):
        report["duplicates"], report["batch_replay"] = len(events), True
        return report
    existing_count = db.scalar(select(func.count()).select_from(Seen)) or 0
    if existing_count >= cfg.maximum_receipts:
        db.execute(delete(Seen).where(Seen.received < clock - cfg.dedup_hours * 3600))
        existing_count = db.scalar(select(func.count()).select_from(Seen)) or 0
    # Conservative reservation bounds a batch before any observation is written.
    if existing_count + len(events) > cfg.maximum_receipts:
        raise CapacityError("Event-deduplication capacity reached. Run retention or raise the capacity in Settings. "
                            "The batch/checkpoint was not committed.")
    hosts, processes, coverage, behaviors, windows, sketches = {}, {}, {}, {}, {}, {}
    refs, context_counts = {}, {}
    ids = [digest(namespace, e.id) for e in events]
    known = set()
    for offset in range(0, len(ids), 500):
        known.update(db.scalars(select(Seen.id).where(Seen.id.in_(ids[offset:offset + 500]))))
    for e in sorted(events, key=lambda x: (x.ts, x.event_id != 1)):
        receipt = digest(namespace, e.id)
        if receipt in known:
            report["duplicates"] += 1
            continue
        if e.ts < (int(clock) // DAY - cfg.baseline_days) * DAY:
            report["outside_retention"] += 1
            continue
        if e.ts > clock + 300:
            report["future"] += 1
            continue
        known.add(receipt)
        db.add(Seen(id=receipt, namespace=namespace, received=clock))
        hid = host_key(namespace, e.host)
        if hid not in hosts:
            hosts[hid] = db.get(Host, hid)
            if hosts[hid] is None:
                hosts[hid] = Host(id=hid, name=e.host, namespace=namespace,
                                  first_seen=e.ts, last_seen=e.ts, cohort=cohort)
                db.add(hosts[hid])
                db.flush()
        host = hosts[hid]
        host.first_seen, host.last_seen = min(host.first_seen, e.ts), max(host.last_seen, e.ts)
        day = int(e.ts) // DAY
        ckey = digest(hid, day, e.event_id)
        if ckey not in coverage:
            coverage[ckey] = db.get(Coverage, ckey)
            if coverage[ckey] is None:
                coverage[ckey] = Coverage(id=ckey, host_id=hid, day=day, event_id=e.event_id, count=0)
                db.add(coverage[ckey])
        coverage[ckey].count += 1
        report["accepted"] += 1
        report["warnings"] += len(e.warnings)
        report["missing_guid"] += int(not e.guid)
        proc = None
        if e.guid:
            pkey = digest(hid, e.guid)
            if pkey not in processes:
                processes[pkey] = db.get(Process, pkey)
                if processes[pkey] is None:
                    processes[pkey] = Process(id=pkey, host_id=hid, guid=e.guid, last_seen=e.ts,
                        app=e.app, location=e.location, context="", metadata_json={}, network={})
                    db.add(processes[pkey])
            proc = processes[pkey]
            proc.last_seen = max(proc.last_seen, e.ts)
        if e.event_id == 1:
            ctx = execution_context(e)
            rkey = (hid, ctx, day)
            if rkey not in refs:
                refs[rkey] = reference(db, host, ctx, e.app, e.ts, cfg)
            sample = {"image": e.image, "sha256": e.sha256, "parent": e.parent,
                      "parent_guid": e.parent_guid, "flags": e.flags,
                      "reference": refs[rkey], "pointer": e.pointer, "warnings": e.warnings}
            if proc:
                proc.created, proc.app, proc.location, proc.context = e.ts, e.app, e.location, ctx
                proc.metadata_json = sample
                execution_findings(db, host, proc, cfg, clock)
            else:
                proxy = Process(guid="", created=e.ts, app=e.app, location=e.location,
                                context=ctx, metadata_json=sample, network={})
                execution_findings(db, host, proxy, cfg, clock)
            bkey = digest(hid, day, ctx)
            if bkey not in behaviors:
                behaviors[bkey] = db.get(BehaviorDay, bkey, populate_existing=True)
                if behaviors[bkey] is None:
                    ck = (hid, day)
                    if ck not in context_counts:
                        context_counts[ck] = db.scalar(select(func.count()).select_from(BehaviorDay).where(
                            BehaviorDay.host_id == hid, BehaviorDay.day == day)) or 0
                    if context_counts[ck] >= cfg.maximum_contexts_per_host_day:
                        report["context_limit"] += 1
                        continue
                    context_counts[ck] += 1
                    # Explicit upsert avoids two ORM identities for a daily summary
                    # when a previously deleted demo/context identity is reloaded.
                    if db.bind.dialect.name == "postgresql":
                        from sqlalchemy.dialects.postgresql import insert
                    else:
                        from sqlalchemy.dialects.sqlite import insert
                    statement = insert(BehaviorDay).values(id=bkey, host_id=hid, day=day,
                        context=ctx, app=e.app, parent=e.parent, location=e.location,
                        count=0, first_seen=e.ts, last_seen=e.ts, sample=sample)
                    db.execute(statement.on_conflict_do_nothing(index_elements=[BehaviorDay.id]))
                    behaviors[bkey] = db.get(BehaviorDay, bkey, populate_existing=True)
            b = behaviors[bkey]
            if b is None:
                report["context_limit"] += 1
                continue
            b.count += 1
            b.first_seen, b.last_seen = min(b.first_seen, e.ts), max(b.last_seen, e.ts)
        elif e.event_id in {3, 22}:
            if e.event_id == 3:
                external = ipaddress.ip_address(e.destination).is_global
                if proc and external and e.initiated is True:
                    proc.network = {"external": True, "initiated": True, "destination": e.destination,
                        "port": e.port, "event_time": e.ts, "source": e.pointer,
                        "attribution": "same endpoint and ProcessGuid"}
                    execution_findings(db, host, proc, cfg, clock)
                if not external or e.initiated is not True:
                    continue
                kind, value = "ip", e.destination
            else:
                if "." not in e.query:
                    continue
                kind, value = "domain", service_group(e.query)
            start = int(e.ts) // WINDOW * WINDOW
            wkey = digest(hid, e.app, e.location, kind, start)
            if wkey not in windows:
                windows[wkey] = db.get(Window, wkey)
                if windows[wkey] is None:
                    windows[wkey] = Window(id=wkey, host_id=hid, app=e.app, location=e.location,
                        kind=kind, start=start, count=0, sketch="", samples=[], reference_ok=True, evaluated=False)
                    db.add(windows[wkey])
                sketches[wkey] = Diversity(windows[wkey].sketch)
            w = windows[wkey]
            w.count += 1
            sketches[wkey].add(value)
            exact = e.destination if kind == "ip" else e.query
            if exact not in w.samples and len(w.samples) < 5:
                w.samples = [*w.samples, exact]
            w.evaluated = False
    for key, w in windows.items():
        w.sketch, w.distinct_count = sketches[key].encode(), sketches[key].estimate()
    if batch_id:
        db.add(BatchReceipt(id=batch_id, namespace=namespace, received=clock))
    db.flush()
    set_state(db, "last_ingest", {**report, "at": clock, "namespace": namespace})
    return report


def evaluate_windows(db, clock=None, limit=2000):
    clock = now() if clock is None else clock
    cfg = policy(db)
    db.execute(update(Window).where(Window.start < clock - DAY,
                                   Window.evaluated.is_(False)).values(evaluated=True))
    rows = list(db.scalars(select(Window).where(Window.evaluated.is_(False),
                Window.start + WINDOW <= clock - 300).order_by(Window.start).limit(limit)))
    references, created = {}, 0
    for w in rows:
        w.evaluated = True
        if not cfg.network_enabled:
            continue
        day_start = (w.start // DAY) * DAY
        key = (w.host_id, w.app, w.location, w.kind, day_start)
        if key not in references:
            references[key] = list(db.execute(select(Window.start, Window.distinct_count).where(
                Window.host_id == w.host_id, Window.app == w.app, Window.location == w.location,
                Window.kind == w.kind, Window.start >= day_start - cfg.baseline_days * DAY,
                Window.start < day_start, Window.reference_ok.is_(True))))
        baseline = references[key]
        days = len({r.start // DAY for r in baseline})
        if days < cfg.minimum_days or len(baseline) < 8:
            continue
        values = sorted(r.distinct_count for r in baseline)
        p95 = values[max(0, math.ceil(len(values) * .95) - 1)]
        threshold = max(cfg.network_floor, p95 * cfg.network_factor, p95 + cfg.network_floor / 2)
        if w.distinct_count <= threshold:
            continue
        previous = db.scalar(select(Window).where(Window.host_id == w.host_id,
            Window.app == w.app, Window.location == w.location, Window.kind == w.kind,
            Window.start == w.start - WINDOW))
        if not previous or previous.distinct_count <= threshold:
            continue
        host = db.get(Host, w.host_id)
        evidence = {"app": w.app, "location": w.location, "metric": w.kind,
            "current": w.distinct_count, "previous": previous.distinct_count,
            "window_minutes": WINDOW // 60, "interval_start": previous.start,
            "interval_end": w.start + WINDOW, "baseline_median": statistics.median(values),
            "baseline_p95": p95, "baseline_windows": len(values), "baseline_days_observed": days,
            "reference_before": day_start, "threshold": threshold, "samples": w.samples,
            "limitations": ["Diversity is a HyperLogLog estimate (about 6.5% standard error).",
                "Two adjacent 30-minute windows exceed the local reference; intent is unknown.",
                "No DNS-to-IP causal association is inferred."]}
        finding = make_finding(db, host, "DS-NET-001", digest(w.app, w.location),
            w.start + WINDOW, "Sustained network change in " + w.app,
            "Destination diversity exceeded this application's prior local range in two consecutive active windows.", evidence)
        if finding:
            created += 1
            w.reference_ok = previous.reference_ok = False
    return created


def maintenance(db, clock=None):
    clock = now() if clock is None else clock
    cfg = policy(db)
    day = int(clock) // DAY - cfg.baseline_days
    operations = [
        (Seen, Seen.received < clock - cfg.dedup_hours * 3600),
        (BatchReceipt, BatchReceipt.received < clock - (cfg.baseline_days + 1) * DAY),
        (BehaviorDay, BehaviorDay.day < day), (Coverage, Coverage.day < day),
        (Window, Window.start < day * DAY), (Process, Process.last_seen < clock - cfg.process_days * DAY),
        (Job, (Job.finished > 0) & (Job.finished < clock - 7 * DAY)),
        (LoginSession, LoginSession.expires < clock),
        (Finding, (Finding.closed.is_not(None)) & (Finding.closed < clock - cfg.closed_finding_days * DAY)),
        (Expectation, Expectation.expires < clock - 365 * DAY), (Audit, Audit.created < clock - 365 * DAY)]
    counts = {}
    for model, predicate in operations:
        counts[model.__tablename__] = db.execute(delete(model).where(predicate)).rowcount
    set_state(db, "last_maintenance", {"at": clock, "deleted": counts})
    return counts