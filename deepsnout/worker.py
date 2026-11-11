"""Durable jobs with a single analysis coordinator and transactional checkpoints."""
import contextlib
import fcntl
import logging
import time
from sqlalchemy import select, func, text, delete
from .db import (transaction, Source, Job, State, Host, Coverage, Process, BehaviorDay,
                 Window, Finding, Expectation, BatchReceipt, Seen, now, set_state, audit)
from .normalize import Event, digest
from .engine import ingest, evaluate_windows, maintenance
from .peer_groups import refresh_peer_groups
from .finding_quality import refresh_finding_quality, ATTEMPT_KEY as QUALITY_ATTEMPT_KEY, STATE_KEY as QUALITY_STATE_KEY
from .splunk import SplunkClient, SplunkSettings, SplunkError
from .security import crypto
from .demo import fixtures

LOG = logging.getLogger("deepsnout.worker")
ACTIVE_JOB_STATUSES = ("queued", "running", "cancel_requested")
POLL_WALL_BUDGET = 900
CATCHUP_BATCH_MAX_SLICES = 4
CATCHUP_BATCH_MAX_EVENTS = 50000
CATCHUP_COLLECTION_BUDGET = 420
LIVE_FINDING_HORIZON = 86400
PROFILE_AUDIT_INTERVAL = 86400
AUTO_PROFILE_MIN_SUPPORTED = 20
AUTO_PROFILE_MIN_FRACTION = 0.90
TARGET_RESULT_FILL = 0.65


def _tuning_key(source_id):
    return "splunk_tuning:" + source_id


def _tail_key(source_id):
    return "splunk_tail:" + source_id


def _next_slice_span(current_span, ceiling, received, maximum, attempts):
    """Learn a useful slice duration without probing an oversized window every poll."""
    current_span = max(1, int(current_span))
    ceiling = max(1, int(ceiling))
    if maximum <= 0:
        return min(current_span, ceiling)
    fill = received / maximum
    if attempts > 1 or fill > 0.75:
        if received <= 0:
            return min(current_span, ceiling)
        target = max(1, int(current_span * TARGET_RESULT_FILL / fill))
        return min(ceiling, max(1, target))
    if fill < 0.45 and current_span < ceiling:
        return min(ceiling, max(current_span + 1, current_span * 2))
    return min(current_span, ceiling)


def _combine_slice_reports(reports):
    if not reports:
        return {}
    combined = dict(reports[-1])
    additive = (
        "received", "invalid", "ignored", "filtered_by_computer",
        "supported_parsed", "cribl_adapter_supported", "tolerated_malformed",
    )
    for key in additive:
        combined[key] = sum(int(report.get(key, 0) or 0) for report in reports)
    combined["slice_attempts"] = sum(int(report.get("slice_attempts", 1) or 1) for report in reports)
    combined["requested_span"] = sum(int(report.get("requested_span", 0) or 0) for report in reports)
    combined["effective_span"] = sum(int(report.get("effective_span", 0) or 0) for report in reports)
    supported = combined.get("supported_parsed", 0)
    cribl = combined.get("cribl_adapter_supported", 0)
    if supported:
        combined["cribl_adapter_fraction"] = round(cribl / supported, 4)
    combined["catchup_sub_slices"] = [
        {
            "index_time_start": report.get("index_time_start"),
            "index_time_end": report.get("index_time_end"),
            "received": report.get("received", 0),
            "slice_attempts": report.get("slice_attempts", 1),
            "effective_span": report.get("effective_span", 0),
        }
        for report in reports
    ]
    return combined


def _cancel_requested(engine, job_id):
    with transaction(engine) as db:
        job = db.get(Job, job_id)
        return bool(job and job.status == "cancel_requested")


def enqueue(db, kind, payload=None, source_id=None):
    count = db.scalar(select(func.count()).select_from(Job).where(Job.status.in_(ACTIVE_JOB_STATUSES))) or 0
    if count >= 20:
        raise ValueError("Queue contains 20 pending jobs. Wait for the worker or inspect Operations")
    if source_id:
        # Live and backfill have independent source cursors and jobs.
        existing = db.scalar(select(Job).where(
            Job.source_id == source_id, Job.kind == kind,
            Job.status.in_(ACTIVE_JOB_STATUSES)))
        if existing:
            return existing
    if kind in {"peer_groups", "finding_quality"}:
        existing = db.scalar(select(Job).where(Job.kind == kind, Job.status.in_(ACTIVE_JOB_STATUSES)))
        if existing:
            return existing
    job = Job(kind=kind, source_id=source_id, payload=payload or {})
    db.add(job)
    db.flush()
    if kind == "peer_groups":
        set_state(db, "peer_group_last_attempt", {"at": now(), "job_id": job.id})
    if kind == "finding_quality":
        set_state(db, QUALITY_ATTEMPT_KEY, {"at": now(), "job_id": job.id})
    return job


@contextlib.contextmanager
def worker_lock(engine, config, role="analysis"):
    """Refuse any overlapping host-shard writers, not just identical roles."""
    fixed = {"analysis": 174220601, "ingest": 174220602, "insight": 174220603}
    if role.startswith("analysis:"):
        shards = tuple(int(v) for v in role.removeprefix("analysis:").split(","))
        if not shards or len(set(shards)) != len(shards) or any(
                not 0 <= v < 4 for v in shards):
            raise ValueError("Invalid analysis shard lock")
        keys = [174220610 + (1 << shard) for shard in sorted(shards)]
    elif role in fixed:
        keys = [fixed[role]]
    else:
        raise ValueError("Unknown worker role")
    if engine.dialect.name == "postgresql":
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
            held = []
            try:
                for key in keys:
                    if not connection.scalar(
                            text("SELECT pg_try_advisory_lock(:key)"), {"key": key}):
                        raise RuntimeError("Another DeepSnout writer owns a selected host shard")
                    held.append(key)
                pid = connection.scalar(text("SELECT pg_backend_pid()"))
                def guard():
                    if connection.scalar(text("SELECT pg_backend_pid()")) != pid:
                        raise RuntimeError("Worker lock connection was replaced; stop before writing")
                yield guard
            finally:
                if not connection.invalidated:
                    for key in reversed(held):
                        connection.execute(
                            text("SELECT pg_advisory_unlock(:key)"), {"key": key})
    else:
        with contextlib.ExitStack() as stack:
            for key in keys:
                path = config.data_dir / ("worker-lock-" + str(key))
                file = stack.enter_context(path.open("w"))
                try:
                    fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise RuntimeError("Another worker owns this host shard") from None
            yield lambda: None



INGEST_COUNTER_FIELDS = (
    "accepted", "duplicates", "outside_retention", "future", "context_limit",
    "missing_guid", "warnings", "historical_process_state_skipped",
    "historical_reference_queries_skipped",
)


def ingest_age_partitioned(db, events, *, namespace, batch_id=None, clock=None,
                           cohort="unassigned", progress=None,
                           counter_state_key="behavioral_discovery_pipeline",
                           last_ingest_state_key="last_ingest",
                           baseline_incomplete=False):
    """Ingest old events via the fast path, then live events, in one transaction.

    The caller owns the session and source checkpoint. Old entries precede
    recent entries in event-time order. Any failure rolls both groups back,
    including the one batch receipt. Only numeric counts leave the worker.
    """
    clock = now() if clock is None else clock
    cutoff = clock - LIVE_FINDING_HORIZON
    old = [event for event in events if event.ts < cutoff]
    live = [event for event in events if event.ts >= cutoff]

    def process(part, historical, receipt=None):
        stage = "ingest-historical" if historical else "ingest-live"

        def report(position, total):
            if progress is not None:
                progress(stage, {"processed": position, "total": total})

        start = time.monotonic()
        result = ingest(
            db, part, namespace=namespace, batch_id=receipt, clock=clock,
            cohort=cohort, historical=historical,
            on_progress=report if progress is not None else None,
            counter_state_key=counter_state_key,
            last_ingest_state_key=last_ingest_state_key,
            baseline_incomplete=baseline_incomplete)
        return result, round(time.monotonic() - start, 3)

    if not old or not live:
        # Preserve the original exactly-once receipt for uniform-age batches.
        is_historical = bool(old)
        result, seconds = process(events, is_historical, batch_id)
        return {
            **result,
            "age_partition": "historical-only" if is_historical else "live-only",
            "historical_input_events": len(old),
            "live_input_events": len(live),
            "historical_ingest_seconds": seconds if is_historical else 0.0,
            "live_ingest_seconds": 0.0 if is_historical else seconds,
        }

    # A receipt represents the WHOLE Splunk slice. Never mark either part
    # committed separately; a replay must not count/process either part.
    if batch_id and db.get(BatchReceipt, batch_id):
        return {
            "accepted": 0, "duplicates": len(events), "batch_replay": True,
            "age_partition": "mixed",
            "historical_input_events": len(old), "live_input_events": len(live),
            "historical_ingest_seconds": 0.0, "live_ingest_seconds": 0.0,
        }

    historic_report, historic_seconds = process(old, True)
    live_report, live_seconds = process(live, False)
    result = {
        key: int(historic_report.get(key, 0)) + int(live_report.get(key, 0))
        for key in INGEST_COUNTER_FIELDS
    }
    pipeline = {}
    for portion in (historic_report, live_report):
        for label, count in portion.get("behavioral_pipeline", {}).items():
            pipeline[label] = pipeline.get(label, 0) + int(count)
    if pipeline:
        result["behavioral_pipeline"] = pipeline
    result.update({
        "age_partition": "mixed",
        "historical_fast_path": "historical-subset-only",
        "historical_input_events": len(old),
        "live_input_events": len(live),
        "historical_ingest_seconds": historic_seconds,
        "live_ingest_seconds": live_seconds,
    })
    if batch_id:
        db.add(BatchReceipt(id=batch_id, namespace=namespace, received=clock))
    # Engine.ingest writes an interim report for each portion. Replace it with
    # the aggregate report in the same transaction before checkpoint commit.
    set_state(db, last_ingest_state_key,
              {**result, "at": clock, "namespace": namespace})
    return result


def run_job(engine, config, job_id, client_factory=SplunkClient, guard=lambda: None,
            defer_analysis=False, heartbeat_key="worker"):
    with transaction(engine) as db:
        job = db.get(Job, job_id)
        if job.status == "cancel_requested":
            job.status, job.finished, job.payload = "cancelled", now(), {}
            audit(db, "worker", "job.cancelled", job.id, "Cancelled before execution")
            return False
        if job.status != "queued":
            raise ValueError("Job is not queued")
        job.status, job.started, job.error = "running", now(), ""
        kind, payload = job.kind, dict(job.payload)
        source = db.get(Source, job.source_id) if job.source_id else None
        tuning_state = db.get(State, _tuning_key(source.id)) if source else None
        tail_state = db.get(State, _tail_key(source.id)) if source else None
        snapshot = ({"id": source.id, "config": source.config, "credential": source.credential,
                     "namespace": source.namespace, "checkpoint": source.checkpoint,
                     "tuning": dict(tuning_state.value) if tuning_state else {},
                     "tail": dict(tail_state.value) if tail_state else {}} if source else None)
        started_at = job.started

    def progress(stage, detail=None):
        if engine.dialect.name == "sqlite":
            return
        with transaction(engine) as heartbeat_db:
            current = heartbeat_db.get(Job, job_id)
            set_state(heartbeat_db, heartbeat_key, {
                "heartbeat": now(), "state": "running", "job_id": job_id,
                "job_kind": kind, "job_started": started_at, "stage": stage,
                "detail": detail or {},
            })
            if current and current.status == "cancel_requested":
                raise SplunkError("Job cancellation requested")

    LOG.info("Job %s started kind=%s source=%s", job_id, kind, snapshot["id"] if snapshot else "-")
    progress("starting")
    try:
        records, result, next_checkpoint = None, {}, None
        poll_tuning = None
        poll_latest = None
        if kind in {"poll", "tail_poll", "test"}:
            if not snapshot:
                raise ValueError("Source no longer exists")
            settings = SplunkSettings.model_validate(snapshot["config"])
            configured_profile = settings.search_profile
            tuning = dict(snapshot.get("tuning") or {})
            profile_audit = False
            if kind in ("poll", "tail_poll") and configured_profile == "auto":
                detected = str(tuning.get("detected_profile", ""))
                last_audit = float(tuning.get("profile_audit_at", 0) or 0)
                if detected == "cribl_flat_sysmon" and now() - last_audit < PROFILE_AUDIT_INTERVAL:
                    settings.search_profile = detected
                else:
                    settings.search_profile = "broad"
                    profile_audit = True
            client = client_factory(settings, crypto(config).decrypt(snapshot["credential"].encode()).decode(),
                                    allow_http=config.allow_http_connectors)
            if hasattr(client, "cancel_check"):
                def poll_check():
                    progress("splunk-" + kind)
                    return _cancel_requested(engine, job_id)
                client.cancel_check = poll_check
            if kind in ("poll", "tail_poll") and hasattr(client, "operation_deadline"):
                client.operation_deadline = time.monotonic() + POLL_WALL_BUDGET
            try:
                if kind == "test":
                    result = client.test()
                else:
                    latest = int(now()) - settings.lag
                    poll_latest = latest
                    tail = snapshot.get("tail") or {}
                    is_tail = kind == "tail_poll"
                    if is_tail:
                        if not tail.get("active"):
                            raise ValueError("Live-tail cursor is no longer active")
                        start = int(tail["checkpoint"])
                        lane_end = latest
                    else:
                        start = (snapshot["checkpoint"] if snapshot["checkpoint"] is not None
                                 else int(tail.get("backfill_start", latest - settings.lookback)))
                        lane_end = min(latest, int(tail["start"])) if tail.get("active") else latest
                    backlog = max(0, latest - start)
                    catching_up = lane_end - start > settings.window * 2
                    ceiling = max(settings.window, settings.catchup_window) if catching_up else settings.window
                    spans = dict(tuning.get("spans") or {})
                    preferred_span = int(spans.get(settings.search_profile, settings.window) or settings.window)
                    preferred_span = max(1, min(ceiling, preferred_span))
                    collection_started = time.monotonic()
                    end = min(lane_end, start + preferred_span)
                    if start >= end:
                        records, next_checkpoint = [], start
                        result = {"received": 0, "slice_attempts": 1, "effective_span": 0,
                                  "requested_span": 0, "search_profile": settings.search_profile}
                        next_span = preferred_span
                    else:
                        records, slice_report, next_checkpoint = client.slice(start, end)
                        reports = [slice_report]
                        last_span = max(1, next_checkpoint - start)
                        next_span = _next_slice_span(
                            last_span, ceiling, int(slice_report.get("received", 0)),
                            settings.max_events, int(slice_report.get("slice_attempts", 1)))
                        multi_slice = catching_up and settings.search_profile == "cribl_flat_sysmon"
                        max_slices = 2 if tail.get("active") and not is_tail else CATCHUP_BATCH_MAX_SLICES
                        while (multi_slice and next_checkpoint < lane_end
                                and len(reports) < max_slices
                                and len(records) < CATCHUP_BATCH_MAX_EVENTS
                                and time.monotonic() - collection_started < CATCHUP_COLLECTION_BUDGET):
                            sub_start = next_checkpoint
                            sub_end = min(lane_end, sub_start + next_span)
                            more, sub_report, next_checkpoint = client.slice(sub_start, sub_end)
                            records.extend(more)
                            reports.append(sub_report)
                            last_span = max(1, next_checkpoint - sub_start)
                            next_span = _next_slice_span(
                                last_span, ceiling, int(sub_report.get("received", 0)),
                                settings.max_events, int(sub_report.get("slice_attempts", 1)))
                        result = _combine_slice_reports(reports)
                    result["collection_seconds"] = round(time.monotonic() - collection_started, 3)
                    actual_span = max(0, next_checkpoint - start)
                    poll_tuning = dict(tuning)
                    learned_spans = dict(poll_tuning.get("spans") or {})
                    learned_spans[settings.search_profile] = next_span
                    poll_tuning.update({
                        "spans": learned_spans,
                        "updated_at": now(),
                    })
                    if configured_profile == "auto" and settings.search_profile == "broad":
                        supported = int(result.get("supported_parsed", 0) or 0)
                        fraction = float(result.get("cribl_adapter_fraction", 0) or 0)
                        if supported >= AUTO_PROFILE_MIN_SUPPORTED:
                            poll_tuning["detected_profile"] = (
                                "cribl_flat_sysmon" if fraction >= AUTO_PROFILE_MIN_FRACTION else "")
                            poll_tuning["profile_audit_at"] = now()
                            result["auto_profile_decision"] = poll_tuning["detected_profile"] or "broad"
                        elif profile_audit:
                            result["auto_profile_decision"] = "insufficient-sample"
                    result["configured_search_profile"] = configured_profile
                    result["effective_search_profile"] = settings.search_profile
                    result["index_time_start"], result["index_time_end"] = start, next_checkpoint
                    result["collection_lane"] = "live" if is_tail else "backfill"
                    result["live_head_index_time"] = latest
                    result["index_seconds_processed"] = actual_span
                    result["backlog_seconds_before"] = backlog
                    result["backlog_seconds_after"] = max(0, latest - next_checkpoint)
                    result["adaptive_next_span"] = next_span
                    payload["batch_id"] = digest("splunk-slice", snapshot["id"], start, next_checkpoint, sorted(e.id for e in records))
            finally:
                client.close()
        elif kind == "import":
            records = [Event(**item) for item in payload.get("events", [])]
            result = payload.get("parse_report", {})
        elif kind == "demo":
            records = fixtures(now())
            payload["namespace"] = "demo"
            payload["batch_id"] = digest("demo", int(now()) // 86400)
        elif kind not in {"maintenance", "remove_demo", "peer_groups", "finding_quality"}:
            raise ValueError("Unknown job kind")
        guard()
        if _cancel_requested(engine, job_id):
            raise SplunkError("Job cancellation requested")
        with transaction(engine) as db:
            job = db.get(Job, job_id)
            if job.status == "cancel_requested":
                raise SplunkError("Job cancellation requested")
            if snapshot:
                source = db.get(Source, snapshot["id"])
                if source.config != snapshot["config"] or source.credential != snapshot["credential"]:
                    raise ValueError("Source configuration changed during job; retry with the new configuration")
            if records is not None:
                ingest_clock = now()
                ingest_started = time.monotonic()
                if defer_analysis:
                    if kind not in ("poll", "tail_poll") or not snapshot or not payload.get("batch_id"):
                        raise ValueError("Only complete Splunk poll slices can use the durable handoff")
                    from .pipeline import stage_observations
                    progress("stage-observations", {"total": len(records)})
                    handoff = stage_observations(
                        db, records, batch_id=payload["batch_id"],
                        source_id=snapshot["id"], namespace=snapshot["namespace"],
                        cohort=snapshot["config"].get("default_cohort", "unassigned"),
                        collected_clock=ingest_clock,
                        lane="live" if kind == "tail_poll" else "backfill")
                    result.update(handoff)
                    result["stage_seconds"] = round(time.monotonic() - ingest_started, 3)
                    result["analysis_deferred"] = True
                else:
                    ingest_report = ingest_age_partitioned(
                        db, records,
                        namespace=snapshot["namespace"] if snapshot else payload.get("namespace", "default"),
                        batch_id=payload.get("batch_id"), clock=ingest_clock,
                        cohort=snapshot["config"].get("default_cohort", "unassigned") if snapshot else "unassigned",
                        progress=progress)
                    result = {**result, **ingest_report}
                    result["ingest_seconds"] = round(time.monotonic() - ingest_started, 3)
                    if not ingest_report["live_input_events"]:
                        result["window_evaluation_deferred"] = True
                        result["evaluate_seconds"] = 0.0
                    else:
                        progress("evaluate-network", {"windows_limit": 2000})
                        evaluate_started = time.monotonic()
                        result["network_findings_created"] = evaluate_windows(db, clock=ingest_clock)
                        result["evaluate_seconds"] = round(time.monotonic() - evaluate_started, 3)
            if kind == "peer_groups":
                result = refresh_peer_groups(db, progress=progress)
            if kind == "finding_quality":
                progress("finding-quality")
                result = refresh_finding_quality(db)
            if kind == "remove_demo":
                ids = select(Host.id).where(Host.namespace == "demo")
                count = db.scalar(select(func.count()).select_from(Host).where(Host.namespace == "demo"))
                for model in [Expectation, Finding, Coverage, Process, BehaviorDay, Window]:
                    # The demo is tiny: use ORM deletes so identity state is also
                    # cleared, rather than leaving loaded instances after bulk SQL.
                    for item in db.scalars(select(model).where(model.host_id.in_(ids))).all():
                        db.delete(item)
                    db.flush()
                db.execute(delete(Host).where(Host.namespace == "demo"))
                db.execute(delete(BatchReceipt).where(BatchReceipt.namespace == "demo"))
                db.execute(delete(Seen).where(Seen.namespace == "demo"))
                result = {"demo_endpoints_removed": count}
            if kind == "maintenance":
                result = {"deleted": maintenance(db)}
            db.refresh(job)
            if job.status == "cancel_requested":
                raise SplunkError("Job cancellation requested")
            if snapshot:
                source.last_success, source.last_error = now(), ""
                if kind == "poll":
                    source.checkpoint = next_checkpoint
                    active_tail = snapshot.get("tail") or {}
                    if active_tail.get("active") and next_checkpoint >= int(active_tail["start"]):
                        # Catch-up covers up to tail_start; tail covers the rest.
                        # This merge is safe only when both staging commits exist.
                        source.checkpoint = max(next_checkpoint, int(active_tail["checkpoint"]))
                        set_state(db, _tail_key(source.id), {
                            **active_tail, "active": False, "merged_at": now(),
                            "checkpoint": source.checkpoint})
                        result["live_tail_merged"] = True
                    if poll_tuning is not None:
                        set_state(db, _tuning_key(source.id), poll_tuning)
                elif kind == "tail_poll":
                    active_tail = snapshot.get("tail") or {}
                    if not active_tail.get("active"):
                        raise ValueError("Live-tail cursor was deactivated")
                    set_state(db, _tail_key(source.id), {
                        **active_tail, "checkpoint": next_checkpoint,
                        "last_success": now(), "last_poll": now()})
            if kind in ("poll", "tail_poll"):
                result["wall_seconds"] = round(now() - started_at, 3)
                processed = float(result.get("index_seconds_processed", 0) or 0)
                result["index_seconds_per_wall_second"] = (
                    round(processed / result["wall_seconds"], 3) if result["wall_seconds"] > 0 else 0)
            kept_payload = {"origin": payload["origin"]} if payload.get("origin") else {}
            job.status, job.finished, job.report, job.payload = "done", now(), result, kept_payload
            audit(db, "worker", "job.completed", job.id, kind)
        LOG.info("Job %s completed kind=%s runtime=%.1fs", job_id, kind, now() - started_at)
    except Exception as exc:
        from .engine import CapacityError
        message = str(exc)[:600] if isinstance(exc, (SplunkError, CapacityError, ValueError)) else type(exc).__name__ + ": inspect worker logs"
        failure_report = exc.report if isinstance(exc, SplunkError) and exc.report else {}
        if isinstance(exc, (SplunkError, CapacityError, ValueError)):
            LOG.error("Job %s failed kind=%s type=%s runtime=%.1fs message=%s",
                      job_id, kind, type(exc).__name__, now() - started_at, message)
        else:
            # Unexpected exceptions need a traceback in container logs. Standard
            # Python tracebacks do not include local variable values, so this
            # improves diagnosis without dumping event payloads or credentials.
            LOG.exception("Job %s failed kind=%s type=%s runtime=%.1fs",
                          job_id, kind, type(exc).__name__, now() - started_at)
        with transaction(engine) as db:
            job = db.get(Job, job_id)
            if job.status == "cancel_requested":
                job.status, job.finished, job.error, job.report, job.payload = "cancelled", now(), "Cancelled by operator", {}, {}
                audit(db, "worker", "job.cancelled", job.id, kind)
                return False
            job.status, job.finished, job.error, job.report = "failed", now(), message, failure_report
            if job.source_id:
                source = db.get(Source, job.source_id)
                if source:
                    source.last_error = message
        return False
    return True


def tick(engine, config, guard=lambda: None):
    with transaction(engine) as db:
        set_state(db, "worker", {"heartbeat": now(), "state": "idle"})
        catching_up_ids = []
        for source in db.scalars(select(Source).where(Source.enabled.is_(True), Source.kind == "splunk")):
            settings = SplunkSettings.model_validate(source.config)
            catching_up = source.checkpoint is not None and source.checkpoint < int(now()) - settings.lag - settings.window
            if catching_up:
                catching_up_ids.append(source.id)
            if (catching_up and not source.last_error) or now() - source.last_poll >= settings.interval:
                if (db.scalar(select(func.count()).select_from(Job).where(Job.status.in_(ACTIVE_JOB_STATUSES))) or 0) >= 20:
                    break
                enqueue(db, "poll", {"origin": "scheduler"}, source_id=source.id)
                source.last_poll = now()
        peer_state = db.get(State, "peer_group_suggestions")
        peer_updated = peer_state.value.get("updated_at", 0) if peer_state else 0
        peer_attempt_state = db.get(State, "peer_group_last_attempt")
        peer_attempted = peer_attempt_state.value.get("at", 0) if peer_attempt_state else 0
        if (not catching_up_ids and db.scalar(select(func.count()).select_from(Host))
                and now() - max(peer_updated, peer_attempted) >= 3600):
            enqueue(db, "peer_groups", {"origin": "scheduler"})
        quality_snapshot = db.get(State, QUALITY_STATE_KEY)
        quality_updated = quality_snapshot.value.get("updated_at", 0) if quality_snapshot else 0
        quality_attempt = db.get(State, QUALITY_ATTEMPT_KEY)
        quality_attempted = quality_attempt.value.get("at", 0) if quality_attempt else 0
        # Delay the hourly diagnostic while source backlog is being processed.
        # Operator-triggered quality refreshes can still be queued explicitly.
        if (not catching_up_ids
                and now() - max(quality_updated, quality_attempted) >= 3600
                and db.scalar(select(func.count()).select_from(Finding))
                and (db.scalar(select(func.count()).select_from(Job)
                     .where(Job.status.in_(ACTIVE_JOB_STATUSES))) or 0) < 20):
            enqueue(db, "finding_quality", {"origin": "scheduler"})
        queued = db.scalars(select(Job).where(Job.status == "queued").order_by(Job.created).limit(50)).all()
        operator_job = next((item for item in queued
                             if isinstance(item.payload, dict) and item.payload.get("origin") == "operator"), None)
        catchup_poll = next((item for item in queued
                             if item.kind == "poll" and item.source_id in catching_up_ids), None)
        job = operator_job or catchup_poll or (queued[0] if queued else None)
        job_id = job.id if job else None
    if job_id:
        run_job(engine, config, job_id, guard=guard)
    else:
        with transaction(engine) as db:
            evaluate_windows(db, limit=200)
    with transaction(engine) as db:
        last = db.get(State, "last_maintenance")
        if not last or now() - last.value.get("at", 0) > 3600:
            maintenance(db)
    return bool(job_id)


def run(engine, config):
    with worker_lock(engine, config) as guard:
        LOG.info("Analysis worker started")
        with transaction(engine) as db:
            for job in db.scalars(select(Job).where(Job.status == "cancel_requested")):
                job.status, job.finished, job.payload = "cancelled", now(), {}
                audit(db, "worker", "job.cancelled", job.id, "Recovered cancellation after worker restart")
                LOG.warning("Recovered pending cancellation for job %s kind=%s", job.id, job.kind)
            for job in db.scalars(select(Job).where(Job.status == "running")):
                message = ("Worker restarted while this job was running. The interrupted job was failed; "
                           "transactional checkpoints were not advanced.")
                job.status, job.finished, job.error = "failed", now(), message
                if job.kind == "peer_groups":
                    set_state(db, "peer_group_last_attempt", {"at": now(), "job_id": job.id,
                                                              "recovered": True})
                if job.kind == "finding_quality":
                    set_state(db, QUALITY_ATTEMPT_KEY, {"at": now(), "job_id": job.id,
                                                        "recovered": True})
                if job.source_id:
                    source = db.get(Source, job.source_id)
                    if source:
                        source.last_error = message
                        source.last_poll = now()
                audit(db, "worker", "job.interrupted", job.id, job.kind)
                LOG.error("Recovered interrupted job %s kind=%s as failed", job.id, job.kind)
        while True:
            guard()
            try:
                busy = tick(engine, config, guard=guard)
            except Exception:
                LOG.exception("Worker tick failed")
                busy = False
            time.sleep(1 if busy else 3)


# v2 role-specific loops. Legacy run_job remains useful for local fixture and
# import tests, but production poll jobs ONLY stage durable normalized batches.
COLLECTION_JOB_KINDS = ("tail_poll", "poll", "test")
DETECTION_JOB_KINDS = ("import", "demo", "remove_demo", "maintenance")
INSIGHT_JOB_KINDS = ("peer_groups", "finding_quality")


def _role_heartbeat(engine, role, stage, detail=None):
    with transaction(engine) as db:
        set_state(db, "worker_" + role, {
            "heartbeat": now(), "state": stage, "detail": detail or {}})


def tick_ingest(engine, config, guard=lambda: None):
    """Live-tail always wins over catch-up, unless storage cannot commit safely."""
    from .pipeline import queue_has_room, queued_metrics, CATCHUP_RESERVE_FRACTION
    with transaction(engine) as db:
        can_poll = queue_has_room(db)
        backlog = queued_metrics(db)
        can_catchup = (can_poll and backlog["stored_bytes"] <
                       backlog["store_budget_bytes"] * CATCHUP_RESERVE_FRACTION)
        collection_state = (
            "storage-backpressure" if not can_poll else
            "live-reserve" if not can_catchup else "idle")
        set_state(db, "worker_ingest", {
            "heartbeat": now(), "state": collection_state,
            "detail": backlog})
        if can_poll:
            for source in db.scalars(select(Source).where(
                    Source.enabled.is_(True), Source.kind == "splunk")):
                settings = SplunkSettings.model_validate(source.config)
                latest = int(now()) - settings.lag
                current = (source.checkpoint if source.checkpoint is not None
                           else latest - settings.lookback)
                state_key = _tail_key(source.id)
                tail_row = db.get(State, state_key)
                tail = dict(tail_row.value) if tail_row else {}
                signature = digest(source.config, source.credential)
                # A changed source configuration must not merge a cursor from
                # a different search. Old source.checkpoint is retained.
                if tail.get("active") and tail.get("source_signature") != signature:
                    tail = {**tail, "active": False, "reset_at": now()}
                    set_state(db, state_key, tail)
                if not tail.get("active") and current < latest - max(
                        settings.window * 2, settings.interval * 2):
                    anchor = max(current, latest - max(
                        settings.window * 2, settings.interval * 2))
                    tail = {
                        "active": True, "start": anchor,
                        "checkpoint": anchor, "last_poll": 0,
                        "source_signature": signature, "started_at": now(),
                        "backfill_start": current,
                    }
                    set_state(db, state_key, tail)
                if tail.get("active") and current >= int(tail["start"]):
                    # The backfill range ends exactly where live began.
                    source.checkpoint = max(current, int(tail["checkpoint"]))
                    tail = {**tail, "active": False,
                            "checkpoint": source.checkpoint, "merged_at": now()}
                    set_state(db, state_key, tail)
                    current = source.checkpoint

                if tail.get("active"):
                    gap = max(0, latest - int(tail["checkpoint"]))
                    if (gap > settings.window or
                            now() - float(tail.get("last_poll", 0)) >= settings.interval):
                        enqueue(db, "tail_poll", {"origin": "scheduler"}, source_id=source.id)
                        tail = {**tail, "last_poll": now()}
                        set_state(db, state_key, tail)
                catchup_limit = int(tail["start"]) if tail.get("active") else latest
                catching_up = current < catchup_limit - settings.window
                if can_catchup and (catching_up and not source.last_error or
                        now() - source.last_poll >= settings.interval):
                    pending = db.scalar(select(func.count()).select_from(Job).where(
                        Job.status.in_(ACTIVE_JOB_STATUSES))) or 0
                    if pending >= 20:
                        break
                    enqueue(db, "poll", {"origin": "scheduler"}, source_id=source.id)
                    source.last_poll = now()
        queued = list(db.scalars(select(Job).where(
            Job.status == "queued", Job.kind.in_(COLLECTION_JOB_KINDS))
            .order_by(Job.created).limit(40)))
        test_job = next((j for j in queued if j.kind == "test"), None)
        tail_job = next((j for j in queued if j.kind == "tail_poll"), None)
        job = test_job or (tail_job if can_poll else None)
        if not job and can_catchup:
            job = next((j for j in queued if j.kind == "poll"), None)
    if not job:
        return False
    return run_job(
        engine, config, job.id, guard=guard,
        defer_analysis=(job.kind in ("poll", "tail_poll")),
        heartbeat_key="worker_ingest")


def tick_analysis(engine, config, guard=lambda: None, shards=None, cache=None):
    """Host-sharded detector lanes; one bounded chunk per loop iteration."""
    from .pipeline import next_pending_batch, process_next_batch, queued_metrics
    shards = tuple(range(4)) if shards is None else tuple(shards)
    role_name = "analysis_" + "_".join(map(str, shards))
    _role_heartbeat(engine, role_name, "idle")
    primary = 0 in shards
    manual_job = None
    if primary:
        with transaction(engine) as db:
            urgent = db.scalar(select(Job).where(
                Job.status == "queued", Job.kind.in_(DETECTION_JOB_KINDS),
                Job.payload["origin"].as_string() == "operator"
            ).order_by(Job.created).limit(1))
            manual_job = urgent.id if urgent else None
    if manual_job:
        return run_job(engine, config, manual_job, guard=guard,
                       heartbeat_key="worker_" + role_name)
    # Retention runs even during ongoing analysis so its receipt ledger and
    # completed observation-store data cannot grow without bound.
    if primary:
        with transaction(engine) as db:
            last = db.get(State, "last_maintenance")
            if not last or now() - last.value.get("at", 0) > 3600:
                maintenance(db)
                from .pipeline import prune_finished_batches
                prune_finished_batches(db)

    with transaction(engine) as db:
        batch = next_pending_batch(db, shards=shards)
        batch_id = batch.id if batch else None
        snapshot = queued_metrics(db) if not batch_id else None
    if batch_id:
        def report(stage, detail=None):
            guard()
            _role_heartbeat(engine, role_name, stage, detail)
        return process_next_batch(
            engine, progress=report, max_chunks=1,
            shards=shards, cache=cache)

    if not primary:
        return False
    with transaction(engine) as db:
        job = db.scalar(select(Job).where(
            Job.status == "queued", Job.kind.in_(DETECTION_JOB_KINDS))
            .order_by(Job.created).limit(1))
        job_id = job.id if job else None
    if job_id:
        return run_job(engine, config, job_id, guard=guard,
                       heartbeat_key="worker_" + role_name)
    # A global sweep is safe only after all staged analysis is caught up.
    if snapshot and snapshot["pending_events"] == 0:
        with transaction(engine) as db:
            evaluate_windows(db, limit=200)
    return False


def tick_insight(engine, config, guard=lambda: None):
    """Run expensive fleet discovery only when spare analytical capacity exists."""
    from .pipeline import queued_metrics
    with transaction(engine) as db:
        pressure = queued_metrics(db)
        busy = (pressure["pending_events"] > 100_000 or
                pressure["stored_bytes"] > pressure["store_budget_bytes"] * .7)
        set_state(db, "worker_insight", {
            "heartbeat": now(), "state": "paused-backlog" if busy else "idle",
            "detail": {"pending_events": pressure["pending_events"],
                       "stored_bytes": pressure["stored_bytes"]}})
        stamp = now()
        if not busy:
            peer_state = db.get(State, "peer_group_suggestions")
            peer_updated = peer_state.value.get("updated_at", 0) if peer_state else 0
            attempt = db.get(State, "peer_group_last_attempt")
            peer_attempted = attempt.value.get("at", 0) if attempt else 0
            if (db.scalar(select(func.count()).select_from(Host)) and
                    stamp - max(peer_updated, peer_attempted) >= 3600):
                enqueue(db, "peer_groups", {"origin": "scheduler"})
            quality_state = db.get(State, QUALITY_STATE_KEY)
            quality_updated = quality_state.value.get("updated_at", 0) if quality_state else 0
            quality_attempt = db.get(State, QUALITY_ATTEMPT_KEY)
            quality_attempted = quality_attempt.value.get("at", 0) if quality_attempt else 0
            if (db.scalar(select(func.count()).select_from(Finding)) and
                    stamp - max(quality_updated, quality_attempted) >= 3600):
                enqueue(db, "finding_quality", {"origin": "scheduler"})
        jobs = list(db.scalars(select(Job).where(
            Job.status == "queued", Job.kind.in_(INSIGHT_JOB_KINDS)
        ).order_by(Job.created).limit(30)))
        operator = next((j for j in jobs if isinstance(j.payload, dict)
                         and j.payload.get("origin") == "operator"), None)
        job = operator or (jobs[0] if jobs and not busy else None)
    if not job:
        return False
    return run_job(engine, config, job.id, guard=guard,
                   heartbeat_key="worker_insight")


def run_role(engine, config, role, shards=None):
    if role not in ("ingest", "analysis", "insight"):
        raise ValueError("Worker role must be ingest, analysis or insight")
    shard_set = tuple(range(4)) if shards is None else tuple(sorted(set(shards)))
    if role == "analysis":
        if not shard_set or any(not 0 <= v < 4 for v in shard_set):
            raise ValueError("Invalid analysis shard selection")
        suffix = "_".join(map(str, shard_set))
        worker_name = "analysis_" + suffix
        lock_name = "analysis:" + ",".join(map(str, shard_set))
    else:
        worker_name, lock_name = role, role
    owns_global_jobs = role != "analysis" or 0 in shard_set
    role_kinds = {
        "ingest": COLLECTION_JOB_KINDS,
        "analysis": DETECTION_JOB_KINDS,
        "insight": INSIGHT_JOB_KINDS,
    }
    cache = {}
    with worker_lock(engine, config, role=lock_name) as guard:
        LOG.info("DeepSnout %s worker started shards=%s", role, shard_set)
        # Only the primary analysis worker recovers operator jobs. Another
        # analysis replica restarting must not fail an active primary job.
        if owns_global_jobs:
            with transaction(engine) as db:
                for job in db.scalars(select(Job).where(
                        Job.kind.in_(role_kinds[role]),
                        Job.status.in_(("running", "cancel_requested")))):
                    job.status, job.finished, job.error = (
                        "failed", now(),
                        "Worker restarted during job; uncommitted writes rolled back.")
                    if job.kind == "peer_groups":
                        set_state(db, "peer_group_last_attempt", {
                            "at": now(), "job_id": job.id, "recovered": True})
                    if job.kind == "finding_quality":
                        set_state(db, QUALITY_ATTEMPT_KEY, {
                            "at": now(), "job_id": job.id, "recovered": True})
                    if role == "ingest" and job.source_id:
                        source = db.get(Source, job.source_id)
                        if source:
                            source.last_error = job.error
                    audit(db, "worker-" + role, "job.interrupted", job.id, job.kind)
        while True:
            guard()
            try:
                if role == "ingest":
                    busy = tick_ingest(engine, config, guard=guard)
                elif role == "insight":
                    busy = tick_insight(engine, config, guard=guard)
                else:
                    busy = tick_analysis(engine, config, guard=guard,
                                         shards=shard_set, cache=cache)
            except Exception:
                LOG.exception("%s worker tick failed", worker_name)
                busy = False
            time.sleep(1 if busy else 3)
