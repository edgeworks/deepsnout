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
        existing = db.scalar(select(Job).where(Job.source_id == source_id, Job.status.in_(ACTIVE_JOB_STATUSES)))
        if existing:
            return existing
    if kind == "peer_groups":
        existing = db.scalar(select(Job).where(Job.kind == kind, Job.status.in_(ACTIVE_JOB_STATUSES)))
        if existing:
            return existing
    job = Job(kind=kind, source_id=source_id, payload=payload or {})
    db.add(job)
    db.flush()
    if kind == "peer_groups":
        set_state(db, "peer_group_last_attempt", {"at": now(), "job_id": job.id})
    return job


@contextlib.contextmanager
def worker_lock(engine, config):
    if engine.dialect.name == "postgresql":
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
            if not connection.scalar(text("SELECT pg_try_advisory_lock(174220601)")):
                raise RuntimeError("Another DeepSnout analysis worker owns the database lock")
            pid = connection.scalar(text("SELECT pg_backend_pid()"))
            def guard():
                if connection.scalar(text("SELECT pg_backend_pid()")) != pid:
                    raise RuntimeError("Worker lock connection was replaced; stop before writing")
            try:
                yield guard
            finally:
                if not connection.invalidated:
                    connection.execute(text("SELECT pg_advisory_unlock(174220601)"))
    else:
        with (config.data_dir / "worker.lock").open("w") as file:
            try:
                fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("Another local worker is already running") from None
            yield lambda: None


def run_job(engine, config, job_id, client_factory=SplunkClient, guard=lambda: None):
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
        snapshot = ({"id": source.id, "config": source.config, "credential": source.credential,
                     "namespace": source.namespace, "checkpoint": source.checkpoint,
                     "tuning": dict(tuning_state.value) if tuning_state else {}} if source else None)
        started_at = job.started

    def progress(stage, detail=None):
        if engine.dialect.name == "sqlite":
            return
        with transaction(engine) as heartbeat_db:
            current = heartbeat_db.get(Job, job_id)
            set_state(heartbeat_db, "worker", {
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
        if kind in {"poll", "test"}:
            if not snapshot:
                raise ValueError("Source no longer exists")
            settings = SplunkSettings.model_validate(snapshot["config"])
            configured_profile = settings.search_profile
            tuning = dict(snapshot.get("tuning") or {})
            profile_audit = False
            if kind == "poll" and configured_profile == "auto":
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
            if kind == "poll" and hasattr(client, "operation_deadline"):
                client.operation_deadline = time.monotonic() + POLL_WALL_BUDGET
            try:
                if kind == "test":
                    result = client.test()
                else:
                    latest = int(now()) - settings.lag
                    poll_latest = latest
                    start = snapshot["checkpoint"] if snapshot["checkpoint"] is not None else latest - settings.lookback
                    backlog = max(0, latest - start)
                    catching_up = backlog > settings.window * 2
                    ceiling = max(settings.window, settings.catchup_window) if catching_up else settings.window
                    spans = dict(tuning.get("spans") or {})
                    preferred_span = int(spans.get(settings.search_profile, settings.window) or settings.window)
                    preferred_span = max(1, min(ceiling, preferred_span))
                    collection_started = time.monotonic()
                    end = min(latest, start + preferred_span)
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
                        while (multi_slice and next_checkpoint < latest
                                and len(reports) < CATCHUP_BATCH_MAX_SLICES
                                and len(records) < CATCHUP_BATCH_MAX_EVENTS
                                and time.monotonic() - collection_started < CATCHUP_COLLECTION_BUDGET):
                            sub_start = next_checkpoint
                            sub_end = min(latest, sub_start + next_span)
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
        elif kind not in {"maintenance", "remove_demo", "peer_groups"}:
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
                historical_batch = bool(records) and max(event.ts for event in records) < ingest_clock - LIVE_FINDING_HORIZON
                ingest_started = time.monotonic()
                ingest_report = ingest(db, records,
                    namespace=snapshot["namespace"] if snapshot else payload.get("namespace", "default"),
                    batch_id=payload.get("batch_id"), clock=ingest_clock,
                    cohort=snapshot["config"].get("default_cohort", "unassigned") if snapshot else "unassigned",
                    historical=historical_batch)
                result = {**result, **ingest_report}
                result["ingest_seconds"] = round(time.monotonic() - ingest_started, 3)
                if historical_batch:
                    result["window_evaluation_deferred"] = True
                    result["evaluate_seconds"] = 0.0
                else:
                    evaluate_started = time.monotonic()
                    result["network_findings_created"] = evaluate_windows(db, clock=ingest_clock)
                    result["evaluate_seconds"] = round(time.monotonic() - evaluate_started, 3)
            if kind == "peer_groups":
                result = refresh_peer_groups(db, progress=progress)
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
                    if poll_tuning is not None:
                        set_state(db, _tuning_key(source.id), poll_tuning)
            if kind == "poll":
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