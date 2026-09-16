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
from .splunk import SplunkClient, SplunkSettings
from .security import crypto
from .demo import fixtures

LOG = logging.getLogger("deepsnout.worker")


def enqueue(db, kind, payload=None, source_id=None):
    count = db.scalar(select(func.count()).select_from(Job).where(Job.status.in_(["queued", "running"]))) or 0
    if count >= 20:
        raise ValueError("Queue contains 20 pending jobs. Wait for the worker or inspect Operations")
    if source_id:
        existing = db.scalar(select(Job).where(Job.source_id == source_id, Job.status.in_(["queued", "running"])))
        if existing:
            return existing
    job = Job(kind=kind, source_id=source_id, payload=payload or {})
    db.add(job)
    db.flush()
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
        job.status, job.started = "running", now()
        kind, payload = job.kind, dict(job.payload)
        source = db.get(Source, job.source_id) if job.source_id else None
        snapshot = ({"id": source.id, "config": source.config, "credential": source.credential,
                     "namespace": source.namespace, "checkpoint": source.checkpoint} if source else None)
    try:
        records, result, next_checkpoint = None, {}, None
        if kind in {"poll", "test"}:
            if not snapshot:
                raise ValueError("Source no longer exists")
            settings = SplunkSettings.model_validate(snapshot["config"])
            client = client_factory(settings, crypto(config).decrypt(snapshot["credential"].encode()).decode(),
                                    allow_http=config.allow_http_connectors)
            try:
                if kind == "test":
                    result = client.test()
                else:
                    latest = int(now()) - settings.lag
                    start = snapshot["checkpoint"] if snapshot["checkpoint"] is not None else latest - settings.lookback
                    end = min(latest, start + settings.window)
                    if start >= end:
                        records, next_checkpoint = [], start
                    else:
                        records, result, next_checkpoint = client.slice(start, end)
                    result["index_time_start"], result["index_time_end"] = start, next_checkpoint
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
        elif kind not in {"maintenance", "remove_demo"}:
            raise ValueError("Unknown job kind")
        guard()
        with transaction(engine) as db:
            job = db.get(Job, job_id)
            if snapshot:
                source = db.get(Source, snapshot["id"])
                if source.config != snapshot["config"] or source.credential != snapshot["credential"]:
                    raise ValueError("Source configuration changed during job; retry with the new configuration")
            if records is not None:
                result = {**result, **ingest(db, records,
                    namespace=snapshot["namespace"] if snapshot else payload.get("namespace", "default"),
                    batch_id=payload.get("batch_id"),
                    cohort=snapshot["config"].get("default_cohort", "unassigned") if snapshot else "unassigned")}
                evaluate_windows(db)
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
            if snapshot:
                source.last_success, source.last_error = now(), ""
                if kind == "poll":
                    source.checkpoint = next_checkpoint
            job.status, job.finished, job.report, job.payload = "done", now(), result, {}
            audit(db, "worker", "job.completed", job.id, kind)
    except Exception as exc:
        from .splunk import SplunkError
        from .engine import CapacityError
        message = str(exc)[:600] if isinstance(exc, (SplunkError, CapacityError, ValueError)) else type(exc).__name__ + ": inspect worker logs"
        failure_report = exc.report if isinstance(exc, SplunkError) and exc.report else {}
        LOG.error("Job %s failed (%s)", job_id, type(exc).__name__)
        with transaction(engine) as db:
            job = db.get(Job, job_id)
            job.status, job.finished, job.error, job.report = "failed", now(), message, failure_report
            if job.source_id:
                source = db.get(Source, job.source_id)
                if source:
                    source.last_error = message
        return False
    return True


def tick(engine, config, guard=lambda: None):
    with transaction(engine) as db:
        set_state(db, "worker", {"heartbeat": now(), "state": "running"})
        for source in db.scalars(select(Source).where(Source.enabled.is_(True), Source.kind == "splunk")):
            settings = SplunkSettings.model_validate(source.config)
            catching_up = source.checkpoint is not None and source.checkpoint < int(now()) - settings.lag - settings.window
            if (catching_up and not source.last_error) or now() - source.last_poll >= settings.interval:
                if (db.scalar(select(func.count()).select_from(Job).where(Job.status.in_(["queued", "running"]))) or 0) >= 20:
                    break
                enqueue(db, "poll", source_id=source.id)
                source.last_poll = now()
        job = db.scalar(select(Job).where(Job.status == "queued").order_by(Job.created).limit(1))
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
        with transaction(engine) as db:
            for job in db.scalars(select(Job).where(Job.status == "running")):
                job.status = "queued"
        while True:
            guard()
            try:
                busy = tick(engine, config, guard=guard)
            except Exception:
                LOG.exception("Worker tick failed")
                busy = False
            time.sleep(1 if busy else 3)