"""Synthetic integration tests for the local collection/analysis boundary.

These tests use disposable SQLite or PostgreSQL databases ONLY. They do not
connect to Splunk or read any organization data.
"""
import pytest
from sqlalchemy import select, func

from conftest import CLOCK, DAY, evt, count
from deepsnout.db import (
    transaction, Base, State, StagedBatch, Seen, Host, Process,
    BatchReceipt, Source, Finding, initialize, migrate_v2, migrate_v3, now,
)
from deepsnout.pipeline import (
    stage_observations, process_next_batch, queued_metrics, queue_has_room,
    next_pending_batch, retry_failed_batch, prune_finished_batches,
    BackpressureError,
)
from deepsnout.worker import (
    enqueue, run_job, tick_ingest, tick_analysis, worker_lock,
)
from deepsnout.security import crypto
from deepsnout.splunk import SplunkSettings


def _stage(db, records, *, token="first", clock=CLOCK, namespace="synthetic"):
    return stage_observations(
        db, records, batch_id=token, source_id="synthetic-source",
        namespace=namespace, cohort="unassigned", collected_clock=clock)


def test_schema_version_three_on_fresh_database(db):
    assert db.get(State, "schema_version").value == 3
    assert count(db, StagedBatch) == 0


def test_explicit_v1_migration_is_safe_and_preserves_existing_data(engine):
    with transaction(engine) as db:
        db.get(State, "schema_version").value = 1
        db.add(Host(id="survives-v2", name="synthetic.example",
                    namespace="test", cohort="unassigned",
                    first_seen=CLOCK, last_seen=CLOCK))
    StagedBatch.__table__.drop(engine)
    with pytest.raises(RuntimeError, match="migrate-v2"):
        initialize(engine)
    assert migrate_v2(engine) == "Migrated schema v1 to v2"
    with pytest.raises(RuntimeError, match="migrate-v3"):
        initialize(engine)
    assert migrate_v3(engine) == "Migrated schema v2 to v3"
    initialize(engine)
    assert migrate_v3(engine) == "Schema is already v3"
    with transaction(engine) as db:
        assert db.get(State, "schema_version").value == 3
        assert db.get(Host, "survives-v2") is not None
        assert count(db, StagedBatch) == 0


def test_migration_recovers_only_explicitly_interrupted_jobs(engine):
    from deepsnout.db import Job
    with transaction(engine) as db:
        db.get(State, "schema_version").value = 1
        db.add(Job(kind="poll", status="running", created=CLOCK))
    StagedBatch.__table__.drop(engine)
    with pytest.raises(RuntimeError, match="recover-interrupted"):
        migrate_v2(engine)
    assert migrate_v2(engine, recover_interrupted=True).startswith("Migrated")
    with transaction(engine) as db:
        row = db.scalar(select(Job))
        assert row.status == "failed"
        assert "checkpoint not advanced" in row.error.lower()


def test_staged_input_is_durable_before_analysis_and_payload_is_cleaned(engine):
    old = evt(n=4001, ts=CLOCK - 3*DAY)
    recent = evt(n=4002, ts=CLOCK - 45)
    # Events arrive out of event-time order and are sorted by stage_observations.
    with transaction(engine) as db:
        report = _stage(db, [recent, old], token="mixed")
        assert report["staged_events"] == 2
        assert count(db, Seen) == 0
        assert count(db, Finding) == 0
        assert queued_metrics(db)["pending_events"] == 2
    assert process_next_batch(engine, chunk_limit=1)
    with transaction(engine) as db:
        stored = db.get(StagedBatch, "mixed")
        assert stored.status == "done" and stored.processed == 2
        assert stored.compressed_events is not None
        assert stored.store_bytes == len(stored.compressed_events)
        assert stored.stats["accepted"] == 2
        assert stored.stats["historical_input_events"] == 1
        assert stored.stats["live_input_events"] == 1
        assert count(db, Seen) == 2
        assert count(db, Process) == 1  # Only the live event creates a Process row
        assert queued_metrics(db)["pending_events"] == 0
        assert db.get(State, "analysis_cursor:" + str(stored.shard)).value["status"] == "done"
    # A completed batch is immutable/never processed again.
    assert not process_next_batch(engine)


def test_failed_chunk_is_atomic_and_resume_does_not_repeat_finished_chunk(engine, monkeypatch):
    import deepsnout.worker as worker
    from deepsnout.db import Coverage
    records = [evt(n=4100+i, ts=CLOCK-4*DAY+i) for i in range(3)]
    with transaction(engine) as db:
        _stage(db, records, token="partial")
    original = worker.ingest_age_partitioned
    calls = []

    def fail_second(*args, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise ValueError("synthetic chunk interruption")
        return original(*args, **kwargs)

    monkeypatch.setattr(worker, "ingest_age_partitioned", fail_second)
    assert not process_next_batch(engine, chunk_limit=1)
    with transaction(engine) as db:
        batch = db.get(StagedBatch, "partial")
        assert batch.status == "failed"
        assert batch.processed == 1
        assert batch.compressed_events is not None
        assert count(db, Seen) == 1
        assert count(db, Coverage) == 1
        # Analytics failure must NOT stop neutral collection when storage is safe.
        assert queue_has_room(db)
        retry_failed_batch(db, "partial")
    monkeypatch.setattr(worker, "ingest_age_partitioned", original)
    assert process_next_batch(engine, chunk_limit=1)
    with transaction(engine) as db:
        assert count(db, Seen) == 3
        assert count(db, BatchReceipt) == 3
        assert db.get(StagedBatch, "partial").status == "done"
        assert db.get(StagedBatch, "partial").stats["accepted"] == 3


def test_failed_earlier_batch_cannot_be_bypassed(engine, monkeypatch):
    import deepsnout.worker as worker
    with transaction(engine) as db:
        _stage(db, [evt(n=4200)], token="first")
        _stage(db, [evt(n=4201)], token="second")
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic processor failure")
    original = worker.ingest_age_partitioned
    monkeypatch.setattr(worker, "ingest_age_partitioned", fail)
    assert not process_next_batch(engine)
    with transaction(engine) as db:
        assert next_pending_batch(db) is None
        assert db.get(StagedBatch, "first").status == "failed"
        assert count(db, Seen) == 0
        assert queued_metrics(db)["failed_batches"] == 1
        with pytest.raises(ValueError):
            retry_failed_batch(db, "second")
    # Do not process 'second' until 'first' is explicitly retried.
    assert not process_next_batch(engine)
    monkeypatch.setattr(worker, "ingest_age_partitioned", original)
    with transaction(engine) as db:
        retry_failed_batch(db, "first")
    assert process_next_batch(engine)
    assert process_next_batch(engine)
    with transaction(engine) as db:
        assert count(db, Seen) == 2


def test_backpressure_preserves_existing_batch(monkeypatch, db):
    import deepsnout.pipeline as pipeline
    assert _stage(db, [evt(n=4300), evt(n=4301)])["staged_events"] == 2
    used = queued_metrics(db)["stored_bytes"]
    monkeypatch.setattr(pipeline, "MAX_STORE_BYTES", used)
    with pytest.raises(BackpressureError, match="byte budget"):
        _stage(db, [evt(n=4302)], token="overflow")
    assert count(db, StagedBatch) == 1
    assert not queue_has_room(db)


def test_deduplicated_staging_and_corrupt_payload_fail_closed(engine):
    with transaction(engine) as db:
        records = [evt(n=4400)]
        assert _stage(db, records, token="repeat")["staged_events"] == 1
        assert _stage(db, records, token="repeat")["batch_already_staged"]
        db.flush()
        db.get(StagedBatch, "repeat").compressed_events = b"not a zlib stream"
    assert not process_next_batch(engine)
    with transaction(engine) as db:
        batch = db.get(StagedBatch, "repeat")
        assert batch.status == "failed" and batch.processed == 0
        assert count(db, Seen) == 0


def test_successful_collector_checkpoint_is_independent_of_detection(engine, config):
    source_id = None
    with transaction(engine) as db:
        source = Source(
            name="Synthetic", namespace="test",
            config=SplunkSettings(url="https://splunk.example", indexes="wef").model_dump(),
            credential=crypto(config).encrypt(b"TEST-ONLY").decode(),
            checkpoint=CLOCK-600)
        db.add(source)
        db.flush()
        source_id = source.id
        job_id = enqueue(db, "poll", source_id=source_id).id

    class Client:
        def __init__(self, *args, **kwargs): pass
        def close(self): pass
        def slice(self, start, end):
            return [evt(n=4500, ts=CLOCK-80)], {"received": 1}, end

    assert run_job(engine, config, job_id, client_factory=Client,
                   defer_analysis=True, heartbeat_key="worker_ingest")
    with transaction(engine) as db:
        assert db.get(Source, source_id).checkpoint == CLOCK-540
        assert count(db, StagedBatch) == 1
        assert count(db, Seen) == 0
        assert count(db, Process) == 0
        from deepsnout.db import Job
        job = db.get(Job, job_id)
        assert job.status == "done" and job.report["staged_events"] == 1
        assert job.report["analysis_deferred"] is True
    assert process_next_batch(engine)
    with transaction(engine) as db:
        assert count(db, Seen) == 1
        assert db.get(Source, source_id).checkpoint == CLOCK-540


def test_source_checkpoint_rolls_back_if_staging_rejected(engine, config, monkeypatch):
    import deepsnout.pipeline as pipeline
    with transaction(engine) as db:
        source = Source(
            name="Synthetic", namespace="test",
            config=SplunkSettings(url="https://splunk.example", indexes="wef").model_dump(),
            credential=crypto(config).encrypt(b"TEST-ONLY").decode(),
            checkpoint=CLOCK-600)
        db.add(source)
        db.flush()
        source_id = source.id
        job_id = enqueue(db, "poll", source_id=source_id).id

    class Client:
        def __init__(self, *args, **kwargs): pass
        def close(self): pass
        def slice(self, start, end):
            return [evt(n=4505, ts=CLOCK-80)], {"received": 1}, end

    monkeypatch.setattr(pipeline, "MAX_STORE_BYTES", 0)
    assert not run_job(engine, config, job_id, client_factory=Client,
                       defer_analysis=True, heartbeat_key="worker_ingest")
    with transaction(engine) as db:
        assert db.get(Source, source_id).checkpoint == CLOCK-600
        assert count(db, StagedBatch) == 0
        assert count(db, Seen) == 0


def test_different_worker_roles_have_independent_locks(engine, config):
    with worker_lock(engine, config, "ingest"):
        with worker_lock(engine, config, "analysis"):
            with worker_lock(engine, config, "insight"):
                pass


def test_finished_batch_retention_never_removes_pending_data(db):
    from deepsnout.db import now
    _stage(db, [evt(n=4600)], token="pending")
    _stage(db, [evt(n=4601)], token="done")
    db.flush()
    old = now() - 10 * DAY
    row = db.get(StagedBatch, "done")
    row.status, row.finished, row.compressed_events = "done", old, None
    assert prune_finished_batches(db) == 1
    assert db.get(StagedBatch, "pending") is not None
    assert db.get(StagedBatch, "done") is None
