"""Privacy-safe tests for fresh-first collection and sharded analysis."""
import pytest
from sqlalchemy import select

from conftest import CLOCK, DAY, evt, count
from deepsnout.db import (transaction, State, Source, Job, StagedBatch, Seen,
                          initialize, now, set_state)
from deepsnout.normalize import digest
from deepsnout.pipeline import (stage_observations, queued_metrics, queue_has_room,
                                host_shard, next_pending_batch, process_next_batch,
                                retry_failed_batch)
from deepsnout.worker import enqueue, run_job, tick_ingest
from deepsnout.security import crypto
from deepsnout.splunk import SplunkSettings


def _host(shard, namespace="test"):
    for i in range(500):
        candidate = f"synthetic-shard-{i}.example"
        if host_shard(namespace, candidate) == shard:
            return candidate
    raise AssertionError("Synthetic hostname not found")


def _stage(db, token, host, *, lane="backfill", timestamp=CLOCK-40):
    return stage_observations(
        db, [evt(host=host, n=5000 + len(token), ts=timestamp)],
        batch_id=token, source_id="synthetic",
        namespace="test", cohort="unassigned", collected_clock=CLOCK,
        lane=lane)


def test_same_host_is_always_one_shard_and_multi_host_stage_is_atomic(db):
    hosts = [_host(i) for i in range(4)]
    records = [evt(host=host, n=6000+i) for i, host in enumerate(hosts)]
    result = stage_observations(
        db, records, batch_id="four-shard-parent", source_id="synthetic",
        namespace="test", cohort="unassigned", collected_clock=CLOCK,
        lane="live")
    db.flush()
    batches = db.scalars(select(StagedBatch).where(
        StagedBatch.batch_parent == "four-shard-parent")).all()
    assert result["staged_events"] == 4
    assert result["staged_shards"] == 4
    assert len(batches) == 4
    assert {b.shard for b in batches} == {0, 1, 2, 3}
    assert all(b.lane == "live" for b in batches)
    assert len({b.id for b in batches}) == 4
    assert all(b.compressed_events for b in batches)
    assert all(b.store_bytes == len(b.compressed_events) for b in batches)
    assert stage_observations(
        db, records, batch_id="four-shard-parent", source_id="synthetic",
        namespace="test", cohort="unassigned", collected_clock=CLOCK,
        lane="live")["batch_already_staged"]
    assert count(db, StagedBatch) == 4


def test_recent_analysis_preempts_background_at_chunk_boundary(engine):
    host = _host(0)
    with transaction(engine) as db:
        stage_observations(
            db, [evt(host=host, n=7000+i, ts=CLOCK-3*DAY+i)
                 for i in range(3)],
            batch_id="long-background", source_id="synthetic",
            namespace="test", cohort="unassigned", collected_clock=CLOCK)
    assert process_next_batch(engine, chunk_limit=1, max_chunks=1, shards=[0])
    with transaction(engine) as db:
        assert db.get(StagedBatch, "long-background").processed == 1
        _stage(db, "new-live", host, lane="live")
        assert next_pending_batch(db, shards=[0]).id == "new-live"
    assert process_next_batch(engine, chunk_limit=1, max_chunks=1, shards=[0])
    with transaction(engine) as db:
        assert db.get(StagedBatch, "new-live").status == "done"
        assert db.get(StagedBatch, "long-background").processed == 1
        assert next_pending_batch(db, shards=[0]).id == "long-background"
    assert process_next_batch(engine, chunk_limit=1, shards=[0])
    with transaction(engine) as db:
        assert count(db, Seen) == 4
        assert db.get(StagedBatch, "long-background").status == "done"


def test_failed_background_does_not_block_live_or_collection(engine):
    host = _host(1)
    with transaction(engine) as db:
        _stage(db, "broken-backfill", host)
        db.flush()
        db.get(StagedBatch, "broken-backfill").status = "failed"
        _stage(db, "healthy-live", host, lane="live")
        assert queue_has_room(db)
        assert queued_metrics(db)["failed_batches"] == 1
        assert next_pending_batch(db, shards=[1]).id == "healthy-live"
    assert process_next_batch(engine, shards=[1])
    with transaction(engine) as db:
        assert db.get(StagedBatch, "healthy-live").status == "done"
        assert db.get(StagedBatch, "broken-backfill").status == "failed"
        assert next_pending_batch(db, shards=[1]) is None
        retry_failed_batch(db, "broken-backfill")
    assert process_next_batch(engine, shards=[1])


def test_failed_live_only_blocks_that_host_shard(engine):
    a, b = _host(0), _host(1)
    with transaction(engine) as db:
        _stage(db, "broken-live", a, lane="live")
        db.flush()
        db.get(StagedBatch, "broken-live").status = "failed"
        _stage(db, "other-shard-live", b, lane="live")
        assert next_pending_batch(db, shards=[0]) is None
        assert next_pending_batch(db, shards=[1]).id == "other-shard-live"
    assert process_next_batch(engine, shards=[1])
    with transaction(engine) as db:
        assert db.get(StagedBatch, "other-shard-live").status == "done"
        assert db.get(StagedBatch, "broken-live").status == "failed"


def test_two_disjoint_analysis_workers_do_not_overlap_hosts(engine):
    hosts = [_host(i) for i in range(4)]
    with transaction(engine) as db:
        stage_observations(
            db, [evt(host=host, n=8100+i) for i, host in enumerate(hosts)],
            batch_id="partitioned", source_id="synthetic",
            namespace="test", cohort="unassigned", collected_clock=CLOCK,
            lane="live")
    for _ in range(2):
        assert process_next_batch(engine, shards=(0, 2), max_chunks=1)
        assert process_next_batch(engine, shards=(1, 3), max_chunks=1)
    assert not process_next_batch(engine, shards=(0, 2))
    assert not process_next_batch(engine, shards=(1, 3))
    with transaction(engine) as db:
        assert count(db, Seen) == 4
        assert all(row.status == "done" for row in db.scalars(select(StagedBatch)))


def test_finished_observation_payload_retained_for_two_day_window(engine):
    with transaction(engine) as db:
        _stage(db, "retain-batch", _host(0))
    assert process_next_batch(engine, shards=[0])
    with transaction(engine) as db:
        row = db.get(StagedBatch, "retain-batch")
        assert row.status == "done"
        assert row.compressed_events is not None
        assert row.store_bytes > 0


def _source_with_tail(engine, config):
    with transaction(engine) as db:
        src = Source(
            name="Synthetic live-tail", enabled=True, namespace="test",
            config=SplunkSettings(
                url="https://splunk.example", indexes="wef",
                window=60, catchup_window=60,
                lag=60, interval=60).model_dump(),
            credential=crypto(config).encrypt(b"LOCAL-TEST-ONLY").decode(),
            checkpoint=CLOCK-300)
        db.add(src)
        db.flush()
        tail = {"active": True, "start": CLOCK-250,
                "checkpoint": CLOCK-250, "last_poll": 0,
                "source_signature": digest(src.config, src.credential)}
        set_state(db, "splunk_tail:" + src.id, tail)
        return src.id


class _Client:
    def __init__(self, *args, **kwargs): pass
    def close(self): pass
    def slice(self, start, end):
        return [evt(n=9600 + (start % 1000), ts=CLOCK-25)], {
            "received": 1, "requested_span": end-start,
            "effective_span": end-start, "slice_attempts": 1}, end


def test_independent_tail_cursor_and_gap_free_catchup_merge(engine, config):
    sid = _source_with_tail(engine, config)
    with transaction(engine) as db:
        tail_job = enqueue(db, "tail_poll", source_id=sid).id
    assert run_job(engine, config, tail_job, client_factory=_Client,
                   defer_analysis=True, heartbeat_key="worker_ingest")
    with transaction(engine) as db:
        tail_state = db.get(State, "splunk_tail:" + sid).value
        assert tail_state["active"]
        assert tail_state["checkpoint"] == CLOCK-190
        assert db.get(Source, sid).checkpoint == CLOCK-300
        rows = list(db.scalars(select(StagedBatch)))
        assert len(rows) == 1 and rows[0].lane == "live"
        backfill_job = enqueue(db, "poll", source_id=sid).id
    assert run_job(engine, config, backfill_job, client_factory=_Client,
                   defer_analysis=True, heartbeat_key="worker_ingest")
    with transaction(engine) as db:
        source = db.get(Source, sid)
        tail_state = db.get(State, "splunk_tail:" + sid).value
        assert source.checkpoint == CLOCK-190
        assert not tail_state["active"]
        assert tail_state["merged_at"] > 0
        rows = list(db.scalars(select(StagedBatch)))
        assert len(rows) == 2
        assert {r.lane for r in rows} == {"live", "backfill"}
        assert db.get(Job, backfill_job).report["live_tail_merged"] is True


def test_tick_ingest_prioritizes_tail_over_catchup(engine, config, monkeypatch):
    import deepsnout.worker as worker
    with transaction(engine) as db:
        source = Source(
            name="Synthetic backlog", enabled=True, namespace="test",
            config=SplunkSettings(
                url="https://splunk.example", indexes="wef",
                window=60, catchup_window=900, lag=60, interval=60).model_dump(),
            credential=crypto(config).encrypt(b"LOCAL-TEST-ONLY").decode(),
            checkpoint=CLOCK-3600)
        db.add(source)
        db.flush()
        sid = source.id
    called = []
    def fake_run(engine, config, jid, **kwargs):
        with transaction(engine) as db:
            called.append(db.get(Job, jid).kind)
        return True
    monkeypatch.setattr(worker, "run_job", fake_run)
    assert tick_ingest(engine, config)
    with transaction(engine) as db:
        tail = db.get(State, "splunk_tail:" + sid).value
        assert tail["active"] and tail["start"] > CLOCK-3600
        jobs = list(db.scalars(select(Job)))
        assert {j.kind for j in jobs} == {"tail_poll", "poll"}
        assert called == ["tail_poll"]


def test_v3_schema_column_upgrade_preserves_compressed_batch(engine):
    with transaction(engine) as db:
        _stage(db, "pre-v3-record", _host(0))
        db.get(State, "schema_version").value = 2
        row = db.get(StagedBatch, "pre-v3-record")
        old_bytes = bytes(row.compressed_events)
        row.store_bytes = 0
        row.batch_parent = ""
    from deepsnout.db import migrate_v3
    assert migrate_v3(engine) == "Migrated schema v2 to v3"
    initialize(engine)
    with transaction(engine) as db:
        row = db.get(StagedBatch, "pre-v3-record")
        assert row.batch_parent == row.id
        assert row.store_bytes == len(old_bytes)
        assert row.compressed_events == old_bytes
        assert db.get(State, "schema_version").value == 3



def test_overlapping_host_shard_writer_locks_are_rejected(engine, config):
    import pytest
    from deepsnout.worker import worker_lock
    with worker_lock(engine, config, "analysis:0,2"):
        with worker_lock(engine, config, "analysis:1,3"):
            pass
        with pytest.raises(RuntimeError):
            with worker_lock(engine, config, "analysis:0"):
                pass


def test_live_reference_is_explicitly_incomplete_while_backfill_is_unprocessed(engine):
    from deepsnout.db import Process
    host = _host(2)
    with transaction(engine) as db:
        _stage(db, "old-reference", host,
               lane="backfill", timestamp=CLOCK-3*DAY)
        _stage(db, "latest-fresh", host, lane="live",
               timestamp=CLOCK-80)
    assert process_next_batch(engine, shards=[2], max_chunks=1)
    with transaction(engine) as db:
        proc = db.scalar(select(Process).where(Process.host_id.is_not(None)))
        assert proc is not None
        assert proc.metadata_json["reference"]["historical_reference_incomplete"] is True
        assert any("catch-up is incomplete" in w for w in
                   proc.metadata_json["warnings"])
