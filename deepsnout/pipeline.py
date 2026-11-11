"""On-prem observation store and best-effort, host-partitioned analysis.

Splunk cursor advances only when all normalized observations are durably stored.
Analyzer failures never block collection unless the storage budget is exhausted.
"""
from collections import defaultdict
import hashlib
import json
import logging
import os
import time
import zlib

from sqlalchemy import select, func, delete
from sqlalchemy.orm import defer
from .db import StagedBatch, State, now, transaction, set_state
from .normalize import Event, digest
from .engine import evaluate_windows

LOG = logging.getLogger("deepsnout.pipeline")
SHARD_COUNT = 4  # Changing this needs an explicit resharding migration.
MAX_STORE_BYTES = max(1, int(os.getenv("DEEPSNOUT_STORE_BUDGET_GIB", "4"))) * 1024**3
CATCHUP_RESERVE_FRACTION = 0.75
MAX_BATCH_EVENTS = 100_000
MAX_COMPRESSED_BYTES = 64 * 1024**2
MAX_DECOMPRESSED_BYTES = MAX_COMPRESSED_BYTES * 8
ANALYSIS_CHUNK_EVENTS = 400
STORE_RETAIN_DAYS = max(1, min(7, int(os.getenv("DEEPSNOUT_STORE_RETENTION_DAYS", "2"))))
ANALYSIS_STATES = ("pending", "failed")
LANES = ("live", "backfill")


class BackpressureError(ValueError):
    pass


def host_shard(namespace, host):
    return int(digest(namespace, host)[:8], 16) % SHARD_COUNT


def queued_metrics(db):
    grouped = db.execute(
        select(StagedBatch.lane, StagedBatch.status,
               func.count(), func.coalesce(func.sum(
                   StagedBatch.event_count - StagedBatch.processed), 0))
        .group_by(StagedBatch.lane, StagedBatch.status)).all()
    pending = sum(int(count) for _, status, count, _ in grouped
                  if status in ANALYSIS_STATES)
    events = sum(int(remaining) for _, status, _, remaining in grouped
                 if status in ANALYSIS_STATES)
    failed = sum(int(count) for _, status, count, _ in grouped
                 if status == "failed")
    oldest = db.scalar(select(func.min(StagedBatch.collected_at)).where(
        StagedBatch.status.in_(ANALYSIS_STATES)))
    stored = int(db.scalar(select(func.coalesce(
        func.sum(StagedBatch.store_bytes), 0))) or 0)
    by_lane = {}
    for lane in LANES:
        rows = [(status, int(n), int(left))
                for kind, status, n, left in grouped if kind == lane]
        by_lane[lane] = {
            "pending_batches": sum(n for status, n, _ in rows
                                   if status in ANALYSIS_STATES),
            "pending_events": sum(left for status, _, left in rows
                                  if status in ANALYSIS_STATES),
            "failed_batches": sum(n for status, n, _ in rows if status == "failed"),
        }
    return {
        "pending_batches": pending, "pending_events": events,
        "failed_batches": failed,
        "oldest_batch_age_seconds": round(max(0, now() - oldest), 1) if oldest else 0,
        "stored_bytes": stored, "store_budget_bytes": MAX_STORE_BYTES,
        "store_retention_days": STORE_RETAIN_DAYS,
        "storage_backpressure": stored >= MAX_STORE_BYTES,
        "storage_safety_note": "Configured observation-store budget, not disk free space",
        "lanes": by_lane,
    }


def queue_has_room(db):
    return queued_metrics(db)["stored_bytes"] < MAX_STORE_BYTES


def stage_observations(db, records, *, batch_id, source_id, namespace, cohort,
                       collected_clock, lane="backfill"):
    """One atomic staging transaction for all host partitions and checkpoint."""
    if lane not in LANES:
        raise ValueError("Unknown observation lane")
    if not records:
        return {"staged_events": 0, "analysis_pending": False, "lane": lane}
    if len(records) > MAX_BATCH_EVENTS:
        raise BackpressureError("Input exceeds maximum normalized batch events")
    if db.scalar(select(StagedBatch.id).where(
            StagedBatch.batch_parent == batch_id).limit(1)):
        return {"staged_events": 0, "batch_already_staged": True, "lane": lane}

    groups = defaultdict(list)
    for record in records:
        groups[host_shard(namespace, record.host)].append(record)
    payloads = []
    total_bytes = 0
    for shard, rows in sorted(groups.items()):
        ordered = sorted(rows, key=lambda e: (e.ts, e.event_id != 1))
        raw = json.dumps([e.to_dict() for e in ordered], separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
        if len(raw) > MAX_DECOMPRESSED_BYTES:
            raise BackpressureError("Normalized shard exceeds decompression size limit")
        compressed = zlib.compress(raw, level=3)
        if len(compressed) > MAX_COMPRESSED_BYTES:
            raise BackpressureError("Normalized shard exceeds 64 MiB compressed")
        payloads.append((shard, ordered, compressed))
        total_bytes += len(compressed)

    existing_bytes = queued_metrics(db)["stored_bytes"]
    if existing_bytes + total_bytes > MAX_STORE_BYTES:
        raise BackpressureError(
            "Local observation store exceeded byte budget; Splunk checkpoint unchanged.")
    if (lane == "backfill" and
            existing_bytes + total_bytes > MAX_STORE_BYTES * CATCHUP_RESERVE_FRACTION):
        raise BackpressureError(
            "Catch-up storage reservation reached; live ingestion capacity protected.")
    for position, (shard, ordered, compressed) in enumerate(payloads):
        row_id = batch_id if position == 0 else digest("staged-shard", batch_id, shard)
        db.add(StagedBatch(
            id=row_id, batch_parent=batch_id, source_id=source_id,
            namespace=namespace, cohort=cohort,
            shard=shard, lane=lane, collected_at=now(),
            ingestion_clock=collected_clock, event_count=len(ordered),
            processed=0, compressed_events=compressed,
            store_bytes=len(compressed),
            content_sha256=hashlib.sha256(compressed).hexdigest(),
            status="pending", stats={},
        ))
    return {
        "staged_events": len(records), "staged_shards": len(payloads),
        "staged_compressed_bytes": total_bytes, "analysis_pending": True,
        "analysis_cursor_committed": False, "analysis_handoff": "postgresql",
        "lane": lane,
    }


def _decode(batch):
    compressed = batch.compressed_events
    if compressed is None:
        raise ValueError("Missing retained observation payload")
    if len(compressed) > MAX_COMPRESSED_BYTES:
        raise ValueError("Compressed payload exceeds 64 MiB")
    if hashlib.sha256(compressed).hexdigest() != batch.content_sha256:
        raise ValueError("Staged observation failed SHA-256 integrity verification")
    decoder = zlib.decompressobj()
    raw = decoder.decompress(compressed, MAX_DECOMPRESSED_BYTES + 1)
    if len(raw) > MAX_DECOMPRESSED_BYTES or not decoder.eof or decoder.unused_data:
        raise ValueError("Staged observation exceeded safe decompression limit")
    parsed = json.loads(raw)
    if not isinstance(parsed, list) or len(parsed) != batch.event_count:
        raise ValueError("Staged observation has invalid event count")
    return [Event(**row) for row in parsed]


def next_pending_batch(db, shards=None):
    """Live-first within each host shard; failed work blocks its lane only."""
    shards = tuple(range(SHARD_COUNT)) if shards is None else tuple(shards)
    choices = []
    for shard in shards:
        if not 0 <= shard < SHARD_COUNT:
            raise ValueError("Invalid analysis shard")
        for lane in LANES:
            row = db.execute(
                select(StagedBatch.id, StagedBatch.status,
                       StagedBatch.collected_at)
                .where(StagedBatch.shard == shard, StagedBatch.lane == lane,
                       StagedBatch.status.in_(ANALYSIS_STATES))
                .order_by(StagedBatch.collected_at, StagedBatch.id).limit(1)
            ).first()
            if row:
                if row.status == "failed" and lane == "live":
                    break
                if row.status == "pending":
                    choices.append((0 if lane == "live" else 1,
                                    row.collected_at, row.id))
                    break
    if not choices:
        return None
    return db.get(
        StagedBatch, min(choices)[2],
        options=(defer(StagedBatch.compressed_events),))



# Structured operational diagnostics contain NO raw log lines, exception
# messages, SQL queries/parameters, hostnames or command-line content.
# Full tracebacks stay in the local container logs.
def _safe_failure(exc, stage, batch, position):
    root = getattr(exc, "orig", None) or exc
    state = getattr(root, "sqlstate", None) or getattr(root, "pgcode", None)
    if not (isinstance(state, str) and len(state) == 5 and
            state.isascii() and state.isalnum()):
        state = None
    cls = type(exc).__name__
    if state in ("40001", "40P01", "55P03"):
        hint = "Database transaction contention. Review local worker and database logs before retry."
    elif state in ("53100", "53200", "53400"):
        hint = "Database resource limit reported. Verify free disk space and PostgreSQL capacity before retry."
    elif state and state.startswith("23"):
        hint = "Database constraint rejected an analysis write. Review local logs before retry."
    elif stage == "decode":
        hint = "Staged payload validation failed. Check integrity and local worker logs before retry."
    elif stage == "evaluate-network":
        hint = "Network-window evaluation failed. Review the detector-worker logs before retry."
    elif stage == "ingest-chunk":
        hint = "Event processing failed. Review the detector-worker logs before retry."
    else:
        hint = "The analysis transaction failed. Review local worker logs before retry."
    return {
        "occurred_at": now(),
        "exception_type": cls,
        "database_sqlstate": state,
        "stage": stage,
        "cursor_before_failure": position,
        "lane": batch.lane,
        "shard": batch.shard,
        "hint": hint,
        "message_redacted": True,
    }


def process_next_batch(engine, *, progress=None, chunk_limit=ANALYSIS_CHUNK_EVENTS,
                       max_chunks=None, shards=None, cache=None):
    """Commit each chunk and its cursor together; preempt background every chunk."""
    with transaction(engine) as db:
        batch = next_pending_batch(db, shards=shards)
        if not batch:
            return False
        batch_id, offset = batch.id, batch.processed
        snapshot = {
            "id": batch.id, "event_count": batch.event_count,
            "namespace": batch.namespace, "cohort": batch.cohort,
            "clock": batch.ingestion_clock, "lane": batch.lane,
            "shard": batch.shard, "content_sha256": batch.content_sha256,
        }
        if batch.lane == "live":
            tail = db.get(State, "splunk_tail:" + batch.source_id) if batch.source_id else None
            backfill_pending = db.scalar(select(func.count()).select_from(StagedBatch).where(
                StagedBatch.source_id == batch.source_id,
                StagedBatch.lane == "backfill",
                StagedBatch.status.in_(ANALYSIS_STATES))) or 0
            snapshot["baseline_incomplete"] = bool(
                (tail and tail.value.get("active")) or backfill_pending)
        else:
            snapshot["baseline_incomplete"] = False
        # The compressed payload is large: read it only on a cache miss,
        # never during the 400-event transaction that advances a cursor.
        hit = cache.get(batch_id) if cache is not None else None
        if not hit or hit[0] != batch.content_sha256:
            snapshot["compressed_events"] = db.scalar(
                select(StagedBatch.compressed_events).where(StagedBatch.id == batch_id))
    stage = "decode"
    chunk_start = offset
    try:
        cached = cache.get(batch_id) if cache is not None else None
        if cached and cached[0] == snapshot["content_sha256"]:
            events = cached[1]
        else:
            events = _decode(type("Snapshot", (), snapshot)())
            if cache is not None:
                if len(cache) >= 2:
                    cache.pop(next(iter(cache)))
                cache[batch_id] = (snapshot["content_sha256"], events)
        chunk_limit = max(1, min(2000, int(chunk_limit)))
        completed = 0
        for start in range(offset, len(events), chunk_limit):
            end = min(len(events), start + chunk_limit)
            chunk_start = start
            stage = "ingest-chunk"
            if progress:
                progress("analysis-chunk", {
                    "processed": start, "total": len(events),
                    "shard": snapshot["shard"], "lane": snapshot["lane"]})
            with transaction(engine) as db:
                batch = db.get(
                    StagedBatch, batch_id,
                    options=(defer(StagedBatch.compressed_events),))
                if batch.status != "pending" or batch.processed != start:
                    raise RuntimeError("Analysis cursor changed by another writer")
                from .worker import ingest_age_partitioned
                report = ingest_age_partitioned(
                    db, events[start:end], namespace=batch.namespace,
                    cohort=batch.cohort, clock=batch.ingestion_clock,
                    batch_id=digest("analyzed-chunk", batch_id, start, end),
                    counter_state_key="behavioral_discovery_pipeline:" + str(batch.shard),
                    last_ingest_state_key="last_ingest:" + str(batch.shard),
                    baseline_incomplete=snapshot["baseline_incomplete"])
                stats = dict(batch.stats or {})
                for field in ("accepted", "duplicates", "historical_input_events",
                              "live_input_events", "historical_ingest_seconds",
                              "live_ingest_seconds"):
                    stats[field] = round(float(stats.get(field, 0)) +
                                         float(report.get(field, 0)), 3)
                batch.processed = end
                if end == len(events):
                    stage = "evaluate-network"
                    t0 = time.monotonic()
                    affected = {digest(batch.namespace, e.host)[:32] for e in events}
                    stats["network_findings_created"] = evaluate_windows(
                        db, clock=batch.ingestion_clock, host_ids=affected)
                    stats["evaluate_seconds"] = round(time.monotonic()-t0, 3)
                    batch.status, batch.finished = "done", now()
                    if cache is not None:
                        cache.pop(batch_id, None)
                batch.stats = stats
                set_state(db, "analysis_cursor:" + str(batch.shard), {
                    "batch_id": batch_id, "processed": end, "total": len(events),
                    "at": now(), "status": batch.status, "lane": batch.lane,
                })
            completed += 1
            if max_chunks is not None and completed >= max_chunks:
                break
        LOG.info("Analysis shard %s batch %s advanced %d chunks",
                 snapshot["shard"], batch_id[:12], completed)
        return completed > 0
    except Exception as exc:
        # Include the stable batch ID in the local traceback so the GUI can
        # point to the exact log entry. Do not put traceback/SQL/log content in
        # the database, HTML or the counts-only metrics endpoint.
        LOG.exception(
            "Analysis batch failed batch=%s lane=%s shard=%s stage=%s offset=%s; committed chunks retained",
            batch_id, snapshot["lane"], snapshot["shard"], stage, chunk_start)
        with transaction(engine) as db:
            batch = db.get(StagedBatch, batch_id)
            if batch and batch.status == "pending":
                failure = _safe_failure(exc, stage, batch, chunk_start)
                stats = dict(batch.stats or {})
                stats["last_failure"] = failure
                batch.stats = stats
                batch.status = "failed"
                batch.attempts += 1
                batch.last_error = (
                    failure["exception_type"] +
                    (" (SQLSTATE " + failure["database_sqlstate"] + ")"
                     if failure["database_sqlstate"] else "") +
                    " at " + failure["stage"])
                set_state(db, "analysis_cursor:" + str(batch.shard), {
                    "batch_id": batch_id, "processed": batch.processed,
                    "total": batch.event_count, "at": now(), "status": "failed",
                    "lane": batch.lane,
                })
        return False


def retry_failed_batch(db, batch_id):
    batch = db.get(StagedBatch, batch_id)
    if not batch or batch.status != "failed":
        raise ValueError("Only failed staged analysis batches can be retried")
    if batch.compressed_events is None:
        raise ValueError("Missing retained payload; cannot retry")
    batch.status, batch.last_error = "pending", ""
    stats = dict(batch.stats or {})
    stats["last_retry_at"] = now()
    batch.stats = stats


def prune_finished_batches(db, clock=None):
    """Retain finished compressed observations for two days for local replay."""
    clock = now() if clock is None else clock
    return db.execute(
        delete(StagedBatch).where(
            StagedBatch.status == "done",
            StagedBatch.finished < clock - STORE_RETAIN_DAYS * 86400)
    ).rowcount
