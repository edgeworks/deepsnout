"""Local-only durable boundary between Splunk collection and analysis.

A Splunk cursor advances only after a bounded, compressed NORMALIZED event
batch is durably stored in PostgreSQL. An independent worker consumes batches
in collection order, committing its own position in the same transaction as
each analysis chunk. No broker, external API, raw Splunk response or log export.

The source checkpoint and the analysis position are deliberately independent:
a slow detector may create analysis lag but cannot monopolize the collector.
"""
import hashlib
import json
import logging
import time
import zlib

from sqlalchemy import select, func, delete

from .db import StagedBatch, State, now, transaction, set_state
from .normalize import Event, digest
from .engine import evaluate_windows

LOG = logging.getLogger("deepsnout.pipeline")

# A bounded queue is essential when 50K live observations can take hours to
# analyze. Backpressure stops NEW checkpoint advancement; no events are lost.
MAX_PENDING_EVENTS = 800_000
MAX_PENDING_BATCHES = 80
MAX_BATCH_EVENTS = 100_000
MAX_COMPRESSED_BYTES = 64 * 1024 * 1024
ANALYSIS_CHUNK_EVENTS = 400
DONE_BATCH_DAYS = 7

ANALYSIS_STATES = ("pending", "failed")


class BackpressureError(ValueError):
    pass


def queued_metrics(db):
    outstanding = (select(StagedBatch)
                   .where(StagedBatch.status.in_(ANALYSIS_STATES))
                   .subquery())
    count, remaining = db.execute(
        select(func.count(), func.coalesce(
            func.sum(outstanding.c.event_count - outstanding.c.processed), 0))
        .select_from(outstanding)).one()
    oldest = db.scalar(
        select(func.min(StagedBatch.collected_at))
        .where(StagedBatch.status.in_(ANALYSIS_STATES)))
    failures = db.scalar(
        select(func.count()).select_from(StagedBatch)
        .where(StagedBatch.status == "failed")) or 0
    return {
        "pending_batches": int(count),
        "pending_events": int(remaining),
        "failed_batches": int(failures),
        "oldest_batch_age_seconds": round(max(0, now() - oldest), 1) if oldest else 0,
        "queue_cap_events": MAX_PENDING_EVENTS,
        "queue_cap_batches": MAX_PENDING_BATCHES,
    }


def queue_has_room(db):
    counts = queued_metrics(db)
    return (counts["pending_batches"] < MAX_PENDING_BATCHES and
            counts["pending_events"] < MAX_PENDING_EVENTS and
            not counts["failed_batches"])


def stage_observations(db, records, *, batch_id, source_id, namespace, cohort,
                       collected_clock):
    """Stage normalized events; the caller owns the source checkpoint txn."""
    if not records:
        return {"staged_events": 0, "analysis_pending": True}
    if len(records) > MAX_BATCH_EVENTS:
        raise BackpressureError("Input exceeds maximum normalized batch events")
    current = db.get(StagedBatch, batch_id)
    if current:
        return {"staged_events": 0, "batch_already_staged": True}
    capacity = queued_metrics(db)
    if (capacity["failed_batches"] or
            capacity["pending_batches"] >= MAX_PENDING_BATCHES or
            capacity["pending_events"] + len(records) > MAX_PENDING_EVENTS):
        raise BackpressureError(
            "Local analysis backlog is at capacity or contains a failed batch. "
            "Splunk checkpoint not advanced; inspect Operations.")
    # Normalize sorting once. Event 1 takes precedence at equal timestamps to
    # preserve its ProcessGuid attribution to later network events.
    ordered = sorted(records, key=lambda e: (e.ts, e.event_id != 1))
    raw = json.dumps([e.to_dict() for e in ordered], separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
    compressed = zlib.compress(raw, level=3)
    if len(compressed) > MAX_COMPRESSED_BYTES:
        raise BackpressureError("Compressed analysis batch exceeds 64 MiB; cursor unchanged")
    db.add(StagedBatch(
        id=batch_id, source_id=source_id, namespace=namespace,
        cohort=cohort, collected_at=now(), ingestion_clock=collected_clock,
        event_count=len(ordered), processed=0,
        compressed_events=compressed, content_sha256=hashlib.sha256(compressed).hexdigest(),
        status="pending", stats={},
    ))
    return {
        "staged_events": len(ordered),
        "staged_compressed_bytes": len(compressed),
        "analysis_pending": True,
        "analysis_cursor_committed": False,
        "analysis_handoff": "postgresql",
    }


def _decode(batch):
    compressed = batch.compressed_events
    if compressed is None:
        raise ValueError("Pending normalized batch has no payload")
    if hashlib.sha256(compressed).hexdigest() != batch.content_sha256:
        raise ValueError("Staged analysis batch failed its integrity check")
    # Decompression is bounded by the event count and compressed input size;
    # output is still capped to avoid corrupt/hostile compressed contents.
    if len(compressed) > MAX_COMPRESSED_BYTES:
        raise ValueError("Staged analysis batch exceeds the maximum compressed size")
    decoder = zlib.decompressobj()
    raw = decoder.decompress(compressed, MAX_COMPRESSED_BYTES * 8 + 1)
    if len(raw) > MAX_COMPRESSED_BYTES * 8 or not decoder.eof or decoder.unused_data:
        raise ValueError("Staged batch is incomplete or exceeds decompression limit")
    parsed = json.loads(raw)
    if not isinstance(parsed, list) or len(parsed) != batch.event_count:
        raise ValueError("Staged analysis event count does not match")
    return [Event(**row) for row in parsed]


def next_pending_batch(db):
    # A failed earlier batch blocks later batches: never quietly skip a
    # historical predecessor and evaluate a later baseline out of order.
    return db.scalar(
        select(StagedBatch)
        .where(StagedBatch.status.in_(ANALYSIS_STATES))
        .order_by(StagedBatch.collected_at, StagedBatch.id)
        .limit(1))


def process_next_batch(engine, *, progress=None, chunk_limit=ANALYSIS_CHUNK_EVENTS):
    """Process one durable batch, committing each chunk with its own cursor.

    If the process crashes mid-chunk, both event writes and the chunk offset
    roll back. On restart it resumes at its previous committed offset without
    contacting Splunk. All input stays in the private local database.
    """
    with transaction(engine) as db:
        current = next_pending_batch(db)
        if not current or current.status == "failed":
            return False
        batch_id, start_pos = current.id, current.processed
        # Detach bytes/metadata before the analysis transactions begin.
        snapshot = {
            "id": current.id, "event_count": current.event_count,
            "namespace": current.namespace, "cohort": current.cohort,
            "clock": current.ingestion_clock, "processed": start_pos,
            "compressed_events": current.compressed_events,
            "content_sha256": current.content_sha256,
        }

    try:
        events = _decode(type("Snapshot", (), snapshot)())
        chunk_limit = max(1, min(2000, int(chunk_limit)))
        if progress:
            progress("analysis-batch", {"processed": start_pos, "total": len(events)})
        # Batch preparation happens outside the DB transaction. Only chunks
        # have write transactions, bounding cancellation and rollback costs.
        for start in range(start_pos, len(events), chunk_limit):
            end = min(len(events), start + chunk_limit)
            if progress:
                progress("analysis-chunk", {"processed": start, "total": len(events)})
            with transaction(engine) as db:
                batch = db.get(StagedBatch, batch_id)
                if batch.status != "pending" or batch.processed != start:
                    raise RuntimeError("Analysis cursor was changed by another writer")
                from .worker import ingest_age_partitioned
                receipt = digest("analyzed-chunk", batch_id, start, end)
                report = ingest_age_partitioned(
                    db, events[start:end], namespace=batch.namespace,
                    cohort=batch.cohort, clock=batch.ingestion_clock,
                    batch_id=receipt)
                stats = dict(batch.stats or {})
                for field in ("accepted", "duplicates", "historical_input_events",
                              "live_input_events", "historical_ingest_seconds",
                              "live_ingest_seconds"):
                    stats[field] = round(
                        float(stats.get(field, 0)) + float(report.get(field, 0)), 3)
                batch.stats = stats
                batch.processed = end
                if end == len(events):
                    # Evaluate completed windows only after the full ordered
                    # batch has arrived. Otherwise a partial chunk might be
                    # marked evaluated before subsequent events are stored.
                    started = time.monotonic()
                    stats["network_findings_created"] = evaluate_windows(
                        db, clock=batch.ingestion_clock)
                    stats["evaluate_seconds"] = round(time.monotonic() - started, 3)
                    batch.stats = stats
                    batch.status, batch.finished = "done", now()
                    batch.compressed_events = None
                set_state(db, "analysis_cursor", {
                    "batch_id": batch_id, "processed": end,
                    "total": len(events), "at": now(),
                    "status": batch.status,
                })
        if progress:
            progress("analysis-batch-complete", {
                "processed": len(events), "total": len(events)})
        LOG.info("Analyzed batch %s events=%d", batch_id[:12], len(events))
        return True
    except Exception as exc:
        LOG.exception("Analysis batch failed; committed chunks are retained")
        # An interrupted transaction always leaves the last committed offset
        # unchanged, so operator retry can resume safely.
        with transaction(engine) as db:
            batch = db.get(StagedBatch, batch_id)
            if batch and batch.status == "pending":
                batch.status = "failed"
                batch.attempts += 1
                batch.last_error = type(exc).__name__ + ": inspect local worker logs"
                set_state(db, "analysis_cursor", {
                    "batch_id": batch_id, "processed": batch.processed,
                    "total": batch.event_count, "at": now(), "status": "failed"})
        return False


def retry_failed_batch(db, batch_id):
    batch = db.get(StagedBatch, batch_id)
    if not batch or batch.status != "failed":
        raise ValueError("Only a failed staged analysis batch can be retried")
    if batch.compressed_events is None:
        raise ValueError("Cannot retry a staged batch with no retained payload")
    batch.status, batch.last_error = "pending", ""


def prune_finished_batches(db, clock=None):
    clock = now() if clock is None else clock
    return db.execute(
        delete(StagedBatch)
        .where(StagedBatch.status == "done",
               StagedBatch.finished < clock - DONE_BATCH_DAYS * 86400)
    ).rowcount
