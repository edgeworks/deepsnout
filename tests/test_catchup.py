from sqlalchemy import select

from conftest import CLOCK, evt
from deepsnout.db import BehaviorDay, Job, Process, Source, State, transaction
from deepsnout.security import crypto
from deepsnout.splunk import SplunkSettings
from deepsnout.worker import enqueue, run_job


def _source(engine, config, checkpoint, profile="cribl_flat_sysmon"):
    with transaction(engine) as db:
        settings = SplunkSettings(
            url="https://splunk.example", indexes="wef", search_profile=profile)
        source = Source(
            name="Catchup", namespace="test", config=settings.model_dump(),
            credential=crypto(config).encrypt(b"TEST-TOKEN").decode(),
            checkpoint=checkpoint)
        db.add(source)
        db.flush()
        return source.id, enqueue(db, "poll", source_id=source.id).id


def test_optimized_catchup_batches_adjacent_slices(engine, config):
    source_id, job_id = _source(engine, config, CLOCK - 3600)
    calls = []

    class Client:
        def __init__(self, settings, *args, **kwargs):
            self.settings = settings
        def close(self):
            pass
        def slice(self, start, end):
            calls.append((start, end))
            number = len(calls)
            return [evt(n=100 + number, ts=CLOCK - 120)], {
                "received": 1000,
                "supported_parsed": 1,
                "cribl_adapter_supported": 1,
                "cribl_adapter_fraction": 1.0,
                "slice_attempts": 1,
                "requested_span": end - start,
                "effective_span": end - start,
                "index_time_start": start,
                "index_time_end": end,
                "search_profile": self.settings.search_profile,
            }, end

    assert run_job(engine, config, job_id, client_factory=Client)
    with transaction(engine) as db:
        job = db.get(Job, job_id)
        assert len(calls) == 4
        assert len(job.report["catchup_sub_slices"]) == 4
        assert job.report["index_seconds_processed"] > 60
        assert job.report["collection_seconds"] >= 0
        assert db.get(Source, source_id).checkpoint == calls[-1][1]


def test_historical_poll_skips_reference_queries_and_process_state(engine, config, monkeypatch):
    _, job_id = _source(engine, config, CLOCK - 3 * 86400)
    import deepsnout.engine as engine_module
    def unexpected_reference(*args, **kwargs):
        raise AssertionError("reference() must not run for historical catch-up")
    monkeypatch.setattr(engine_module, "reference", unexpected_reference)

    class Client:
        def __init__(self, settings, *args, **kwargs):
            self.settings = settings
        def close(self):
            pass
        def slice(self, start, end):
            return [evt(n=701, ts=CLOCK - 2 * 86400)], {
                "received": 1,
                "supported_parsed": 1,
                "cribl_adapter_supported": 1,
                "cribl_adapter_fraction": 1.0,
                "slice_attempts": 1,
                "requested_span": end - start,
                "effective_span": end - start,
                "index_time_start": start,
                "index_time_end": end,
                "search_profile": self.settings.search_profile,
            }, end

    assert run_job(engine, config, job_id, client_factory=Client)
    with transaction(engine) as db:
        job = db.get(Job, job_id)
        assert job.report["historical_fast_path"] == "reference-and-state-elision"
        assert job.report["historical_process_state_skipped"] >= 1
        assert job.report["historical_reference_queries_skipped"] >= 1
        assert job.report["window_evaluation_deferred"] is True
        assert job.report["ingest_seconds"] >= 0
        assert db.scalar(select(Process)) is None
        assert db.scalar(select(BehaviorDay)) is not None
