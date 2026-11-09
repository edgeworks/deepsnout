from sqlalchemy import select
from conftest import evt,CLOCK,count
from deepsnout.db import transaction,Job,Source,Seen,Host,State,policy,set_state
from deepsnout.worker import enqueue,run_job,worker_lock,_next_slice_span
from deepsnout.security import crypto
from deepsnout.splunk import SplunkSettings,SplunkError


class Client:
    def __init__(self,*args,**kwargs): pass
    def close(self): pass
    def slice(self,start,end): return [evt()],{'received':1},end
    def test(self): return {'connection':'authenticated'}


def source_job(engine,config):
    with transaction(engine) as db:
        source=Source(name='Test',namespace='test',config=SplunkSettings(url='https://splunk.example',indexes='wef').model_dump(),
            credential=crypto(config).encrypt(b'TEST-TOKEN').decode(),checkpoint=CLOCK-600)
        db.add(source); db.flush()
        return source.id,enqueue(db,'poll',source_id=source.id).id


def test_adaptive_span_targets_result_headroom():
    assert _next_slice_span(60,900,1000,20000,1)==120
    assert _next_slice_span(15,900,17800,20000,3)==10
    assert _next_slice_span(900,900,13000,20000,1)==900


def test_auto_profile_learns_cribl_and_uses_it_next_poll(engine,config):
    sid,jid=source_job(engine,config)
    profiles=[]
    class ProfileClient(Client):
        def __init__(self,settings,*args,**kwargs):
            self.settings=settings
            profiles.append(settings.search_profile)
        def slice(self,start,end):
            return [evt()],{
                'received':1000,'supported_parsed':100,'cribl_adapter_supported':99,
                'cribl_adapter_fraction':0.99,'slice_attempts':1,
                'requested_span':end-start,'effective_span':end-start,
                'search_profile':self.settings.search_profile,
            },end
    assert run_job(engine,config,jid,client_factory=ProfileClient)
    with transaction(engine) as db:
        tuning=db.get(State,'splunk_tuning:'+sid).value
        assert tuning['detected_profile']=='cribl_flat_sysmon'
        jid2=enqueue(db,'poll',source_id=sid).id
    assert run_job(engine,config,jid2,client_factory=ProfileClient)
    with transaction(engine) as db:
        report=db.get(Job,jid2).report
        assert report['effective_search_profile']=='cribl_flat_sysmon'
    assert profiles==['broad','cribl_flat_sysmon']


def test_cursor_and_observation_atomic(engine,config):
    sid,jid=source_job(engine,config)
    assert run_job(engine,config,jid,client_factory=Client)
    with transaction(engine) as db:
        assert db.get(Source,sid).checkpoint==CLOCK-540 and count(db,Seen)==1 and db.get(Job,jid).status=='done'


def test_remote_failure_does_not_advance(engine,config):
    sid,jid=source_job(engine,config)
    class Broken(Client):
        def slice(self,*_): raise SplunkError('Search incomplete')
    assert not run_job(engine,config,jid,client_factory=Broken)
    with transaction(engine) as db:
        assert db.get(Source,sid).checkpoint==CLOCK-600 and count(db,Seen)==0 and db.get(Job,jid).status=='failed'


def test_parser_failure_report_is_persisted(engine,config):
    sid,jid=source_job(engine,config)
    diagnostic={'invalid':42,'errors':[{'row':7,'reason':'Invalid event id','diagnostic':{'selected_candidate':{'cleaned':'bad'}}}]}
    class Broken(Client):
        def slice(self,*_): raise SplunkError('Detailed diagnostics are in the failed job Result',report=diagnostic)
    assert not run_job(engine,config,jid,client_factory=Broken)
    with transaction(engine) as db:
        job=db.get(Job,jid)
        assert job.status=='failed' and job.report==diagnostic
        assert db.get(Source,sid).checkpoint==CLOCK-600
        assert db.get(Source,sid).last_error.startswith('Detailed diagnostics')


def test_capacity_failure_does_not_advance(engine,config):
    sid,jid=source_job(engine,config)
    with transaction(engine) as db:
        cfg=policy(db); cfg.maximum_receipts=10000; set_state(db,'policy',cfg.model_dump())
    class Huge(Client):
        def slice(self,start,end): return [evt()]*10001,{},end
    assert not run_job(engine,config,jid,client_factory=Huge)
    with transaction(engine) as db:
        assert db.get(Source,sid).checkpoint==CLOCK-600 and count(db,Seen)==0


def test_queue_bound_and_coalescing(db):
    import pytest
    source=Source(name='test',config={}); db.add(source); db.flush()
    a=enqueue(db,'test',source_id=source.id)
    assert a.id==enqueue(db,'poll',source_id=source.id).id
    for i in range(19): enqueue(db,'maintenance')
    with pytest.raises(ValueError): enqueue(db,'demo')


def test_demo_removal_scoped_and_reloadable(engine,config):
    from deepsnout.engine import ingest
    with transaction(engine) as db: ingest(db,[evt()],namespace='production')
    for kind in ['demo','remove_demo','demo']:
        with transaction(engine) as db: jid=enqueue(db,kind).id
        assert run_job(engine,config,jid)
        with transaction(engine) as db:
            assert db.scalar(select(Host).where(Host.namespace=='production'))
            n=len(db.scalars(select(Host).where(Host.namespace=='demo')).all())
            assert (n==0) if kind=='remove_demo' else (n>0)


def test_single_writer(engine,config):
    import pytest
    with worker_lock(engine,config):
        with pytest.raises(RuntimeError):
            with worker_lock(engine,config): pass


def test_finding_quality_job_is_coalesced_and_periodic_when_not_catching_up(engine, config):
    from deepsnout.db import now
    from deepsnout.worker import tick
    stamp = now()
    with transaction(engine) as db:
        host = Host(id="quality-scheduler-host", name="schedule.example",
                    namespace="test", cohort="unassigned",
                    first_seen=stamp-120, last_seen=stamp)
        db.add(host)
        db.flush()
        from deepsnout.db import Finding
        db.add(Finding(
            host_id=host.id, detector="DS-BEH-001",
            context="test-context", title="Synthetic", summary="Synthetic",
            priority="review", state="new", first_seen=stamp-10,
            last_seen=stamp-10, created=stamp-10,
            evidence={"process": {"parent": "service.exe", "image": "test.exe",
                                  "location": "other"}}))
        # Skip costly unrelated peer discovery during the isolated scheduler test.
        set_state(db, "peer_group_last_attempt", {"at": stamp})
    # tick schedules and executes a normal, local finding-quality job.
    assert tick(engine, config)
    with transaction(engine) as db:
        jobs = list(db.scalars(select(Job).where(Job.kind == "finding_quality")))
        assert len(jobs) == 1 and jobs[0].status == "done"
        snapshot = db.get(State, "finding_quality_snapshot").value
        assert snapshot["source_findings"] == 1
        attempt = db.get(State, "finding_quality_last_attempt").value
        assert attempt["at"] > 0
    # A second tick inside the hour cannot schedule another duplicate job.
    tick(engine, config)
    with transaction(engine) as db:
        assert len(list(db.scalars(select(Job).where(Job.kind == "finding_quality")))) == 1


def test_finding_quality_queue_coalesces_duplicate_operator_requests(db):
    first = enqueue(db, "finding_quality", {"origin": "operator"})
    second = enqueue(db, "finding_quality", {"origin": "operator"})
    assert first.id == second.id
    assert db.get(State, "finding_quality_last_attempt").value["job_id"] == first.id


def test_mixed_age_events_take_both_paths_and_keep_one_receipt(db):
    """Mixed age must not send yesterday's backfill through live references."""
    from conftest import DAY
    from deepsnout.worker import ingest_age_partitioned
    from deepsnout.db import BatchReceipt, Process, Finding
    from deepsnout.engine import host_key
    observations = [
        evt(ts=CLOCK-60, n=993, Image=r"C:\Temp\recent-tool.exe"),
        evt(ts=CLOCK-3*DAY, n=991),
        evt(3, ts=CLOCK-35, n=993, Image=r"C:\Temp\recent-tool.exe"),
        evt(ts=CLOCK-2*DAY, n=992),
    ]
    progress = []
    result = ingest_age_partitioned(
        db, observations, namespace="test", batch_id="test-mixed",
        clock=CLOCK,
        progress=lambda stage, details: progress.append((stage, details["processed"])))
    assert result["age_partition"] == "mixed"
    assert result["accepted"] == 4
    assert result["historical_input_events"] == 2
    assert result["live_input_events"] == 2
    assert result["historical_process_state_skipped"] == 2
    assert result["behavioral_pipeline"]["event1_historical_batch"] == 2
    assert result["behavioral_pipeline"]["event1_recent"] == 1
    assert result["historical_reference_queries_skipped"] == 2
    assert count(db, BatchReceipt) == 1 and count(db, Seen) == 4
    assert progress[0] == ("ingest-historical", 0)
    assert progress[-1] == ("ingest-live", 2)
    live = db.scalar(select(Process).where(Process.guid == observations[0].guid))
    assert live.metadata_json["reference"]["prior_observed_days"] == 2
    assert count(db, Process) == 1
    stored = db.get(State, "last_ingest").value
    assert stored["accepted"] == 4
    assert stored["age_partition"] == "mixed"
    # Whole-slice idempotency is preserved, even across the age boundary.
    replay = ingest_age_partitioned(
        db, observations, namespace="test", batch_id="test-mixed", clock=CLOCK)
    assert replay["batch_replay"]
    assert replay["accepted"] == 0 and replay["duplicates"] == 4
    assert count(db, Seen) == 4 and count(db, BatchReceipt) == 1
    assert count(db, Finding) == 0


def test_mixed_age_failure_rolls_back_both_halves_and_receipt(engine, monkeypatch):
    import pytest
    from conftest import DAY
    import deepsnout.worker as worker
    from deepsnout.db import BatchReceipt, Coverage, BehaviorDay
    events = [evt(n=997, ts=CLOCK-2*DAY), evt(n=998, ts=CLOCK-20)]
    original = worker.ingest

    def fail_live(*args, **kwargs):
        if not kwargs["historical"]:
            raise ValueError("Synthetic failure in live suffix")
        return original(*args, **kwargs)

    monkeypatch.setattr(worker, "ingest", fail_live)
    with pytest.raises(ValueError, match="Synthetic failure"):
        with transaction(engine) as db:
            worker.ingest_age_partitioned(
                db, events, namespace="test", batch_id="failed-mixed", clock=CLOCK)
    with transaction(engine) as db:
        assert count(db, Seen) == 0
        assert count(db, Coverage) == 0
        assert count(db, BehaviorDay) == 0
        assert count(db, BatchReceipt) == 0
        assert db.get(State, "last_ingest") is None


def test_mixed_age_splunk_poll_commits_checkpoint_and_job_report(engine, config):
    from conftest import DAY
    from deepsnout.db import BatchReceipt
    sid, jid = source_job(engine, config)
    class Mixed(Client):
        def slice(self, start, end):
            return [evt(n=871, ts=CLOCK-2*DAY),
                    evt(n=872, ts=CLOCK-55),
                    evt(3, n=872, ts=CLOCK-35)], {"received": 3}, end

    assert run_job(engine, config, jid, client_factory=Mixed)
    with transaction(engine) as db:
        job = db.get(Job, jid)
        report = job.report
        assert db.get(Source, sid).checkpoint == CLOCK-540
        assert job.status == "done"
        assert report["age_partition"] == "mixed"
        assert report["accepted"] == 3
        assert report["historical_input_events"] == 1
        assert report["live_input_events"] == 2
        assert report["behavioral_pipeline"]["event1_historical_batch"] == 1
        assert report["behavioral_pipeline"]["event1_recent"] == 1
        assert report["historical_ingest_seconds"] >= 0
        assert report["live_ingest_seconds"] >= 0
        assert report["ingest_seconds"] >= 0
        assert count(db, BatchReceipt) == 1


def test_uniform_historical_poll_keeps_fast_path_and_batch_receipt(engine, config):
    from conftest import DAY
    from deepsnout.db import BatchReceipt, Process
    sid, jid = source_job(engine, config)

    class Older(Client):
        def slice(self, start, end):
            return [evt(n=901, ts=CLOCK-3*DAY),
                    evt(n=902, ts=CLOCK-2*DAY)], {"received": 2}, end

    assert run_job(engine, config, jid, client_factory=Older)
    with transaction(engine) as db:
        report = db.get(Job, jid).report
        assert report["age_partition"] == "historical-only"
        assert report["historical_fast_path"] == "reference-and-state-elision"
        assert report["historical_input_events"] == 2
        assert report["live_input_events"] == 0
        assert report["window_evaluation_deferred"] is True
        assert count(db, Process) == 0
        assert count(db, Seen) == 2
        assert count(db, BatchReceipt) == 1
