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