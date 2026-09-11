"""Small synthetic SQLite timing, NOT a fleet capacity benchmark. Run from root."""
import json
from pathlib import Path
import resource
import sys
import tempfile
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from deepsnout.config import Config
from deepsnout.db import make_engine,initialize,transaction,Seen,Process,Window,select,func
from deepsnout.engine import ingest
from deepsnout.normalize import normalize
from deepsnout.security import initialize_secrets


def run(count=5000,hosts=100):
    clock=int(time.time()); start=time.perf_counter(); events=[]
    for i in range(count):
        host=i%hosts
        kind=1 if i<hosts else 3 if i%2==0 else 22
        events.append(normalize({'EventID':kind,'Provider':'Microsoft-Windows-Sysmon',
            'Computer':f'bench-{host}.example','UtcTime':clock-1800+i/10,
            'Image':r'C:\Program Files\Browser\browser.exe','ParentImage':r'C:\Windows\explorer.exe',
            'ProcessGuid':f'00000000-0000-0000-0000-{host:012x}',
            'DestinationIp':f'8.8.{i//256%256}.{i%256}', 'DestinationPort':443,'Initiated':'true',
            'SourcePort':10000+i,'QueryName':f'service{i%250}.example','QueryStatus':0}))
    parsed=time.perf_counter()-start
    with tempfile.TemporaryDirectory() as directory:
        cfg=Config(data_dir=Path(directory)); initialize_secrets(cfg.data_dir)
        engine=make_engine(cfg); initialize(engine)
        start=time.perf_counter()
        with transaction(engine) as db: report=ingest(db,events,clock=clock)
        ingest_seconds=time.perf_counter()-start
        with transaction(engine) as db:
            rows={m.__tablename__:db.scalar(select(func.count()).select_from(m)) for m in [Seen,Process,Window]}
        engine.dispose()
        size=sum(p.stat().st_size for p in Path(directory).glob('*.db*'))
    return {'synthetic_events':count,'synthetic_hosts':hosts,'parse_seconds':round(parsed,3),
        'ingest_seconds':round(ingest_seconds,3),'ingest_events_per_second':round(count/ingest_seconds),
        'sqlite_bytes':size,'peak_process_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'rows':rows,'accepted':report['accepted'],
        'limits':'One short local synthetic run. No Splunk/network, PostgreSQL, long history, multi-user load or fleet capacity validation.'}

if __name__=='__main__':
    print(json.dumps(run(),indent=2))
