"""Synthetic fixtures only. Optional test DB is DESTRUCTIVELY reinitialized."""
from pathlib import Path
import os
import time
import pytest
from sqlalchemy import select, func
from deepsnout.config import Config
from deepsnout.db import Base, make_engine, initialize, transaction
from deepsnout.security import initialize_secrets
from deepsnout.normalize import normalize

CLOCK = int(time.time())
DAY = 86400
DAY_START = CLOCK // DAY * DAY


def raw_event(eid=1, *, ts=None, n=1, host="workstation.example", **fields):
    row = {"Provider": "Microsoft-Windows-Sysmon", "EventID": eid,
        "Computer": host, "UtcTime": ts or CLOCK - 60,
        "ProcessGuid": f"00000000-0000-0000-0000-{n:012x}",
        "Image": r"C:\Program Files\Utility\utility.exe", "ParentImage": r"C:\Windows\explorer.exe",
        "CommandLine": "utility.exe", "Hashes": "SHA256=" + "a" * 64}
    if eid == 3:
        row.update(DestinationIp="8.8.8.8",DestinationPort="443",Protocol="tcp",Initiated="true")
    if eid == 22:
        row.update(QueryName="api.example.com", QueryStatus="0")
    row.update(fields)
    return row


def evt(eid=1, **kwargs):
    return normalize(raw_event(eid, **kwargs))


def baseline(host="workstation.example", days=8):
    return [evt(ts=DAY_START-d*DAY+3600,n=100+d,host=host) for d in range(1,days+1)]


@pytest.fixture
def config(tmp_path):
    return Config(data_dir=tmp_path, database_url=os.getenv("DEEPSNOUT_TEST_DATABASE_URL", ""),
        allowed_hosts="testserver,localhost,127.0.0.1", allow_http_connectors=True)


@pytest.fixture
def engine(config):
    initialize_secrets(config.data_dir)
    engine = make_engine(config)
    if config.database_url:
        Base.metadata.drop_all(engine)
    initialize(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db(engine):
    with transaction(engine) as session:
        yield session


def count(db, model):
    return db.scalar(select(func.count()).select_from(model))
