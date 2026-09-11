"""Relational state. Bounded metadata rather than a permanent raw-log archive."""
import time
import uuid
from contextlib import contextmanager
from sqlalchemy import (create_engine, event, Column, String, Integer, BigInteger,
                        Float, Boolean, JSON, Text, Index, ForeignKey, select)
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from .config import Policy


def now():
    return time.time()


def uid():
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    pass


class State(Base):
    __tablename__ = "state"
    key = Column(String(80), primary_key=True)
    value = Column(JSON, nullable=False)


class User(Base):
    __tablename__ = "users"
    id = Column(String(32), primary_key=True, default=uid)
    username = Column(String(80), unique=True, nullable=False)
    password = Column(Text, nullable=False)
    role = Column(String(16), nullable=False, default="analyst")
    active = Column(Boolean, nullable=False, default=True)


class LoginSession(Base):
    __tablename__ = "sessions"
    key = Column(String(64), primary_key=True)
    user_id = Column(String(32), ForeignKey("users.id"), nullable=False)
    expires = Column(Float, nullable=False, index=True)


class Source(Base):
    __tablename__ = "sources"
    id = Column(String(32), primary_key=True, default=uid)
    name = Column(String(100), nullable=False)
    namespace = Column(String(80), nullable=False, default="default")
    kind = Column(String(16), nullable=False, default="splunk")
    enabled = Column(Boolean, nullable=False, default=False)
    config = Column(JSON, nullable=False, default=dict)
    credential = Column(Text, nullable=False, default="")
    checkpoint = Column(BigInteger, nullable=True)
    last_poll = Column(Float, nullable=False, default=0)
    last_success = Column(Float, nullable=False, default=0)
    last_error = Column(Text, nullable=False, default="")


class Job(Base):
    __tablename__ = "jobs"
    id = Column(String(32), primary_key=True, default=uid)
    kind = Column(String(24), nullable=False)
    source_id = Column(String(32), ForeignKey("sources.id"), nullable=True)
    status = Column(String(12), nullable=False, default="queued", index=True)
    created = Column(Float, nullable=False, default=now)
    started = Column(Float, nullable=False, default=0)
    finished = Column(Float, nullable=False, default=0)
    payload = Column(JSON, nullable=False, default=dict)
    report = Column(JSON, nullable=False, default=dict)
    error = Column(Text, nullable=False, default="")


class Host(Base):
    __tablename__ = "hosts"
    id = Column(String(32), primary_key=True)
    name = Column(String(255), nullable=False, index=True)
    namespace = Column(String(80), nullable=False, index=True)
    cohort = Column(String(80), nullable=False, default="unassigned", index=True)
    first_seen = Column(Float, nullable=False)
    last_seen = Column(Float, nullable=False, index=True)


class Coverage(Base):
    __tablename__ = "coverage"
    id = Column(String(64), primary_key=True)
    host_id = Column(String(32), ForeignKey("hosts.id"), nullable=False, index=True)
    day = Column(Integer, nullable=False, index=True)
    event_id = Column(Integer, nullable=False)
    count = Column(BigInteger, nullable=False, default=0)


class Seen(Base):
    __tablename__ = "event_receipts"
    id = Column(String(64), primary_key=True)
    namespace = Column(String(80), nullable=False, default="default", index=True)
    received = Column(Float, nullable=False, index=True)


class BatchReceipt(Base):
    __tablename__ = "batch_receipts"
    id = Column(String(64), primary_key=True)
    namespace = Column(String(80), nullable=False, default="default", index=True)
    received = Column(Float, nullable=False, index=True)


class Process(Base):
    __tablename__ = "process_contexts"
    id = Column(String(64), primary_key=True)
    host_id = Column(String(32), ForeignKey("hosts.id"), nullable=False, index=True)
    guid = Column(String(40), nullable=False)
    created = Column(Float, nullable=True)
    last_seen = Column(Float, nullable=False, index=True)
    app = Column(String(255), nullable=False, default="unknown")
    location = Column(String(32), nullable=False, default="unknown")
    context = Column(String(64), nullable=False, default="")
    metadata_json = Column(JSON, nullable=False, default=dict)
    network = Column(JSON, nullable=False, default=dict)


class BehaviorDay(Base):
    __tablename__ = "behavior_days"
    id = Column(String(64), primary_key=True)
    host_id = Column(String(32), ForeignKey("hosts.id"), nullable=False)
    day = Column(Integer, nullable=False, index=True)
    context = Column(String(64), nullable=False)
    app = Column(String(255), nullable=False)
    parent = Column(String(255), nullable=False)
    location = Column(String(32), nullable=False)
    count = Column(BigInteger, nullable=False, default=0)
    first_seen = Column(Float, nullable=False)
    last_seen = Column(Float, nullable=False)
    sample = Column(JSON, nullable=False, default=dict)
    __table_args__ = (Index("ix_behavior_host_day", "host_id", "day"),
                      Index("ix_behavior_context_day", "context", "day"),
                      Index("ix_behavior_app_day", "app", "day"))


class Window(Base):
    __tablename__ = "network_windows"
    id = Column(String(64), primary_key=True)
    host_id = Column(String(32), ForeignKey("hosts.id"), nullable=False)
    start = Column(BigInteger, nullable=False, index=True)
    app = Column(String(255), nullable=False)
    location = Column(String(32), nullable=False)
    kind = Column(String(8), nullable=False)
    count = Column(BigInteger, nullable=False, default=0)
    sketch = Column(Text, nullable=False, default="")
    distinct_count = Column(Integer, nullable=False, default=0)
    samples = Column(JSON, nullable=False, default=list)
    evaluated = Column(Boolean, nullable=False, default=False)
    reference_ok = Column(Boolean, nullable=False, default=True)
    __table_args__ = (Index("ix_window_reference", "host_id", "app", "location", "kind", "start"),)


class Finding(Base):
    __tablename__ = "findings"
    id = Column(String(32), primary_key=True, default=uid)
    active_key = Column(String(64), nullable=True, unique=True)
    host_id = Column(String(32), ForeignKey("hosts.id"), nullable=False, index=True)
    detector = Column(String(32), nullable=False)
    context = Column(String(64), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    summary = Column(Text, nullable=False)
    priority = Column(String(12), nullable=False, default="review")
    state = Column(String(24), nullable=False, default="new", index=True)
    first_seen = Column(Float, nullable=False)
    last_seen = Column(Float, nullable=False, index=True)
    created = Column(Float, nullable=False, default=now)
    closed = Column(Float, nullable=True)
    occurrences = Column(Integer, nullable=False, default=1)
    evidence = Column(JSON, nullable=False)


class Expectation(Base):
    __tablename__ = "expectations"
    id = Column(String(32), primary_key=True, default=uid)
    host_id = Column(String(32), ForeignKey("hosts.id"), nullable=False)
    detector = Column(String(32), nullable=False)
    context = Column(String(64), nullable=False)
    reason = Column(Text, nullable=False)
    owner = Column(String(80), nullable=False)
    expires = Column(Float, nullable=False, index=True)
    revoked = Column(Boolean, nullable=False, default=False)
    created = Column(Float, nullable=False, default=now)


class Audit(Base):
    __tablename__ = "audit"
    id = Column(String(32), primary_key=True, default=uid)
    created = Column(Float, nullable=False, default=now, index=True)
    actor = Column(String(80), nullable=False)
    action = Column(String(80), nullable=False)
    target = Column(String(100), nullable=False)
    detail = Column(Text, nullable=False, default="")


def make_engine(config):
    config.data_dir.mkdir(parents=True, exist_ok=True)
    url = config.url()
    kwargs = {"pool_pre_ping": True}
    if str(url).startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
    engine = create_engine(url, **kwargs)
    if engine.dialect.name == "sqlite":
        @event.listens_for(engine, "connect")
        def pragmas(conn, _):
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA journal_mode=WAL")
    return engine


def initialize(engine):
    # Fresh schema v1 only. Unknown versions are refused, not silently upgraded.
    Base.metadata.create_all(engine)
    with sessionmaker(engine).begin() as db:
        version = db.get(State, "schema_version")
        if version and version.value != 1:
            raise RuntimeError("Unsupported schema; run the documented migration first")
        if not version:
            db.add(State(key="schema_version", value=1))
        if not db.get(State, "policy"):
            db.add(State(key="policy", value=Policy().model_dump()))


def policy(db):
    row = db.get(State, "policy")
    return Policy.model_validate(row.value if row else {})


def set_state(db, key, value):
    row = db.get(State, key)
    if row:
        row.value = value
    else:
        db.add(State(key=key, value=value))


def audit(db, actor, action, target, detail=""):
    db.add(Audit(actor=actor, action=action, target=str(target), detail=detail[:2000]))


@contextmanager
def transaction(engine):
    with sessionmaker(engine, expire_on_commit=False).begin() as db:
        yield db
