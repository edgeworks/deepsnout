"""Relational state. Bounded metadata rather than a permanent raw-log archive."""
import time
import uuid
from contextlib import contextmanager
from sqlalchemy import (create_engine, event, Column, String, Integer, BigInteger,
                        Float, Boolean, JSON, Text, Index, ForeignKey, LargeBinary, select,
                        update, inspect, text)
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


class StagedBatch(Base):
    """Private, bounded and resumable normalized-observation handoff.

    Collection commits this compressed batch with its Splunk cursor. Analysis
    processes bounded chunks with a separate offset. Only finished batches
    discard payload bytes; a failed batch remains available for explicit retry.
    """
    __tablename__ = "staged_batches"
    id = Column(String(64), primary_key=True)
    source_id = Column(String(32), nullable=True)
    namespace = Column(String(80), nullable=False)
    cohort = Column(String(80), nullable=False, default="unassigned")
    collected_at = Column(Float, nullable=False)
    ingestion_clock = Column(Float, nullable=False)
    # Four stable host partitions; every host stays in the same shard.
    shard = Column(Integer, nullable=False, default=0)
    lane = Column(String(12), nullable=False, default="backfill")
    batch_parent = Column(String(64), nullable=False, default="")
    store_bytes = Column(BigInteger, nullable=False, default=0)
    event_count = Column(Integer, nullable=False)
    processed = Column(Integer, nullable=False, default=0)
    compressed_events = Column(LargeBinary, nullable=True)
    content_sha256 = Column(String(64), nullable=False)
    status = Column(String(16), nullable=False, default="pending")
    last_error = Column(String(300), nullable=False, default="")
    stats = Column(JSON, nullable=False, default=dict)
    attempts = Column(Integer, nullable=False, default=0)
    finished = Column(Float, nullable=False, default=0)
    __table_args__ = (
        Index("ix_staged_batch_queue", "status", "collected_at"),
        Index("ix_staged_lane_shard_queue", "shard", "lane", "status", "collected_at"),
        Index("ix_staged_parent", "batch_parent"),
    )


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


SCHEMA_VERSION = 3


def migrate_v2(engine, recover_interrupted=False):
    """Explicit v1 -> v2 migration. Stop worker containers and back up first.

    A separate transaction installs the new table and updates the schema
    marker together. Re-running on v2 is safe. v1 sources/findings remain.
    """
    with engine.begin() as conn:
        if not inspect(conn).has_table("state"):
            raise RuntimeError("No existing database schema; run deepsnout init")
        version = conn.execute(
            select(State.value).where(State.key == "schema_version")).scalar_one_or_none()
        if version == 2:
            return "Schema is already v2"
        if version != 1:
            raise RuntimeError("Expected existing schema v1; refusing unknown version")
        if conn.dialect.name == "postgresql":
            # The old worker owns this advisory lock for its whole lifetime.
            # Do not permit the migration while it is still running.
            if not conn.scalar(text("SELECT pg_try_advisory_xact_lock(174220601)")):
                raise RuntimeError("Old analysis worker is still active; stop it before migrating")
        active = conn.execute(
            select(Job.id).where(Job.status.in_(("running", "cancel_requested")))
            .limit(1)).first()
        if active and not recover_interrupted:
            raise RuntimeError(
                "Interrupted jobs remain. Stop the old worker, then rerun "
                "'deepsnout migrate-v2 --recover-interrupted'. This marks "
                "unfinished jobs failed but does not move Splunk checkpoints.")
        if active:
            conn.execute(
                update(Job).where(Job.status.in_(("running", "cancel_requested")))
                .values(status="failed", finished=now(),
                        error="Interrupted by explicit v2 upgrade; source checkpoint not advanced"))
        # v1->v2 must create the original v2 schema, not a future v3 table.
        # The schema-v3 upgrade below performs the new column additions.
        original = StagedBatch.__table__
        legacy = original.to_metadata(
            __import__("sqlalchemy").MetaData(),
            name="staged_batches")
        for name in ("shard", "lane", "batch_parent", "store_bytes"):
            legacy._columns.remove(legacy.c[name])
        legacy.create(conn, checkfirst=True)
        conn.execute(update(State).where(State.key == "schema_version").values(value=2))
    return "Migrated schema v1 to v2"


def migrate_v3(engine):
    """Explicit v2 -> v3 upgrade. Stop workers and back up DB/secrets first.

    Existing staged events remain on shard 0, in the catch-up lane, with
    their original compressed bytes intact. The upgrade never discards data.
    """
    with engine.begin() as conn:
        if not inspect(conn).has_table("state"):
            raise RuntimeError("No database; run deepsnout init")
        version = conn.execute(
            select(State.value).where(State.key == "schema_version")).scalar_one_or_none()
        if version == 3:
            return "Schema is already v3"
        if version != 2:
            raise RuntimeError("Expected schema v2; upgrade v1 to v2 first")
        if conn.dialect.name == "postgresql":
            for key in (174220601, 174220602, 174220603, 174220611, 174220612):
                if not conn.scalar(text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": key}):
                    raise RuntimeError("Worker still running; stop all workers before migration")
        columns = {col["name"] for col in inspect(conn).get_columns("staged_batches")}
        additions = {
            "shard": "INTEGER NOT NULL DEFAULT 0",
            "lane": "VARCHAR(12) NOT NULL DEFAULT 'backfill'",
            "batch_parent": "VARCHAR(64) NOT NULL DEFAULT ''",
            "store_bytes": "BIGINT NOT NULL DEFAULT 0",
        }
        for name, sql_type in additions.items():
            if name not in columns:
                conn.exec_driver_sql(
                    "ALTER TABLE staged_batches ADD COLUMN " + name + " " + sql_type)
        conn.exec_driver_sql(
            "UPDATE staged_batches SET batch_parent = id WHERE batch_parent = ''")
        size_func = "octet_length" if conn.dialect.name == "postgresql" else "length"
        conn.exec_driver_sql(
            "UPDATE staged_batches SET store_bytes = " +
            size_func + "(compressed_events) WHERE compressed_events IS NOT NULL")
        for idx in StagedBatch.__table__.indexes:
            idx.create(conn, checkfirst=True)
        conn.execute(update(State).where(State.key == "schema_version").values(value=3))
    return "Migrated schema v2 to v3"


def initialize(engine):
    # Check the deployed schema BEFORE creating new tables on an existing DB.
    if inspect(engine).has_table("state"):
        with sessionmaker(engine).begin() as db:
            version = db.get(State, "schema_version")
            if not version or version.value != SCHEMA_VERSION:
                raise RuntimeError(
                    "Database schema upgrade required. Back up PostgreSQL and secrets, "
                    "stop all workers, then run 'deepsnout migrate-v3'.")
    Base.metadata.create_all(engine)
    with sessionmaker(engine).begin() as db:
        if not db.get(State, "schema_version"):
            db.add(State(key="schema_version", value=SCHEMA_VERSION))
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
