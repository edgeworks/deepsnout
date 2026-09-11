"""Deployment configuration and validated, GUI-editable analysis policy."""
from dataclasses import dataclass, field
from pathlib import Path
import os
from pydantic import BaseModel, Field, model_validator


class Policy(BaseModel):
    baseline_days: int = Field(28, ge=7, le=90)
    minimum_days: int = Field(7, ge=2, le=28)
    minimum_peer_hosts: int = Field(10, ge=3, le=1000)
    peer_common_fraction: float = Field(0.1, ge=0.01, le=1)
    network_factor: float = Field(4.0, ge=2, le=20)
    network_floor: int = Field(30, ge=10, le=10000)
    process_days: int = Field(7, ge=1, le=30)
    closed_finding_days: int = Field(90, ge=7, le=730)
    dedup_hours: int = Field(48, ge=6, le=168)
    maximum_receipts: int = Field(2000000, ge=10000, le=100000000)
    maximum_contexts_per_host_day: int = Field(2000, ge=50, le=100000)
    execution_enabled: bool = True
    contextual_enabled: bool = True
    network_enabled: bool = True

    @model_validator(mode="after")
    def check_window(self):
        if self.minimum_days > self.baseline_days:
            raise ValueError("Minimum observed days must fit within the reference window")
        return self


@dataclass
class Config:
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("DEEPSNOUT_DATA_DIR", "./data")))
    database_url: str = field(default_factory=lambda: os.getenv("DATABASE_URL", ""))
    secure_cookies: bool = field(default_factory=lambda: os.getenv("DEEPSNOUT_SECURE_COOKIES", "0") == "1")
    allowed_hosts: str = field(default_factory=lambda: os.getenv("DEEPSNOUT_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]"))
    allow_http_connectors: bool = field(default_factory=lambda: os.getenv("DEEPSNOUT_ALLOW_HTTP_CONNECTORS", "0") == "1")
    maximum_body: int = 10 * 1024 * 1024
    maximum_import_events: int = 5000
    session_seconds: int = 8 * 3600

    def url(self):
        if self.database_url:
            return self.database_url
        if os.getenv("DEEPSNOUT_POSTGRES_HOST"):
            from sqlalchemy import URL
            return URL.create("postgresql+psycopg", username="deepsnout",
                              password=(self.data_dir / "db_password").read_text().strip(),
                              host=os.environ["DEEPSNOUT_POSTGRES_HOST"], database="deepsnout")
        return "sqlite:///" + str((self.data_dir / "deepsnout.db").resolve())
