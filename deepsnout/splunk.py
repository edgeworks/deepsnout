"""Read-only Splunk search adapter; not a direct Universal Forwarder receiver.

Bounded index-time slices, complete pagination, then transactional cursor commit.
"""
import ipaddress
import fnmatch
import json
import re
import ssl
import time
from urllib.parse import urlsplit, quote
import httpx
from pydantic import BaseModel, Field, field_validator
from .normalize import normalize, InvalidEvent, UnsupportedEvent


class SplunkSettings(BaseModel):
    url: str
    indexes: str
    sourcetype: str = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    computer_pattern: str = "*"
    default_cohort: str = "unassigned"
    auth_scheme: str = "Bearer"
    ca_pem: str = ""
    interval: int = Field(60, ge=15, le=3600)
    window: int = Field(60, ge=1, le=3600)
    lag: int = Field(60, ge=10, le=3600)
    lookback: int = Field(3600, ge=60, le=7776000)
    max_events: int = Field(20000, ge=100, le=100000)

    @field_validator("computer_pattern")
    @classmethod
    def computers(cls, value):
        value = value.strip().lower()
        if not re.fullmatch(r"[a-z0-9_.?*-]{1,255}", value):
            raise ValueError("Use a Computer hostname or simple * / ? wildcard pattern")
        return value

    @field_validator("default_cohort")
    @classmethod
    def cohort(cls, value):
        value = value.lower().strip()
        if not re.fullmatch(r"[a-z0-9_-]{1,80}", value):
            raise ValueError("Use a short cohort name containing letters, numbers, - or _")
        return value

    @field_validator("indexes")
    @classmethod
    def indices(cls, value):
        names = [v.strip() for v in value.split(",")]
        if not 1 <= len(names) <= 20 or any(not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]{0,100}", v) for v in names):
            raise ValueError("Supply 1-20 exact index names, separated by commas; no SPL")
        return ",".join(names)

    @field_validator("sourcetype")
    @classmethod
    def source_type(cls, value):
        if not re.fullmatch(r"[A-Za-z0-9_*:/.-]{1,200}", value):
            raise ValueError("Invalid sourcetype; only a name or wildcard pattern is accepted")
        return value

    @field_validator("auth_scheme")
    @classmethod
    def scheme(cls, value):
        if value not in {"Bearer", "Splunk"}:
            raise ValueError("Select Bearer token or Splunk session key")
        return value

    @field_validator("ca_pem")
    @classmethod
    def ca(cls, value):
        if len(value) > 64000:
            raise ValueError("CA bundle too large")
        if value.strip():
            try:
                ssl.create_default_context().load_verify_locations(cadata=value)
            except ssl.SSLError:
                raise ValueError("Invalid PEM CA certificate bundle") from None
        return value.strip()


def validate_url(url, allow_http=False):
    parsed = urlsplit(url.strip())
    if parsed.scheme not in ({"https", "http"} if allow_http else {"https"}):
        raise ValueError("Use HTTPS for the Splunk management API")
    if (not parsed.hostname or parsed.username or parsed.password or parsed.query
            or parsed.fragment or parsed.path not in {"", "/"}):
        raise ValueError("Use only an origin, for example https://splunk.example.org:8089")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None
    if address and (address.is_link_local or address.is_unspecified or address.is_multicast):
        raise ValueError("Link-local, unspecified and multicast connector addresses are not allowed")
    _ = parsed.port
    return url.strip().rstrip("/")


class SplunkError(RuntimeError):
    pass


class TooManyEvents(SplunkError):
    pass


def boolish(v):
    return str(v).lower() in {"1", "true"}


class SplunkClient:
    def __init__(self, settings, credential, *, allow_http=False, transport=None, sleep=time.sleep):
        self.settings = settings
        self.url = validate_url(settings.url, allow_http)
        context = ssl.create_default_context()
        if settings.ca_pem:
            context.load_verify_locations(cadata=settings.ca_pem)
        self.client = httpx.Client(base_url=self.url, verify=context,
            headers={"Authorization": settings.auth_scheme + " " + credential, "User-Agent": "DeepSnout/0.1"},
            timeout=httpx.Timeout(30, connect=10), follow_redirects=False, transport=transport)
        self.sleep = sleep

    def close(self):
        self.client.close()

    def request(self, method, path, data=None):
        kwargs = {"params": data} if method == "GET" else {"data": data}
        try:
            with self.client.stream(method, path, **kwargs) as response:
                if response.status_code >= 300:
                    raise SplunkError(f"Splunk returned HTTP {response.status_code}; verify URL, permissions, certificate and token")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > 16 * 1024 * 1024:
                        raise SplunkError("Splunk response exceeded 16 MiB; reduce the source window")
                if method == "DELETE":
                    return {}
                result = json.loads(body)
        except httpx.HTTPError:
            raise SplunkError("Splunk transport/TLS failure; verify reachability, CA trust and proxy settings") from None
        except (json.JSONDecodeError, UnicodeError, RecursionError):
            raise SplunkError("Splunk did not return valid JSON") from None
        if not isinstance(result, dict):
            raise SplunkError("Splunk returned an unexpected JSON structure")
        for message in result.get("messages", []):
            if isinstance(message, dict) and str(message.get("type", "")).upper() in {"ERROR", "FATAL", "WARN"}:
                raise SplunkError("Splunk returned a warning/error; inspect the job in Splunk before retrying")
        return result

    def test(self):
        response = self.request("GET", "/services/server/info", {"output_mode": "json"})
        if not response.get("entry"):
            raise SplunkError("Server-info response did not identify a Splunk server")
        content = response["entry"][0].get("content", {})
        return {"connection": "authenticated", "version": str(content.get("version", "unknown")),
                "note": "Server access verified; run Poll now to verify search permissions and parsing"}

    def query(self, start, end):
        cfg = self.settings
        indexes = " OR ".join(f'index="{v}"' for v in cfg.indexes.split(","))
        search = (f'search ({indexes}) sourcetype="{cfg.sourcetype}" '
            f'_index_earliest={start} _index_latest={end} '
            f'| where _indextime >= {start} AND _indextime < {end} '
            '| fields _raw _time _indextime index sourcetype source host splunk_server _cd')
        job = self.request("POST", "/services/search/jobs", {"search": search,
            "earliest_time": "0", "latest_time": "+10y", "output_mode": "json",
            "exec_mode": "normal", "max_count": str(cfg.max_events + 1)})
        sid = str(job.get("sid", ""))
        if not sid:
            raise SplunkError("Splunk did not return a search job ID")
        path = "/services/search/jobs/" + quote(sid, safe="")
        try:
            deadline = time.monotonic() + 150
            while True:
                response = self.request("GET", path, {"output_mode": "json"})
                entries = response.get("entry", [])
                if not entries:
                    raise SplunkError("Search job disappeared")
                status = entries[0].get("content", {})
                if boolish(status.get("isFailed")) or status.get("dispatchState") in {"FAILED", "BAD_INPUT", "INTERNAL_CANCEL"}:
                    raise SplunkError("Splunk search job failed")
                if boolish(status.get("isFinalized")):
                    raise SplunkError("Splunk search was finalized early; refusing potentially incomplete data")
                if boolish(status.get("isDone")) or status.get("dispatchState") == "DONE":
                    break
                if time.monotonic() >= deadline:
                    raise SplunkError("Splunk search timed out; checkpoint was not advanced")
                self.sleep(1)
            if "resultCount" not in status:
                raise SplunkError("Completed search did not report resultCount; refusing to advance")
            for message in status.get("messages", []):
                if isinstance(message, dict) and str(message.get("type", "")).upper() in {"WARN", "ERROR", "FATAL"}:
                    raise SplunkError("Search job reported incomplete/error conditions; inspect it in Splunk")
            count = int(status["resultCount"])
            if count < 0:
                raise SplunkError("Invalid resultCount")
            if count >= cfg.max_events:
                raise TooManyEvents("Slice exceeds result cap")
            events, report = [], {"received": count, "invalid": 0, "ignored": 0, "filtered_by_computer": 0, "errors": []}
            offset = 0
            while offset < count:
                if time.monotonic() >= deadline:
                    raise SplunkError("Result retrieval timed out; checkpoint was not advanced")
                page = self.request("GET", "/services/search/v2/jobs/" + quote(sid, safe="") + "/results",
                    {"output_mode": "json", "count": str(min(500, count - offset)), "offset": str(offset)})
                if boolish(page.get("preview", False)):
                    raise SplunkError("Preview results are not a complete search result")
                records = page.get("results", [])
                if not records or offset + len(records) > count:
                    raise SplunkError("Search pagination is incomplete or inconsistent; checkpoint not advanced")
                for index, row in enumerate(records):
                    try:
                        event = normalize(row)
                        if fnmatch.fnmatchcase(event.host, cfg.computer_pattern):
                            events.append(event)
                        else:
                            report["filtered_by_computer"] += 1
                    except UnsupportedEvent:
                        report["ignored"] += 1
                    except InvalidEvent as exc:
                        report["invalid"] += 1
                        if len(report["errors"]) < 20:
                            report["errors"].append({"row": offset + index + 1, "reason": str(exc)})
                offset += len(records)
            if report["invalid"]:
                raise SplunkError(f"{report['invalid']} malformed supported events in slice; "
                    + report["errors"][0]["reason"] + ". Checkpoint not advanced")
            return events, report
        finally:
            try:
                self.request("DELETE", path)
            except SplunkError:
                pass

    def slice(self, start, end):
        while True:
            try:
                events, report = self.query(start, end)
                return events, report, end
            except TooManyEvents:
                if end - start <= 1:
                    raise SplunkError("Even one indexed second exceeds the result cap; narrow source scope or raise the cap") from None
                end = start + max(1, (end - start) // 2)
