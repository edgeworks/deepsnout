"""Safe standard Sysmon normalization; full command lines are never persisted."""
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import ntpath
import re
from defusedxml import ElementTree as ET

VERSION = "sysmon-v1"
SUPPORTED = {1, 3, 22}
GUID = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"


class InvalidEvent(ValueError):
    pass


class UnsupportedEvent(InvalidEvent):
    pass


def load_json(text, maximum_depth=64):
    """Bound nesting explicitly, independent of the interpreter recursion limit."""
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > maximum_depth:
                raise InvalidEvent(f"JSON nesting exceeds {maximum_depth} levels")
        elif char in "]}":
            depth -= 1
    return json.loads(text)


def digest(*values):
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True).encode()).hexdigest()


def scalar(value):
    if isinstance(value, dict):
        return value.get("#text", value.get("text", value.get("value", "")))
    if isinstance(value, list):
        return scalar(value[0]) if value else ""
    return value


def timestamp(value):
    try:
        if isinstance(value, (int, float)) or re.fullmatch(r"\d{10}(?:\.\d+)?", str(value)):
            return float(value)
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        return dt.replace(tzinfo=timezone.utc).timestamp() if dt.tzinfo is None else dt.timestamp()
    except (ValueError, TypeError, OverflowError):
        raise InvalidEvent("Missing or invalid original event timestamp") from None


def location(image):
    p = image.lower().replace("/", "\\")
    if p.startswith("\\\\"):
        return "network-share"
    if "\\temp\\" in p or "\\tmp\\" in p:
        return "temporary"
    if "\\downloads\\" in p:
        return "downloads"
    if "\\users\\" in p or "\\appdata\\" in p:
        return "user-profile"
    if "\\windows\\" in p:
        return "windows"
    if "\\program files" in p:
        return "program-files"
    return "other" if p else "unknown"


def redact_path(image):
    return re.sub(r"(?i)(\\users\\)[^\\]+", lambda m: m[1] + "<user>", image)[:1024]


def command_features(command, app):
    text = command.lower()[:32768]
    remote = bool(re.search(r"https?://", text))
    encoded = bool(re.search(r"(?:^|\s)-(?:e|en|enc|enco|encodedcommand)\s+\S+", text))
    download = bool(re.search(r"downloadstring|downloadfile|invoke-webrequest|\biwr\b|\bcurl(?:\.exe)?\b|start-bitstransfer", text))
    execute = bool(re.search(r"\biex\b|invoke-expression|start-process|javascript:|vbscript:", text))
    if app in {"mshta.exe", "regsvr32.exe"} and remote:
        execute = True
    return {"remote_reference": remote, "download_primitive": download,
            "execution_primitive": execute, "encoded_argument": encoded,
            "shell_chain": "&&" in text or "|" in text}


def xml_fields(raw):
    if len(raw) > 512000:
        raise InvalidEvent("Single XML event exceeds 500 KiB")
    try:
        root = ET.fromstring(raw)
    except Exception:
        raise InvalidEvent("Malformed or unsafe XML") from None
    if root.tag.split("}")[-1] != "Event":
        raise InvalidEvent("Expected one Event element")
    fields = {}
    for node in root.iter():
        tag = node.tag.split("}")[-1]
        if tag == "Data" and node.get("Name"):
            fields[node.get("Name")] = node.text or ""
        elif tag in {"EventID", "Computer", "EventRecordID", "Channel"}:
            fields[tag] = node.text or ""
        elif tag == "TimeCreated":
            fields["SystemTime"] = node.get("SystemTime", "")
        elif tag == "Provider":
            fields["Provider"] = node.get("Name", "")
    return fields


def object_fields(obj):
    if not isinstance(obj, dict):
        raise InvalidEvent("Expected a JSON event object")
    fields = {}
    event = obj.get("Event", obj)
    if not isinstance(event, dict):
        return fields
    for key, value in event.items():
        if not isinstance(value, (dict, list)):
            fields[key] = value
    system = event.get("System", {})
    if isinstance(system, dict):
        for key, value in system.items():
            if key == "Provider" and isinstance(value, dict):
                fields[key] = value.get("@Name", value.get("Name", ""))
            elif key == "TimeCreated" and isinstance(value, dict):
                fields["SystemTime"] = value.get("@SystemTime", value.get("SystemTime", ""))
            else:
                fields[key] = scalar(value)
    data = event.get("EventData", {})
    if isinstance(data, dict):
        fields.update({k: scalar(v) for k, v in data.items() if k != "Data"})
        nodes = data.get("Data", [])
        if isinstance(nodes, dict):
            nodes = [nodes]
        if isinstance(nodes, list):
            for node in nodes:
                if isinstance(node, dict):
                    fields[node.get("@Name", node.get("Name", ""))] = scalar(node)
    winlog = event.get("winlog", {})
    if isinstance(winlog, dict):
        data = winlog.get("event_data", {})
        if isinstance(data, dict):
            fields.update(data)
        for src, dest in [("event_id", "EventID"), ("computer_name", "Computer"),
                          ("provider_name", "Provider"), ("record_id", "EventRecordID")]:
            if src in winlog:
                fields[dest] = scalar(winlog[src])
    return fields


@dataclass
class Event:
    id: str
    host: str
    event_id: int
    ts: float
    guid: str = ""
    parent_guid: str = ""
    app: str = "unknown"
    parent: str = "unknown"
    image: str = ""
    location: str = "unknown"
    sha256: str = ""
    flags: dict = field(default_factory=dict)
    destination: str = ""
    port: int = 0
    protocol: str = ""
    initiated: bool | None = None
    query: str = ""
    query_status: str = ""
    pointer: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def normalize(record):
    envelope = record if isinstance(record, dict) else {}
    if isinstance(envelope.get("result"), dict):
        envelope = envelope["result"]
    raw = envelope.get("_raw", record if isinstance(record, str) else None)
    fields = object_fields(envelope)
    if isinstance(raw, str):
        stripped = raw.lstrip("\ufeff \r\n\t")
        if stripped.startswith("<"):
            fields.update(xml_fields(stripped))
        elif stripped.startswith("{"):
            try:
                fields.update(object_fields(load_json(stripped)))
            except (json.JSONDecodeError, RecursionError):
                raise InvalidEvent("Malformed JSON inside _raw") from None
        else:
            # English rendered event support; XML avoids locale-dependent headers.
            for match in re.finditer(r"(?m)^\s*([A-Za-z][A-Za-z0-9_. ]{0,70})\s*[:=]\s*(.*?)\s*$", stripped):
                fields[match[1].replace(" ", "")] = match[2]
    low = {str(k).lower(): scalar(v) for k, v in fields.items()}
    def get(*keys, default=""):
        for key in keys:
            v = low.get(key.lower())
            if v is not None and v != "":
                return str(v).strip()
        return default
    provider = get("Provider", "ProviderName", "SourceName")
    if provider and provider.lower() not in {"microsoft-windows-sysmon", "sysmon"}:
        raise UnsupportedEvent("Not a Sysmon provider")
    try:
        eid = int(get("EventID", "EventCode", "event.code"))
    except ValueError:
        raise InvalidEvent("Missing Sysmon EventID/EventCode") from None
    if eid not in SUPPORTED:
        raise UnsupportedEvent("Sysmon event type not implemented")
    host = get("Computer", "ComputerName").lower().rstrip(".")
    warnings = []
    if not host:
        host = str(envelope.get("host", "")).lower().rstrip(".")
        warnings.append("Endpoint identity fell back to collector host; verify the source")
    if not host or len(host) > 255 or any(c.isspace() for c in host):
        raise InvalidEvent("Missing or invalid original endpoint Computer")
    ts = timestamp(get("UtcTime", "SystemTime", "@timestamp", "_time"))
    if not 0 < ts < 4102444800:
        raise InvalidEvent("Event timestamp outside supported range")
    image, parent_image = get("Image"), get("ParentImage")
    app = ntpath.basename(image).lower()[:255] or "unknown"
    sha = get("SHA256", "sha256")
    if not sha:
        match = re.search(r"(?i)(?:^|[,;\s])SHA256=([a-f0-9]{64})(?:$|[,;\s])", get("Hashes"))
        sha = match[1] if match else ""
    if sha and not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
        warnings.append("Invalid SHA-256 omitted")
        sha = ""
    guid = get("ProcessGuid").lower().strip("{}")
    parent_guid = get("ParentProcessGuid").lower().strip("{}")
    if guid and not re.fullmatch(GUID, guid):
        warnings.append("Invalid ProcessGuid; process attribution unavailable")
        guid = ""
    if parent_guid and not re.fullmatch(GUID, parent_guid):
        warnings.append("Invalid ParentProcessGuid omitted")
        parent_guid = ""
    if not image:
        warnings.append("No Image; application identity unavailable")
    if not provider:
        warnings.append("Provider absent; Sysmon origin assumed from configured source scope")
    if not guid:
        warnings.append("No ProcessGuid; no exact process correlation")
    destination, port = "", 0
    if eid == 3:
        try:
            destination = str(ipaddress.ip_address(get("DestinationIp")))
            port = int(get("DestinationPort", default="0"))
            if not 0 <= port <= 65535:
                raise ValueError()
        except ValueError:
            raise InvalidEvent("Invalid DestinationIp or DestinationPort") from None
    query = get("QueryName").rstrip(".").lower()
    if eid == 22:
        if not query or len(query) > 253 or any(c.isspace() for c in query):
            raise InvalidEvent("Missing or invalid QueryName")
        try:
            query = query.encode("idna").decode("ascii")
        except UnicodeError:
            raise InvalidEvent("Invalid domain encoding") from None
        if len(query) > 253:
            raise InvalidEvent("Encoded domain exceeds 253 characters")
    flags = command_features(get("CommandLine"), app) if eid == 1 else {}
    fingerprint = digest(host, eid, ts, guid, get("EventRecordID", "RecordNumber"),
                         image, parent_guid, get("CommandLine"), destination, port,
                         get("SourceIp"), get("SourcePort"), get("Protocol"),
                         query, get("QueryStatus"), sha.lower())
    pointer = {k: str(envelope[k])[:255] for k in ("index", "source", "sourcetype", "_cd", "splunk_server") if k in envelope}
    pointer.update({"event_time": ts, "computer": host, "event_id": eid})
    direction = get("Initiated").lower()
    return Event(fingerprint, host, eid, ts, guid, parent_guid, app,
                 ntpath.basename(parent_image).lower()[:255] or "unknown", redact_path(image),
                 location(image), sha.lower(), flags, destination, port, get("Protocol").lower()[:16],
                 True if direction == "true" else False if direction == "false" else None,
                 query, get("QueryStatus")[:32], pointer, warnings)


def parse_payload(body, maximum=5000):
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8-sig")
        except UnicodeError:
            raise InvalidEvent("Input must be UTF-8 XML, JSON or NDJSON (not binary EVTX)") from None
    text = body.strip()
    if not text:
        raise InvalidEvent("Empty input")
    if text.startswith("<"):
        try:
            root = ET.fromstring(text)
            records = [ET.tostring(e, encoding="unicode") for e in root] if root.tag.split("}")[-1] == "Events" else [text]
        except Exception:
            raise InvalidEvent("Malformed or unsafe XML document") from None
    else:
        try:
            parsed = load_json(text)
            if isinstance(parsed, dict) and isinstance(parsed.get("results"), list):
                parsed = parsed["results"]
            records = parsed if isinstance(parsed, list) else [parsed]
        except RecursionError:
            raise InvalidEvent("JSON nesting too deep") from None
        except json.JSONDecodeError:
            try:
                records = [load_json(line) for line in text.splitlines() if line.strip()]
            except RecursionError:
                raise InvalidEvent("JSON nesting too deep") from None
            except json.JSONDecodeError:
                records = [text]
    if len(records) > maximum:
        raise InvalidEvent(f"At most {maximum} events per import; split the file")
    accepted, errors, ignored = [], [], 0
    for i, record in enumerate(records):
        try:
            accepted.append(normalize(record))
        except UnsupportedEvent:
            ignored += 1
        except InvalidEvent as exc:
            errors.append({"row": i + 1, "reason": str(exc)})
    return accepted, {"received": len(records), "parsed": len(accepted), "ignored": ignored,
                      "invalid": len(errors), "errors": errors[:20]}
