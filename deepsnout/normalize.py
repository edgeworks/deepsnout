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
EVENT_FORMATS = {"auto", "xml", "json"}
SYSMON_PROVIDERS = {"microsoft-windows-sysmon", "sysmon"}
SYSMON_CHANNEL = "microsoft-windows-sysmon/operational"
SYSMON_PROVIDER_GUID = "5770385f-c22a-43e0-bf4c-06f5698ffbd9"


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
        for key in ("#text", "text", "value", "Value", "_value", "$text", "_text"):
            if key in value and not isinstance(value[key], (dict, list)):
                return value[key]
        if len(value) == 1:
            only = next(iter(value.values()))
            if not isinstance(only, (dict, list)):
                return only
        return ""
    if isinstance(value, list):
        return scalar(value[0]) if value else ""
    return value


def clean_text(value):
    """Normalize scalar text and remove one Cribl-style wrapping quote pair."""
    value = scalar(value)
    if value is None:
        return ""
    text = str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        text = text[1:-1].strip()
    return text


def timestamp(value):
    try:
        if isinstance(value, (int, float)) or re.fullmatch(r"\d{10}(?:\.\d+)?", str(value)):
            return float(value)
        dotnet = re.fullmatch(r"/?Date\(([-+]?\d+)(?:[-+]\d{4})?\)/?", str(value).strip())
        if dotnet:
            return int(dotnet.group(1)) / 1000.0
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


_CANONICAL = {
    "provider": "Provider", "providername": "ProviderName", "sourcename": "SourceName",
    "eventid": "EventID", "eventcode": "EventCode", "computer": "Computer",
    "computername": "ComputerName", "machinename": "Computer", "sourcemachineid": "Computer",
    "eventrecordid": "EventRecordID", "recordnumber": "RecordNumber", "channel": "Channel",
    "systemtime": "SystemTime", "utctime": "UtcTime", "image": "Image",
    "parentimage": "ParentImage", "commandline": "CommandLine", "processguid": "ProcessGuid",
    "parentprocessguid": "ParentProcessGuid", "sha256": "SHA256", "hashes": "Hashes",
    "destinationip": "DestinationIp", "destinationport": "DestinationPort",
    "sourceip": "SourceIp", "sourceport": "SourcePort", "protocol": "Protocol",
    "initiated": "Initiated", "queryname": "QueryName", "querystatus": "QueryStatus",
}


def _norm_name(value):
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _canonical_path(path):
    if not path:
        return None
    segments = []
    for part in path:
        segments.extend(p for p in re.split(r"[./]", str(part)) if p)
    if not segments:
        return None
    leaf = _norm_name(segments[-1])
    if leaf in _CANONICAL:
        return _CANONICAL[leaf]
    normalized = [_norm_name(part) for part in segments]
    if leaf == "name" and "provider" in normalized:
        return "Provider"
    if leaf == "systemtime" and "timecreated" in normalized:
        return "SystemTime"
    return None


def _named_data(node):
    """Return (canonical-name, value) for common XML-to-JSON Data representations."""
    if not isinstance(node, dict):
        return None, None
    name = ""
    for key in ("@Name", "Name", "name"):
        if key in node and not isinstance(node[key], (dict, list)):
            name = str(node[key])
            break
    if not name:
        for container in ("@", "_attributes", "attributes", "attrs", "_attr"):
            attrs = node.get(container)
            if isinstance(attrs, dict):
                for key in ("Name", "name", "@Name"):
                    if key in attrs and not isinstance(attrs[key], (dict, list)):
                        name = str(attrs[key])
                        break
            if name:
                break
    canonical = _CANONICAL.get(_norm_name(name)) if name else None
    return canonical, scalar(node) if canonical else None


def _collect_json_fields(node, fields, path=(), depth=0):
    """Fill known Sysmon fields from tolerant Cribl/XML-to-JSON layouts.

    Explicit schema-aware extraction runs first; this is a bounded fallback for
    flattened dotted keys, attribute containers and named Data arrays.
    """
    if depth > 64:
        raise InvalidEvent("JSON nesting exceeds 64 levels")
    if isinstance(node, dict):
        canonical, value = _named_data(node)
        if canonical and value not in (None, ""):
            fields.setdefault(canonical, value)
        for key, value in node.items():
            child_path = path + (str(key),)
            canonical = _canonical_path(child_path)
            if canonical:
                candidate = scalar(value)
                if candidate not in (None, ""):
                    fields.setdefault(canonical, candidate)
            if isinstance(value, (dict, list)):
                _collect_json_fields(value, fields, child_path, depth + 1)
    elif isinstance(node, list):
        for value in node:
            _collect_json_fields(value, fields, path, depth + 1)


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
    # Cribl Windows Event Logs JSON / Get-WinEvent-style system fields. Event
    # payload values are recovered from __winEvent or Message below when present.
    for src, dest in (("Id", "EventID"), ("RecordId", "EventRecordID"),
                      ("MachineName", "Computer"), ("sourceMachineID", "Computer"),
                      ("TimeCreated", "SystemTime")):
        if src in event and not isinstance(event[src], (dict, list)):
            fields.setdefault(dest, event[src])
    # Some Cribl Windows Event Log pipelines flatten the XML System block into
    # top-level keys. In that shape Name is the provider name and EventID may be
    # omitted even though the original Windows Task remains present. Preserve the
    # provider even when it is not Sysmon so a mixed Windows-event sourcetype can
    # be ignored safely instead of being reported as malformed Sysmon.
    provider_name = clean_text(event.get("Name", ""))
    channel = clean_text(event.get("Channel", ""))
    flat_system_shape = any(key in event for key in
                            ("Task", "Guid", "Channel", "sourceMachineID", "SystemTime", "EventRecordID"))
    if provider_name and flat_system_shape:
        fields.setdefault("Provider", provider_name)
    elif channel.lower() == SYSMON_CHANNEL:
        fields.setdefault("Provider", "Microsoft-Windows-Sysmon")
    message = event.get("Message")
    if isinstance(message, str):
        for match in re.finditer(r"(?m)^\s*([A-Za-z][A-Za-z0-9_. ]{0,70})\s*:\s*(.*?)\s*$", message):
            fields.setdefault(match[1].replace(" ", ""), match[2])
    system = event.get("System", {})
    if isinstance(system, dict):
        for key, value in system.items():
            if key == "Provider" and isinstance(value, dict):
                fields[key] = value.get("@Name", value.get("Name", scalar(value)))
            elif key == "TimeCreated" and isinstance(value, dict):
                fields["SystemTime"] = value.get("@SystemTime", value.get("SystemTime", scalar(value)))
            else:
                fields[key] = scalar(value)
    data = event.get("EventData", {})
    if isinstance(data, dict):
        fields.update({k: scalar(v) for k, v in data.items() if k != "Data" and scalar(v) != ""})
        nodes = data.get("Data", [])
        if isinstance(nodes, dict):
            nodes = [nodes]
        if isinstance(nodes, list):
            for node in nodes:
                if isinstance(node, dict):
                    name = node.get("@Name", node.get("Name", node.get("name", "")))
                    if not name:
                        canonical, value = _named_data(node)
                        if canonical and value not in (None, ""):
                            fields[canonical] = value
                    else:
                        fields[str(name)] = scalar(node)
    winlog = event.get("winlog", {})
    if isinstance(winlog, dict):
        data = winlog.get("event_data", {})
        if isinstance(data, dict):
            fields.update(data)
        for src, dest in [("event_id", "EventID"), ("computer_name", "Computer"),
                          ("provider_name", "Provider"), ("record_id", "EventRecordID")]:
            if src in winlog:
                fields[dest] = scalar(winlog[src])
    _collect_json_fields(event, fields)
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


def normalize(record, event_format="auto"):
    if event_format not in EVENT_FORMATS:
        raise InvalidEvent("Unknown event payload format")
    envelope = record if isinstance(record, dict) else {}
    if isinstance(envelope.get("result"), dict):
        envelope = envelope["result"]
    raw = envelope.get("_raw", record if isinstance(record, str) else None)
    fields = object_fields(envelope)
    if isinstance(raw, str):
        stripped = raw.lstrip("\ufeff \r\n\t")
        if event_format == "xml" and not stripped.startswith("<"):
            raise InvalidEvent("Configured XML source returned non-XML _raw")
        if event_format == "json" and not stripped.startswith("{"):
            raise InvalidEvent("Configured JSON source returned non-JSON _raw")
        if stripped.startswith("<"):
            if event_format == "json":
                raise InvalidEvent("Configured JSON source returned XML _raw")
            fields.update(xml_fields(stripped))
        elif stripped.startswith("{"):
            if event_format == "xml":
                raise InvalidEvent("Configured XML source returned JSON _raw")
            try:
                fields.update(object_fields(load_json(stripped)))
            except (json.JSONDecodeError, RecursionError):
                raise InvalidEvent("Malformed JSON inside _raw") from None
        elif event_format in {"xml", "json"}:
            raise InvalidEvent(f"Configured {event_format.upper()} source returned an unsupported _raw payload")
        else:
            # English rendered event support; XML/JSON avoids locale-dependent headers.
            for match in re.finditer(r"(?m)^\s*([A-Za-z][A-Za-z0-9_. ]{0,70})\s*[:=]\s*(.*?)\s*$", stripped):
                fields[match[1].replace(" ", "")] = match[2]
    elif event_format in {"xml", "json"} and not isinstance(record, dict):
        raise InvalidEvent(f"Configured {event_format.upper()} source returned an unsupported event object")
    low = {str(k).lower(): scalar(v) for k, v in fields.items()}
    def get(*keys, default=""):
        for key in keys:
            v = low.get(key.lower())
            if v is not None and v != "":
                return clean_text(v)
        return default
    provider = get("Provider", "ProviderName", "SourceName")
    channel = get("Channel").lower()
    provider_guid = get("Guid").lower().strip("{}")
    provider_is_sysmon = provider.lower() in SYSMON_PROVIDERS
    channel_is_sysmon = channel == SYSMON_CHANNEL
    guid_is_sysmon = provider_guid == SYSMON_PROVIDER_GUID
    if provider and not provider_is_sysmon:
        raise UnsupportedEvent("Not a Sysmon provider")
    if not provider and channel and not channel_is_sysmon:
        raise UnsupportedEvent("Not a Sysmon channel")
    eid_text = get("EventID", "EventCode", "Id", "event.code")
    inferred_from_task = False
    if not eid_text:
        task = get("Task")
        trusted_sysmon = provider_is_sysmon or channel_is_sysmon or guid_is_sysmon
        if task and trusted_sysmon:
            eid_text = task
            inferred_from_task = True
        elif task:
            raise InvalidEvent("Missing Sysmon EventID/EventCode; Task present but Sysmon provider/channel/GUID markers absent")
        else:
            raise InvalidEvent("Missing Sysmon EventID/EventCode; no Task fallback field present")
    try:
        eid = int(eid_text)
    except ValueError:
        raise InvalidEvent("Invalid Sysmon EventID/EventCode or Task value") from None
    if eid not in SUPPORTED:
        raise UnsupportedEvent("Sysmon event type not implemented")
    host = get("Computer", "ComputerName", "MachineName", "sourceMachineID").lower().rstrip(".")
    warnings = []
    if inferred_from_task:
        warnings.append("EventID inferred from Sysmon Task because upstream JSON omitted EventID")
    if not host:
        host = str(envelope.get("host", "")).lower().rstrip(".")
        warnings.append("Endpoint identity fell back to collector host; verify the source")
    if not host or len(host) > 255 or any(c.isspace() for c in host):
        raise InvalidEvent("Missing or invalid original endpoint Computer")
    ts = timestamp(get("UtcTime", "SystemTime", "TimeCreated", "@timestamp", "_time"))
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
    if not provider and not guid_is_sysmon:
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
    fingerprint = digest(host, eid, ts, guid, get("EventRecordID", "RecordId", "RecordNumber"),
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