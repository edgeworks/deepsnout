"""Compatibility adapters for non-canonical JSON event shapes.

The core normalizer should understand the DeepSnout event contract, not every
collector/vendor serialization quirk. JSON adapters run before core event-ID
resolution and may contribute canonical fields or classify a trusted event as a
known-but-unsupported source shape.

Adapters are deliberately small, deterministic functions registered in
``JSON_ADAPTERS``. Adding another environment-specific dialect should normally
mean adding one adapter here instead of expanding transport-neutral parser logic.
"""
from dataclasses import dataclass, field
import re

from .event_contract import (SUPPORTED_EVENT_IDS, SYSMON_CHANNEL,
                             SYSMON_PROVIDER_GUID, SYSMON_PROVIDERS)


@dataclass(frozen=True)
class AdapterContribution:
    name: str
    fields: dict[str, object] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    unsupported_reason: str = ""
    detail: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class JsonAdaptation:
    names: tuple[str, ...] = ()
    fields: dict[str, object] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    unsupported_reason: str = ""
    detail: dict[str, str] = field(default_factory=dict)


def _scalar_text(value):
    if value is None:
        return ""
    if isinstance(value, dict):
        for key in ("#text", "text", "value", "Value", "_value", "$text", "_text"):
            if key in value and not isinstance(value[key], (dict, list)):
                value = value[key]
                break
        else:
            return ""
    elif isinstance(value, list):
        if not value:
            return ""
        return _scalar_text(value[0])
    text = str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {"'", '"'}:
        text = text[1:-1].strip()
    return text


def _flat_windows_shape(event):
    if not isinstance(event, dict):
        return False
    markers = sum(key in event for key in
                  ("Task", "Guid", "Channel", "sourceMachineID", "SystemTime", "EventRecordID"))
    # Three independent Windows-System-like markers keep this adapter narrow while
    # still supporting records where Cribl dropped Name but retained provider GUID.
    return markers >= 3


def _trusted_sysmon(event):
    provider = _scalar_text(event.get("Name", "")).lower()
    channel = _scalar_text(event.get("Channel", "")).lower()
    guid = _scalar_text(event.get("Guid", "")).lower().strip("{}")
    return provider in SYSMON_PROVIDERS or channel == SYSMON_CHANNEL or guid == SYSMON_PROVIDER_GUID


def _flat_windows_system(event):
    """Promote flattened Windows System fields without assigning event semantics."""
    if not _flat_windows_shape(event):
        return None
    fields = {}
    provider = _scalar_text(event.get("Name", ""))
    computer = _scalar_text(event.get("sourceMachineID", ""))
    if provider:
        fields["Provider"] = provider
    if computer:
        fields["Computer"] = computer
    return AdapterContribution("flat-windows-system", fields=fields)


_SYMBOLIC_SUPPORTED = {
    "PROCESS_CREATE": 1,
    "NETWORK_CONNECT": 3,
    "DNS_QUERY": 22,
}


def _symbol(value):
    return re.sub(r"[^A-Z0-9]+", "_", _scalar_text(value).upper()).strip("_")


def _task_signature_matches(event, event_id):
    """Require event-specific payload fields before trusting Cribl's Task hint.

    In the observed flattened pipeline Task=1 happens to identify Process Create,
    while Image Load records use Task=255. Task is therefore a compatibility hint,
    not a generic Windows event identifier.
    """
    present = lambda key: _scalar_text(event.get(key, "")) != ""
    if event_id == 1:
        return present("ProcessGuid") and present("Image") and (present("ParentProcessGuid") or present("ParentImage"))
    if event_id == 3:
        return present("DestinationIp") and present("DestinationPort") and (present("ProcessGuid") or present("Image"))
    if event_id == 22:
        return present("QueryName") and (present("ProcessGuid") or present("Image"))
    return False


def _cribl_flat_sysmon(event):
    """Adapt the observed Cribl flattened Sysmon dialect.

    This adapter is intentionally narrow. It runs only for the flattened Windows
    shape and only when provider/channel/provider-GUID independently establish
    Sysmon identity. A generic ``ID`` is never treated as an event ID by the core
    parser; this adapter may interpret the Cribl-specific symbolic ``ID`` field.
    ``Task`` is used only for the three DeepSnout-supported event types and only
    when their payload signature corroborates the hint.
    """
    if not _flat_windows_shape(event) or not _trusted_sysmon(event):
        return None

    fields = {}
    warnings = []
    detail = {}
    raw_symbol = _scalar_text(event.get("ID", ""))
    symbolic = _symbol(raw_symbol) if raw_symbol else ""
    if symbolic:
        detail["symbolic_id"] = symbolic
        mapped = _SYMBOLIC_SUPPORTED.get(symbolic)
        if mapped is not None:
            fields["EventID"] = str(mapped)
            warnings.append(f"EventID inferred by cribl-flat-sysmon adapter from symbolic ID {symbolic}")
        elif raw_symbol.isdigit():
            numeric = int(raw_symbol)
            if numeric in SUPPORTED_EVENT_IDS:
                fields["EventID"] = str(numeric)
                warnings.append("EventID inferred by cribl-flat-sysmon adapter from numeric ID")
            else:
                return AdapterContribution(
                    "cribl-flat-sysmon", fields=fields, warnings=tuple(warnings),
                    unsupported_reason=f"Unsupported numeric Sysmon event type from cribl-flat-sysmon adapter: {numeric}",
                    detail=detail)
        else:
            return AdapterContribution(
                "cribl-flat-sysmon",
                fields=fields,
                warnings=tuple(warnings),
                unsupported_reason=f"Unsupported symbolic Sysmon event type from cribl-flat-sysmon adapter: {symbolic[:120]}",
                detail=detail,
            )

    # Explicit/nested EventID extraction in the core takes precedence over this
    # compatibility hint because adapter fields are merged with setdefault().
    if "EventID" not in fields and not symbolic:
        task_text = _scalar_text(event.get("Task", ""))
        detail["task"] = task_text
        try:
            task = int(task_text)
        except (TypeError, ValueError):
            task = None
        if task in SUPPORTED_EVENT_IDS and _task_signature_matches(event, task):
            fields["EventID"] = str(task)
            warnings.append(
                "EventID inferred from Sysmon Task by cribl-flat-sysmon adapter after event-specific payload signature validation"
            )

    return AdapterContribution(
        "cribl-flat-sysmon",
        fields=fields,
        warnings=tuple(warnings),
        detail=detail,
    )


JSON_ADAPTERS = (
    _flat_windows_system,
    _cribl_flat_sysmon,
)


def adapt_json_event(event):
    """Apply registered JSON compatibility adapters and merge their contributions."""
    if not isinstance(event, dict):
        return JsonAdaptation()
    names = []
    fields = {}
    warnings = []
    unsupported_reason = ""
    detail = {}
    for adapter in JSON_ADAPTERS:
        contribution = adapter(event)
        if contribution is None:
            continue
        names.append(contribution.name)
        for key, value in contribution.fields.items():
            fields.setdefault(key, value)
        warnings.extend(contribution.warnings)
        if contribution.unsupported_reason and not unsupported_reason:
            unsupported_reason = contribution.unsupported_reason
        if contribution.detail:
            detail[contribution.name] = contribution.detail
    return JsonAdaptation(tuple(names), fields, tuple(warnings), unsupported_reason, detail)
