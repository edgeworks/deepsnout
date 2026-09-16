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

# Only names actually observed/verified in this compatibility dialect belong
# here. Unknown symbolic IDs remain malformed instead of being silently ignored.
_SYMBOLIC_UNSUPPORTED = {
    "IMAGE_LOAD": "image-load",
}

# These are not a global claim that Windows Task == Sysmon EventID. They describe
# concrete flat-Cribl shapes observed in the pilot. The Task value and payload
# signature must both match before the adapter may classify the record as a known
# unsupported Sysmon family. This preserves fail-closed behavior for a changed or
# different serialization.
_UNSUPPORTED_TASK_SIGNATURES = {
    2: ("file-creation-time-change", ("ProcessGuid", "TargetFilename", "CreationUtcTime", "PreviousCreationUtcTime")),
    4: ("sysmon-service-state-change", ("State", "SchemaVersion")),
    5: ("process-terminate", ("ProcessGuid", "Image")),
    6: ("driver-load", ("ImageLoaded", "Hashes", "Signed")),
    7: ("image-load", ("ProcessGuid", "Image", "ImageLoaded")),
    8: ("create-remote-thread", ("SourceProcessGuid", "TargetProcessGuid", "NewThreadId", "StartAddress")),
    11: ("file-create", ("ProcessGuid", "TargetFilename", "CreationUtcTime")),
    12: ("registry-object-create-delete", ("ProcessGuid", "TargetObject", "EventType")),
    13: ("registry-value-set", ("ProcessGuid", "TargetObject", "EventType", "Details")),
    15: ("file-create-stream-hash", ("ProcessGuid", "TargetFilename", "Hash", "Contents")),
}


def _symbol(value):
    return re.sub(r"[^A-Z0-9]+", "_", _scalar_text(value).upper()).strip("_")


def _present(event, key):
    return _scalar_text(event.get(key, "")) != ""


def _all_present(event, keys):
    return all(_present(event, key) for key in keys)


def _supported_signature_matches(event, event_id):
    """Require event-specific payload fields before trusting a compatibility hint."""
    if event_id == 1:
        return (_present(event, "ProcessGuid") and _present(event, "Image")
                and (_present(event, "ParentProcessGuid") or _present(event, "ParentImage")))
    if event_id == 3:
        return (_present(event, "DestinationIp") and _present(event, "DestinationPort")
                and (_present(event, "ProcessGuid") or _present(event, "Image")))
    if event_id == 22:
        return _present(event, "QueryName") and (_present(event, "ProcessGuid") or _present(event, "Image"))
    return False


def _unsupported_task_shape(event, task):
    definition = _UNSUPPORTED_TASK_SIGNATURES.get(task)
    if not definition:
        return ""
    label, required = definition
    return label if _all_present(event, required) else ""


def _cribl_flat_sysmon(event):
    """Adapt the observed Cribl flattened Sysmon dialect.

    This adapter is intentionally narrow. It runs only for the flattened Windows
    shape and only when provider/channel/provider-GUID independently establish
    Sysmon identity. Generic ``ID`` and Windows ``Task`` remain compatibility
    hints, not core EventID aliases. Supported hints need event-specific payload
    corroboration; unsupported Task values are ignored only for verified payload
    signatures observed in this dialect.
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
            if _supported_signature_matches(event, mapped):
                fields["EventID"] = str(mapped)
                warnings.append(f"EventID inferred by cribl-flat-sysmon adapter from symbolic ID {symbolic}")
            else:
                detail["symbolic_signature_mismatch"] = symbolic
        elif symbolic in _SYMBOLIC_UNSUPPORTED:
            return AdapterContribution(
                "cribl-flat-sysmon",
                fields=fields,
                warnings=tuple(warnings),
                unsupported_reason=("Recognized unsupported flat Sysmon shape from cribl-flat-sysmon adapter: "
                                    f"{_SYMBOLIC_UNSUPPORTED[symbolic]} (ID={symbolic})"),
                detail=detail,
            )
        elif raw_symbol.isdigit():
            numeric = int(raw_symbol)
            if numeric in SUPPORTED_EVENT_IDS and _supported_signature_matches(event, numeric):
                fields["EventID"] = str(numeric)
                warnings.append("EventID inferred by cribl-flat-sysmon adapter from numeric ID plus payload signature")
            else:
                unsupported = _unsupported_task_shape(event, numeric)
                if unsupported:
                    return AdapterContribution(
                        "cribl-flat-sysmon", fields=fields, warnings=tuple(warnings),
                        unsupported_reason=("Recognized unsupported flat Sysmon shape from cribl-flat-sysmon adapter: "
                                            f"{unsupported} (ID={numeric})"),
                        detail=detail)
        else:
            detail["unrecognized_symbolic_id"] = symbolic

    # Explicit/nested EventID extraction in the core takes precedence over this
    # compatibility hint because adapter fields are merged with setdefault().
    if "EventID" not in fields and not symbolic:
        task_text = _scalar_text(event.get("Task", ""))
        detail["task"] = task_text
        try:
            task = int(task_text)
        except (TypeError, ValueError):
            task = None
        if task in SUPPORTED_EVENT_IDS:
            if _supported_signature_matches(event, task):
                fields["EventID"] = str(task)
                warnings.append(
                    "EventID inferred from Sysmon Task by cribl-flat-sysmon adapter after event-specific payload signature validation"
                )
            elif task is not None:
                detail["task_signature_mismatch"] = task_text
        elif task is not None:
            unsupported = _unsupported_task_shape(event, task)
            if unsupported:
                return AdapterContribution(
                    "cribl-flat-sysmon",
                    fields=fields,
                    warnings=tuple(warnings),
                    unsupported_reason=("Recognized unsupported flat Sysmon shape from cribl-flat-sysmon adapter: "
                                        f"{unsupported} (Task={task})"),
                    detail=detail,
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
