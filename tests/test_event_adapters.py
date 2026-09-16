import json
import pytest

from conftest import raw_event
from deepsnout.event_adapters import adapt_json_event
from deepsnout.normalize import InvalidEvent, normalize, parse_payload


SYSMON_GUID = "'{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'"


def flat_sysmon(**extra):
    event = {
        "sourceMachineID": "ws.example",
        "Name": "'Microsoft-Windows-Sysmon'",
        "Guid": SYSMON_GUID,
        "Task": "255",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "SystemTime": "'2026-09-14T11:57:36.2358960Z'",
        "EventRecordID": "42",
        "UtcTime": "2026-09-14 11:57:36.233",
    }
    event.update(extra)
    return event


def test_symbolic_image_load_is_unsupported_not_malformed():
    events, report = parse_payload(json.dumps(flat_sysmon(ID="IMAGE_LOAD")))
    assert events == []
    assert report["ignored"] == 1
    assert report["invalid"] == 0


def test_symbolic_supported_event_is_mapped_by_adapter():
    raw = flat_sysmon(
        ID="PROCESS_CREATE",
        ProcessGuid="{00000000-0000-0000-0000-000000000001}",
        ParentProcessGuid="{00000000-0000-0000-0000-000000000002}",
        Image=r"C:\Windows\System32\cmd.exe",
        ParentImage=r"C:\Windows\explorer.exe",
    )
    event = normalize({"_raw": json.dumps(raw)}, "json")
    assert event.event_id == 1
    assert any("cribl-flat-sysmon adapter" in warning for warning in event.warnings)


def test_task_is_only_a_correlated_compatibility_hint():
    raw = flat_sysmon(Task="1")
    adaptation = adapt_json_event(raw)
    assert "cribl-flat-sysmon" in adaptation.names
    assert "EventID" not in adaptation.fields
    with pytest.raises(InvalidEvent, match="after compatibility adapters"):
        normalize({"_raw": json.dumps(raw)}, "json")


def test_generic_uppercase_id_never_overrides_explicit_event_id():
    raw = raw_event(ID="IMAGE_LOAD")
    event = normalize(raw)
    assert event.event_id == 1


def test_flat_non_sysmon_provider_stays_outside_sysmon_semantics():
    raw = flat_sysmon(Name="'Microsoft-Windows-Security-Auditing'", Guid="'{54849625-5478-4994-a5ba-3e3b0328c30d}'",
                      Channel="Security", Task="1", ID="PROCESS_CREATE")
    events, report = parse_payload(json.dumps(raw))
    assert events == []
    assert report["ignored"] == 1
    assert report["invalid"] == 0
