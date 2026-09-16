import json
import pytest

from conftest import raw_event
from deepsnout.event_adapters import adapt_json_event
from deepsnout.normalize import InvalidEvent, normalize, parse_payload


SYSMON_GUID = "'{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'"
PROCESS_GUID = "{00000000-0000-0000-0000-000000000001}"
PARENT_GUID = "{00000000-0000-0000-0000-000000000002}"
TARGET_GUID = "{00000000-0000-0000-0000-000000000003}"


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
        ProcessGuid=PROCESS_GUID,
        ParentProcessGuid=PARENT_GUID,
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


@pytest.mark.parametrize("task,extra", [
    (2, {"ProcessGuid": PROCESS_GUID, "Image": r"C:\Windows\x.exe",
         "TargetFilename": r"C:\Temp\a.tmp", "CreationUtcTime": "2026-09-14 11:57:00.000",
         "PreviousCreationUtcTime": "2026-09-13 11:57:00.000"}),
    (4, {"State": "Started", "SchemaVersion": "4.90"}),
    (5, {"ProcessGuid": PROCESS_GUID, "Image": r"C:\Windows\x.exe"}),
    (6, {"ImageLoaded": r"C:\Windows\System32\driver.sys", "Hashes": "SHA256=" + "a" * 64,
         "Signed": "true", "SignatureStatus": "Valid"}),
    (7, {"ProcessGuid": PROCESS_GUID, "Image": r"C:\Windows\x.exe",
         "ImageLoaded": r"C:\Windows\System32\library.dll"}),
    (8, {"SourceProcessGuid": PROCESS_GUID, "TargetProcessGuid": TARGET_GUID,
         "NewThreadId": "1234", "StartAddress": "0x7ff00000"}),
    (11, {"ProcessGuid": PROCESS_GUID, "Image": r"C:\Windows\x.exe",
          "TargetFilename": r"C:\Temp\created.bin", "CreationUtcTime": "2026-09-14 11:57:00.000"}),
    (12, {"ProcessGuid": PROCESS_GUID, "Image": r"C:\Windows\x.exe",
          "TargetObject": r"HKLM\Software\Example", "EventType": "CreateKey"}),
    (13, {"ProcessGuid": PROCESS_GUID, "Image": r"C:\Windows\x.exe",
          "TargetObject": r"HKLM\Software\Example\Value", "EventType": "SetValue", "Details": "DWORD (0x1)"}),
    (15, {"ProcessGuid": PROCESS_GUID, "Image": r"C:\Windows\x.exe",
          "TargetFilename": r"C:\Temp\download.bin:Zone.Identifier", "Hash": "SHA256=" + "b" * 64,
          "Contents": "ZoneId=3"}),
])
def test_observed_unsupported_task_shapes_are_ignored(task, extra):
    events, report = parse_payload(json.dumps(flat_sysmon(Task=str(task), **extra)))
    assert events == []
    assert report["ignored"] == 1
    assert report["invalid"] == 0


def test_known_unsupported_task_without_signature_remains_malformed():
    raw = flat_sysmon(Task="7", ImageLoaded=r"C:\Windows\System32\library.dll")
    adaptation = adapt_json_event(raw)
    assert adaptation.unsupported_reason == ""
    with pytest.raises(InvalidEvent, match="after compatibility adapters"):
        normalize({"_raw": json.dumps(raw)}, "json")


def test_unknown_task_remains_malformed():
    raw = flat_sysmon(Task="99", ProcessGuid=PROCESS_GUID, Image=r"C:\Windows\x.exe")
    adaptation = adapt_json_event(raw)
    assert adaptation.unsupported_reason == ""
    with pytest.raises(InvalidEvent, match="after compatibility adapters"):
        normalize({"_raw": json.dumps(raw)}, "json")


def test_unknown_symbolic_id_remains_malformed():
    raw = flat_sysmon(ID="SOMETHING_NEW", ProcessGuid=PROCESS_GUID, Image=r"C:\Windows\x.exe")
    adaptation = adapt_json_event(raw)
    assert adaptation.unsupported_reason == ""
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
