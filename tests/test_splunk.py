import hashlib
import http.server
import json
import ssl
import threading
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from conftest import raw_event
from deepsnout.splunk import SplunkClient,SplunkSettings,SplunkError,TooManyEvents,validate_url,peer_sha256


def client_for(rows,*,status=None,broken_page=False,preview=False,messages=None):
    seen=[]
    def handle(request):
        seen.append(request)
        if request.method=='POST': return httpx.Response(200,json={'sid':'test-sid'})
        if request.method=='DELETE': return httpx.Response(200,json={})
        if request.url.path.endswith('/results'):
            assert '/search/v2/' in request.url.path
            offset,size=int(request.url.params['offset']),int(request.url.params['count'])
            return httpx.Response(200,json={'results':[] if broken_page else rows[offset:offset+size],
                                          'preview':preview,'messages':messages or []})
        if request.url.path=='/services/server/info':
            return httpx.Response(200,json={'entry':[{'content':{'version':'test'}}]})
        return httpx.Response(200,json={'entry':[{'content':status or {'isDone':True,'resultCount':len(rows)}}]})
    client=SplunkClient(SplunkSettings(url='https://splunk.example',indexes='wef,win_server'),
        'NEVER-LOG-THIS-TOKEN',transport=httpx.MockTransport(handle),sleep=lambda _:None)
    return client,seen


def test_pagination_and_index_time_scope():
    rows=[{'_raw':json.dumps(raw_event(n=i+1)),'index':'wef'} for i in range(1201)]
    client,seen=client_for(rows)
    events,report=client.query(100,200)
    assert len(events)==1201 and report['invalid']==0
    requests=[r for r in seen if r.url.path.endswith('/results')]
    assert [r.url.params['offset'] for r in requests]==['0','500','1000']
    params=parse_qs(seen[0].content.decode())
    assert '_indextime >= 100 AND _indextime < 200' in params['search'][0]
    assert 'max_count' in params and params['earliest_time']==['0']
    assert seen[-1].method=='DELETE' and seen[0].headers['Authorization']=='Bearer NEVER-LOG-THIS-TOKEN'
    client.close()


@pytest.mark.parametrize('kwargs',[dict(broken_page=True),dict(preview=True),
    dict(messages=[{'type':'WARN','text':'partial search'}]),
    dict(status={'isDone':True,'resultCount':1,'isFinalized':True}),dict(status={'isDone':True}),
    dict(status={'isFailed':True,'resultCount':1}),
    dict(status={'isDone':True,'resultCount':1,'messages':[{'type':'ERROR'}]})])
def test_incomplete_is_never_success(kwargs):
    client,requests=client_for([raw_event()],**kwargs)
    with pytest.raises(SplunkError): client.query(100,200)
    assert requests[-1].method=='DELETE'; client.close()


def test_invalid_supported_cannot_skip():
    client,_=client_for([{'EventCode':'3'}])
    with pytest.raises(SplunkError,match='Checkpoint not advanced'): client.query(100,200)
    client.close()


def test_failed_parse_keeps_detailed_candidate_diagnostics():
    raw=raw_event()
    raw.pop('EventID')
    raw.update(Task='1',Name="'Microsoft-Windows-Sysmon'",
        Guid="'{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'",
        Channel='Microsoft-Windows-Sysmon/Operational',Wrapper={'EventID':'Process Create'})
    row={'_raw':json.dumps(raw),'_time':'2026-09-14T13:33:12Z','_indextime':'1789392792',
         'index':'wef','sourcetype':'sysmon-json','host':'collector','_cd':'1:2'}
    client,_=client_for([row])
    with pytest.raises(SplunkError,match='Grouped diagnostics') as caught:
        client.query(100,200)
    report=caught.value.report
    assert report['invalid']==1 and report['index_time_start']==100 and report['index_time_end']==200
    group=report['diagnostic_groups'][0]
    assert group['count']==1 and group['sample_rows']==[1]
    diagnostic=group['sample']
    assert diagnostic['selected_candidate']['requested_key']=='eventid'
    assert diagnostic['selected_candidate']['cleaned']=='Process Create'
    assert diagnostic['selected_candidate']['parsed_integer'] is None
    assert diagnostic['normalized_candidates']['task']['cleaned']=='1'
    assert any(item['path']=='Wrapper.EventID' for item in diagnostic['raw_candidate_paths'])
    assert diagnostic['raw']['sha256'] and '_raw' in diagnostic['row_keys']
    assert 'cribl-flat-sysmon' in diagnostic['compatibility']['adapters']
    assert raw['CommandLine'] not in json.dumps(diagnostic)
    client.close()


def test_diagnostics_group_repeated_failures_and_keep_later_signatures():
    rows=[]
    for i in range(25):
        raw=raw_event(n=i+1); raw['EventID']='bad-a'
        rows.append({'_raw':json.dumps(raw),'_time':'2026-09-14T13:33:12Z','_indextime':str(100+i),
                     'index':'wef','sourcetype':'sysmon-json','host':'collector','_cd':f'1:{i}'})
    for i in range(3):
        raw=raw_event(n=100+i); raw['EventID']='bad-b'
        rows.append({'_raw':json.dumps(raw),'_time':'2026-09-14T13:34:12Z','_indextime':str(200+i),
                     'index':'wef','sourcetype':'sysmon-json','host':'collector','_cd':f'2:{i}'})
    client,_=client_for(rows)
    with pytest.raises(SplunkError) as caught:
        client.query(100,300)
    groups=caught.value.report['diagnostic_groups']
    assert sorted(group['count'] for group in groups)==[3,25]
    assert {group['signature']['selected']['cleaned'] for group in groups}=={'bad-a','bad-b'}
    assert all(len(group['sample_pointers'])<=3 for group in groups)
    client.close()


def test_explicit_malformed_tolerance_allows_pilot_progress():
    client,_=client_for([raw_event(),{'EventCode':'3'},raw_event(n=2)])
    client.settings.malformed_tolerance=1
    events,report=client.query(100,200)
    assert len(events)==2
    assert report['invalid']==1 and report['tolerated_malformed']==1
    assert 'checkpoint advanced' in report['warning']
    client.close()


def test_other_sysmon_types_counted():
    client,_=client_for([raw_event(7)])
    events,report=client.query(100,200)
    assert not events and report['ignored']==1; client.close()


def test_overload_bisects_without_losing_tail(monkeypatch):
    client,_=client_for([]); tried=[]
    def query(start,end):
        tried.append((start,end))
        if end-start>2: raise TooManyEvents('test')
        return [],{'received':0}
    monkeypatch.setattr(client,'query',query)
    assert client.slice(100,108)[2]==102 and tried==[(100,108),(100,104),(100,102)]
    monkeypatch.setattr(client,'query',lambda *_: (_ for _ in ()).throw(TooManyEvents('test')))
    with pytest.raises(SplunkError,match='one indexed second'): client.slice(100,101)
    client.close()


@pytest.mark.parametrize('url',['http://splunk.example','https://user:password@host',
    'https://169.254.169.254','https://host/path','https://host?query=1','https://host:99999'])
def test_unsafe_origins(url):
    with pytest.raises(ValueError): validate_url(url)


def test_private_sources_ca_validation_and_no_arbitrary_spl():
    assert validate_url('https://10.1.2.3:8089/')=='https://10.1.2.3:8089'
    with pytest.raises(ValueError): SplunkSettings(url='https://host',indexes='wef',ca_pem='not a certificate')
    with pytest.raises(ValueError): SplunkSettings(url='https://host',indexes='wef | delete')
    with pytest.raises(ValueError): SplunkSettings(url='https://host',indexes='wef',malformed_tolerance=1001)


def test_cooperative_cancel_and_poll_budget():
    client,_=client_for([])
    client.cancel_check=lambda: True
    with pytest.raises(SplunkError,match='cancellation requested'):
        client.query(100,200)
    client.cancel_check=None
    client.operation_deadline=0
    with pytest.raises(SplunkError,match='15-minute worker budget'):
        client.query(100,200)
    client.close()


def test_remote_error_does_not_echo_secrets():
    client=SplunkClient(SplunkSettings(url='https://splunk.example',indexes='wef'),'secret',
        transport=httpx.MockTransport(lambda _:httpx.Response(401,text='secret')))
    with pytest.raises(SplunkError) as exc: client.test()
    assert 'secret' not in str(exc.value) and '401' in str(exc.value); client.close()


def test_computer_selection_matches_original_not_collector():
    client,_=client_for([{'_raw':json.dumps(raw_event(host='TEST-1.EXAMPLE')),'host':'collector'},
                         {'_raw':json.dumps(raw_event(host='production.example')),'host':'collector'}])
    client.settings.computer_pattern='test-*.example'
    events,report=client.query(100,200)
    assert len(events)==1 and events[0].host=='test-1.example'
    assert report['received']==2 and report['filtered_by_computer']==1
    client.close()


def test_no_spl_in_computer_pattern():
    with pytest.raises(ValueError):
        SplunkSettings(url='https://host',indexes='wef',computer_pattern='* | delete')


def test_json_format_and_pin_validation():
    fingerprint='97:04:69:19:BC:7F:BC:F4:16:0E:DB:FF:3E:64:C8:40:0D:91:33:63:DE:B9:EA:15:57:CD:1A:7C:DA:4A:76:7C'
    settings=SplunkSettings(url='https://host',indexes='wef',event_format='JSON',
        tls_mode='pinned',cert_sha256=fingerprint)
    assert settings.event_format=='json'
    assert settings.cert_sha256=='97046919bc7fbcf4160edbff3e64c8400d913363deb9ea1557cd1a7cda4a767c'
    with pytest.raises(ValueError):
        SplunkSettings(url='https://host',indexes='wef',tls_mode='pinned')
    with pytest.raises(ValueError):
        SplunkSettings(url='https://host',indexes='wef',event_format='evtx')


def test_peer_fingerprint_from_tls_stream():
    certificate=b'synthetic-der-certificate'
    class TLS:
        def getpeercert(self,binary=False):
            return certificate if binary else {}
    class Stream:
        def get_extra_info(self,name):
            return TLS() if name=='ssl_object' else None
    response=httpx.Response(200,extensions={'network_stream':Stream()})
    assert peer_sha256(response)==hashlib.sha256(certificate).hexdigest()


def test_query_honors_explicit_json_format():
    client,_=client_for([{'_raw':json.dumps(raw_event(3)),'index':'wef'}])
    client.settings.event_format='json'
    events,report=client.query(100,200)
    assert len(events)==1 and report['invalid']==0
    client.close()


def test_pinned_tls_wrong_hostname_and_fail_closed(tmp_path):
    now=datetime.now(timezone.utc)
    root_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    root_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Test Root')])
    root=(x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
        .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False,content_commitment=False,key_encipherment=False,
            data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,
            encipher_only=None,decipher_only=None),critical=True)
        .sign(root_key,hashes.SHA256()))
    leaf_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    leaf_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'intentionally-wrong-host')])
    leaf=(x509.CertificateBuilder().subject_name(leaf_name).issuer_name(root_name)
        .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=True,
            data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,
            encipher_only=None,decipher_only=None),critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
        .sign(root_key,hashes.SHA256()))
    chain=tmp_path/'chain.pem'; keyfile=tmp_path/'leaf.key'
    chain.write_bytes(leaf.public_bytes(serialization.Encoding.PEM)+root.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()))
    auth_seen=[]
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            auth=self.headers.get('Authorization'); auth_seen.append(auth)
            body=(json.dumps({'entry':[{'content':{'version':'test'}}]}).encode() if auth else b'{}')
            self.send_response(200 if auth else 401); self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self,*args): pass
    server=http.server.HTTPServer(('127.0.0.1',0),Handler)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(chain,keyfile)
    server.socket=context.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    fingerprint=hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest()
    url=f'https://127.0.0.1:{server.server_address[1]}'
    try:
        client=SplunkClient(SplunkSettings(url=url,indexes='wef',tls_mode='pinned',cert_sha256=fingerprint),'token')
        assert client.test()['tls']=='leaf certificate pinned'; client.close()
        assert auth_seen[:2]==[None,'Bearer token']
        before=len(auth_seen)
        with pytest.raises(SplunkError,match='fingerprint mismatch'):
            SplunkClient(SplunkSettings(url=url,indexes='wef',tls_mode='pinned',cert_sha256='0'*64),'secret')
        assert auth_seen[before:]==[None]
    finally:
        server.shutdown(); thread.join(timeout=3); server.server_close()
