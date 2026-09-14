import hashlib
import json
from urllib.parse import parse_qs
import httpx
import pytest
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
