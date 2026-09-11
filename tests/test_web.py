import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from conftest import raw_event,count
from deepsnout.web import create_app
from deepsnout.db import transaction,Job,Finding,Host,User,Source,LoginSession
from deepsnout.worker import run_job


@pytest.fixture
def browser(engine,config):
    app=create_app(config)
    with TestClient(app,follow_redirects=False) as client:
        client.get('/setup')
        r=client.post('/setup',data={'csrf':client.cookies['ds_csrf'],
            'setup_token':(config.data_dir/'setup_token').read_text(),
            'username':'admin','password':'This is a test passphrase'})
        assert r.status_code==303
        client.get('/login')
        r=client.post('/login',data={'csrf':client.cookies['ds_csrf'],
            'username':'admin','password':'This is a test passphrase'})
        assert r.status_code==303
        yield client
    app.state.engine.dispose()


def post(browser,path,**data):
    return browser.post(path,data={'csrf':browser.cookies['ds_csrf'],**data})


@pytest.mark.parametrize('path',['/','/discover','/endpoints','/expectations','/sources',
    '/imports','/operations','/settings','/accounts','/help','/healthz','/api/status'])
def test_pages(browser,path):
    r=browser.get(path)
    assert r.status_code==200,r.text
    assert "frame-ancestors 'none'" in r.headers['content-security-policy']


def test_anonymous_access_csrf_and_host(engine,config):
    app=create_app(config)
    with TestClient(app,follow_redirects=False) as client:
        assert client.get('/sources').status_code==303
        assert client.post('/setup',data={}).status_code==403
        assert client.get('/setup',headers={'host':'attacker.example'}).status_code==400
    app.state.engine.dispose()


def test_real_demo_finding_lifecycle(browser,engine,config):
    r=post(browser,'/demo'); assert r.status_code==303
    jid=r.headers['location'].split('/')[-1]
    assert run_job(engine,config,jid) and browser.get('/jobs/'+jid).status_code==200
    with transaction(engine) as db: ids=[(f.id,f.detector) for f in db.scalars(select(Finding))]
    assert len(ids)==2 and 'SYNTHETIC' in browser.get('/').text
    for fid,detector in ids:
        assert browser.get('/findings/'+fid).status_code==200
        assert browser.get('/findings/'+fid+'/export').status_code==200
        assert post(browser,'/findings/'+fid+'/state',state='investigating',reason='Review original source logs').status_code==303
        if detector=='DS-NET-001':
            assert browser.get('/findings/'+fid+'/expect').status_code==200
            assert post(browser,'/findings/'+fid+'/expect',days='30',reason='Approved workstation workload').status_code==303
        else:
            assert post(browser,'/findings/'+fid+'/expect',days='30',reason='Should not suppress this detector').status_code==400
    with transaction(engine) as db:
        host=db.scalar(select(Host)); hid=host.id
    assert browser.get('/endpoints/'+hid).status_code==200
    assert post(browser,'/endpoints/'+hid+'/cohort',cohort='office').status_code==303


def test_import_drops_command_secrets(browser,engine,config):
    row=raw_event(CommandLine='utility.exe --password TEST-SECRET-COMMAND')
    response=post(browser,'/imports',text=json.dumps(row),namespace='test')
    assert response.status_code==303
    jid=response.headers['location'].split('/')[-1]
    with transaction(engine) as db: assert 'TEST-SECRET-COMMAND' not in json.dumps(db.get(Job,jid).payload)
    assert run_job(engine,config,jid)
    assert post(browser,'/imports',text='{}',namespace='test').status_code==400


def test_source_encryption_no_echo(browser,engine):
    r=post(browser,'/sources/save',name='Test',namespace='test',url='https://splunk.example:8089',
        indexes='wef',credential='MY-PRIVATE-TOKEN')
    assert r.status_code==303
    with transaction(engine) as db:
        src=db.scalar(select(Source)); sid=src.id
        assert 'MY-PRIVATE-TOKEN' not in src.credential
    assert 'MY-PRIVATE-TOKEN' not in browser.get('/sources?edit='+sid).text
    assert post(browser,'/sources/save',name='Bad',namespace='test',url='http://169.254.169.254',indexes='wef',credential='token').status_code==400


def test_mutations_require_csrf(browser):
    assert browser.post('/demo',data={}).status_code==403
    assert browser.post('/logout',data={'csrf':'forged'}).status_code==403
    assert browser.post('/logout',data={'csrf':'\u00e9'}).status_code==403


def test_viewer_cannot_write(browser,engine):
    assert post(browser,'/accounts',username='viewer',password='Viewer test passphrase',role='viewer').status_code==303
    post(browser,'/logout'); browser.get('/login')
    assert post(browser,'/login',username='viewer',password='Viewer test passphrase').status_code==303
    assert browser.get('/sources').status_code==403 and post(browser,'/demo').status_code==403
    assert browser.get('/').status_code==200


def test_password_invalidates_sessions(browser,engine):
    assert post(browser,'/password',current_password='This is a test passphrase',password='Another good test passphrase').status_code==303
    assert browser.get('/').status_code==303
    with transaction(engine) as db: assert count(db,LoginSession)==0


def test_escape_untrusted_host(browser,engine):
    with transaction(engine) as db:
        db.add(Host(id='abc',name='<img/src=x/onerror=alert(1)>',namespace='test',cohort='unassigned',first_seen=1,last_seen=1))
    text=browser.get('/endpoints').text
    assert '<img/src=x' not in text and '&lt;img/src=x' in text


def test_body_limit(engine,config):
    config.maximum_body=100; app=create_app(config)
    with TestClient(app,follow_redirects=False) as client:
        r=client.post('/imports',content='text='+'x'*500,headers={'content-type':'application/x-www-form-urlencoded'})
        assert r.status_code==413
    app.state.engine.dispose()


def test_admin_role_and_password_reset(browser,engine):
    from deepsnout.security import check_password
    post(browser,'/accounts',username='reviewer',password='Initial test passphrase',role='viewer')
    with transaction(engine) as db: uid=db.scalar(select(User).where(User.username=='reviewer')).id
    assert post(browser,'/accounts/'+uid+'/manage',role='analyst',password='Replacement test passphrase').status_code==303
    with transaction(engine) as db:
        u=db.get(User,uid)
        assert u.role=='analyst' and check_password(u.password,'Replacement test passphrase')
