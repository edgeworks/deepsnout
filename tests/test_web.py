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


@pytest.mark.parametrize('path',['/','/discover','/endpoints','/peer-groups','/expectations','/sources',
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
    assert post(browser,'/peer-groups/manual',label='office').status_code==303
    assert post(browser,'/endpoints/'+hid+'/cohort',cohort='office').status_code==303
    assert browser.get('/peer-groups/office').status_code==200


def test_operations_can_cancel_queued_job(browser,engine):
    with transaction(engine) as db:
        job=Job(kind='maintenance'); db.add(job); db.flush(); jid=job.id
    page=browser.get('/operations')
    assert page.status_code==200 and jid in page.text and 'Cancel' in page.text
    assert post(browser,'/jobs/'+jid+'/cancel').status_code==303
    with transaction(engine) as db:
        job=db.get(Job,jid)
        assert job.status=='cancelled' and job.finished and job.payload=={}
    detail=browser.get('/jobs/'+jid)
    assert detail.status_code==200 and 'Retry job' in detail.text


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
    assert post(browser,'/peer-groups/manual',label='forbidden').status_code==403
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


def test_environment_discovery_metrics_authenticated_and_counts_only(browser, engine):
    response = browser.get("/api/behavioral-discovery/metrics")
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["detector"] == "DS-BEH-001"
    assert report["behavioral_enabled"] is True
    assert report["findings_total"] == 0
    assert report["minimum_fleet_hosts"] == 50
    assert report["includes_endpoints_or_executable_names"] is False
    assert "workstation.example" not in response.text



def test_behavioral_pipeline_aggregates_only_recent_daily_counts(browser, engine):
    from deepsnout.db import set_state
    from deepsnout.db import now as utc_now
    day = int(utc_now()) // 86400
    with transaction(engine) as db:
        set_state(db, "behavioral_discovery_pipeline", {
            "schema": 1, "last_updated": utc_now(),
            "by_day": {
                str(day): {"event1_recent": 23, "fleet_reference_eligible": 7},
                str(day-1): {"event1_recent": 10},
                str(day-9): {"event1_recent": 400},
            },
        })
    payload = browser.get("/api/behavioral-discovery/metrics").json()
    assert payload["findings_last_7d"] == 0
    assert payload["evaluation_pipeline_last_7d"]["event1_recent"] == 33
    assert payload["evaluation_pipeline_last_7d"]["fleet_reference_eligible"] == 7
    assert payload["evaluation_counts_are_events_not_distinct_hosts"]
    assert "400" not in str(payload["evaluation_pipeline_last_7d"])



def _insert_example_table_findings(db):
    """All identities and paths here are synthetic."""
    host = Host(id="test-table-001", name="workstation.example", namespace="test",
                cohort="unassigned", first_seen=1760000000, last_seen=1760000100)
    other = Host(id="test-table-002", name="=FAKE_FORMULA()", namespace="test",
                 cohort="unassigned", first_seen=1760000000, last_seen=1760000100)
    db.add_all([host, other])
    db.flush()
    evidence = {
        "process": {"parent": "explorer.exe",
                    "app": "utility.exe",
                    "image": r"C:\Program Files\PrivateSuite\utility.exe",
                    "location": "program-files"},
        "environment": {"category": "rare_application",
                        "reference": {"fleet_application_hosts": 1,
                                      "fleet_hosts_with_process_coverage": 800}},
    }
    f1 = Finding(host_id=host.id, detector="DS-BEH-001", context="first",
                 title="Uncommon application", summary="Synthetic", priority="review",
                 state="new", first_seen=1760000001, last_seen=1760000101,
                 evidence=evidence)
    f2 = Finding(host_id=other.id, detector="DS-NET-001", context="other",
                 title="Sustained network change", summary="Synthetic", priority="review",
                 state="investigating", first_seen=1760000201, last_seen=1760000201,
                 evidence={"app": "msedge.exe", "location": "program-files",
                           "current": 60, "baseline_p95": 8})
    f3 = Finding(host_id=host.id, detector="DS-BEH-001", context="third",
                 title="Uncommon launch", summary="Synthetic", priority="review",
                 state="resolved", first_seen=1760000301, last_seen=1760000301,
                 evidence={"process": {"parent": "winword.exe",
                                       "image": r"C:\Temp\candidate.exe",
                                       "location": "temporary"},
                           "environment": {"category": "rare_launch_relationship",
                                           "reference": {"fleet_launch_relationship_hosts": 0,
                                                         "fleet_application_hosts": 500}}})
    db.add_all([f1, f2, f3])
    db.flush()
    return (f1.id, f2.id, f3.id)


def test_findings_table_filters_global_sort_and_details_link(browser, engine):
    with transaction(engine) as db:
        first, network, closed = _insert_example_table_findings(db)
    main = browser.get("/findings/table")
    assert main.status_code == 200, main.text
    assert "Findings table" in main.text
    assert "2</strong> matching findings" in main.text
    assert r"C:\Program Files\PrivateSuite\utility.exe" in main.text
    assert "explorer.exe" in main.text
    assert "path unavailable" in main.text
    assert "Rare application (1/800 hosts)" in main.text
    assert f'/findings/{first}' in main.text
    assert f'/findings/{network}' in main.text
    assert closed not in main.text
    assert main.text.index("=FAKE_FORMULA()") < main.text.index("workstation.example")
    # Detector, category, host/process search, state and SQL JSON-based sorting.
    filtered = browser.get("/findings/table", params={
        "status": "all", "detector": "DS-BEH-001",
        "category": "rare_launch_relationship"})
    assert filtered.status_code == 200
    assert "winword.exe" in filtered.text
    assert '<td class="table-executable">explorer.exe</td>' not in filtered.text
    searched = browser.get("/findings/table", params={"q": "PRIVATEsuite"})
    assert searched.status_code == 200
    assert "utility.exe" in searched.text
    assert "msedge.exe" not in searched.text
    sorted_page = browser.get("/findings/table", params={
        "status": "all", "sort": "parent", "order": "desc"})
    assert sorted_page.status_code == 200
    assert (sorted_page.text.index('<td class="table-executable">winword.exe</td>')
            < sorted_page.text.index('<td class="table-executable">explorer.exe</td>'))
    assert "Findings table" in browser.get("/").text


def test_csv_export_matches_filters_and_sanitizes_sensitive_columns(browser, engine):
    import csv
    import io
    with transaction(engine) as db:
        _insert_example_table_findings(db)
    full = browser.get("/findings/table.csv", params={
        "detector": "DS-BEH-001", "status": "all", "sort": "process", "order": "asc"})
    assert full.status_code == 200, full.text
    assert "attachment;" in full.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(full.content.decode("utf-8-sig"))))
    assert rows[0] == ["Last seen (UTC)", "Detector", "Hostname", "Parent", "Process (path)", "Trigger"]
    assert len(rows) == 3
    assert all(row[1] == "DS-BEH-001" for row in rows[1:])
    assert rows[1][4].startswith(r"C:\Program Files")
    assert rows[2][4].startswith(r"C:\Temp")
    assert "workstation.example" in full.text

    reduced = browser.get("/findings/table.csv", params={
        "detector": "DS-BEH-001", "status": "all", "privacy": "reduced"})
    assert reduced.status_code == 200
    parsed = list(csv.reader(io.StringIO(reduced.content.decode("utf-8-sig"))))
    assert len(parsed) == 3
    assert parsed[1][2] == parsed[2][2]
    assert parsed[1][2].startswith("host-")
    assert parsed[1][4] in (r"temporary\candidate.exe", r"program-files\utility.exe")
    assert "workstation.example" not in reduced.text
    assert "PrivateSuite" not in reduced.text
    assert r"C:\Temp" not in reduced.text
    assert "FAKE_FORMULA" not in reduced.text
    assert "private" in reduced.headers["content-disposition"]

    full_all = browser.get("/findings/table.csv", params={"status": "all"})
    parsed_all = list(csv.reader(io.StringIO(full_all.content.decode("utf-8-sig"))))
    assert len(parsed_all) == 4
    # Spreadsheet cells starting with formula-like content are escaped.
    malicious_host_row = next(row for row in parsed_all[1:] if row[1] == "DS-NET-001")
    assert malicious_host_row[2].startswith("'=")
    assert browser.get("/findings/table.csv", params={"privacy": "unknown"}).status_code == 400


def test_table_export_all_filtered_rows_not_only_current_page(browser, engine):
    from conftest import CLOCK
    with transaction(engine) as db:
        host = Host(id="big-table-host", name="table.example", namespace="test",
                    cohort="unassigned", first_seen=CLOCK-4000, last_seen=CLOCK)
        db.add(host)
        db.flush()
        db.add_all([
            Finding(host_id=host.id, detector="DS-BEH-001",
                    context=f"context-{i}", title="Rare behavior",
                    summary="Synthetic", state="new", priority="review",
                    first_seen=CLOCK-i, last_seen=CLOCK-i,
                    evidence={"process": {"parent": "explorer.exe",
                                          "image": rf"C:\Program Files\tool{i}.exe"}})
            for i in range(102)])
    first = browser.get("/findings/table", params={"detector": "DS-BEH-001"})
    second = browser.get("/findings/table", params={"detector": "DS-BEH-001", "page": 2})
    assert "102</strong> matching findings" in first.text
    assert first.text.count('title="Open finding details"') == 100
    assert second.text.count('title="Open finding details"') == 2
    assert "tool101.exe" in second.text
    response = browser.get("/findings/table.csv", params={"detector": "DS-BEH-001"})
    import csv
    import io
    rows = list(csv.reader(io.StringIO(response.content.decode("utf-8-sig"))))
    assert len(rows) == 103


def test_table_and_csv_require_authentication(engine, config):
    app = create_app(config)
    with TestClient(app, follow_redirects=False) as guest:
        assert guest.get("/findings/table").status_code == 303
        assert guest.get("/findings/table.csv").status_code == 303
    app.state.engine.dispose()



def _seed_finding_quality_example(db):
    """This test never contains customer or actual detection names."""
    from deepsnout.db import now
    stamp = now()
    hosts = [
        Host(id=f"quality-host-{i}", name=f"quality-{i}.example",
             namespace="synthetic", cohort="unassigned",
             first_seen=stamp-3600, last_seen=stamp)
        for i in range(6)
    ]
    db.add_all(hosts)
    db.flush()
    for i in range(18):
        basename = f"SupportPackage_6.12.{i%3}.0.exe"
        db.add(Finding(
            host_id=hosts[i%len(hosts)].id,
            detector="DS-BEH-001", context=f"quality-{i}",
            title="Synthetic local novelty", summary="Synthetic",
            priority="review", state="new",
            first_seen=stamp-60-i, last_seen=stamp-60-i,
            created=stamp-30,
            evidence={
                "process": {
                    "app": basename.lower(), "parent": "installer-agent.exe",
                    "location": "program-files",
                    "image": rf"C:\Program Files\Demo\{basename}",
                },
                "environment": {"category": "rare_application"},
            },
        ))
    # A non-execution finding must be included in total but not grouped.
    db.add(Finding(
        host_id=hosts[0].id, detector="DS-NET-001", context="net",
        title="Synthetic network finding", summary="Synthetic",
        priority="review", state="new",
        first_seen=stamp-100, last_seen=stamp-100,
        created=stamp-30, evidence={"app": "updater.exe"},
    ))
    # A second independent finding reaches the 20-finding concentration floor.
    db.add(Finding(
        host_id=hosts[1].id, detector="DS-NET-001", context="net-second",
        title="Another unrelated synthetic finding", summary="Synthetic",
        priority="review", state="new",
        first_seen=stamp-105, last_seen=stamp-105,
        created=stamp-30, evidence={"app": "other-network.exe"},
    ))
    # Synthetic demo observations are excluded from operational reporting.
    demo = Host(id="quality-demo", name="demo.example", namespace="demo",
                cohort="unassigned", first_seen=stamp-3600, last_seen=stamp)
    db.add(demo)
    db.flush()
    db.add(Finding(
        host_id=demo.id, detector="DS-BEH-001", context="ignored",
        title="Excluded synthetic demo", summary="Synthetic",
        priority="review", state="new", first_seen=stamp-50, last_seen=stamp-50,
        created=stamp-30, evidence={
            "process": {"image": "demo.exe", "parent": "unknown",
                        "location": "other"},
        },
    ))


def test_finding_quality_gui_scheduler_metrics_and_drilldown(browser, engine, config):
    from deepsnout.db import State
    from deepsnout.worker import enqueue
    initial = browser.get("/finding-quality")
    assert initial.status_code == 200
    assert "No analysis snapshot yet" in initial.text
    empty = browser.get("/api/finding-quality/metrics").json()
    assert empty["updated_at"] is None

    with transaction(engine) as db:
        _seed_finding_quality_example(db)
        job = enqueue(db, "finding_quality", {"origin": "operator"})
        jid = job.id

    assert run_job(engine, config, jid)
    report = browser.get("/api/finding-quality/metrics")
    assert report.status_code == 200
    metrics = report.json()
    assert metrics["source_findings"] == 20
    assert metrics["dominant_family_findings"] == 18
    assert metrics["families_discovered"] == 1
    assert metrics["version_churn_families"] == 1
    assert metrics["self_diagnosis"] == "one-family-dominance"
    assert metrics["suppression_allowed"] is False
    assert "SupportPackage" not in report.text
    assert "quality-host" not in report.text

    with transaction(engine) as db:
        snapshot = db.get(State, "finding_quality_snapshot").value
        assert len(snapshot["families"][0]["member_ids"]) == 18
        assert not db.scalar(select(Finding).where(Finding.state != "new"))
        group_id = snapshot["families"][0]["id"]

    page = browser.get("/finding-quality")
    assert page.status_code == 200, page.text
    assert "supportpackage_6.12.*.0.exe" in page.text
    assert "18</strong>" in page.text
    assert "one behavior family" in page.text.lower()
    assert group_id in page.text

    detail = browser.get("/finding-quality/families/" + group_id)
    assert detail.status_code == 200, detail.text
    assert "installer-agent.exe" in detail.text
    assert "quality-1.example" in detail.text
    assert "supportpackage_6.12.*.0.exe" in detail.text
    assert detail.text.count('href="/findings/') >= 18
    assert browser.get("/finding-quality/families/not-a-group").status_code == 404
    assert post(browser, "/finding-quality/refresh").status_code == 303


def test_finding_quality_requires_session_and_write_role(engine, config, browser):
    from fastapi.testclient import TestClient
    client_app = create_app(config)
    with TestClient(client_app, follow_redirects=False) as guest:
        for path in ["/finding-quality", "/api/finding-quality/metrics",
                     "/finding-quality/families/unknown"]:
            assert guest.get(path).status_code == 303
        assert guest.post("/finding-quality/refresh", data={}).status_code == 403
    client_app.state.engine.dispose()

    assert post(browser, "/accounts", username="qualityviewer",
                password="Quality viewer safe test passphrase",
                role="viewer").status_code == 303
    assert post(browser, "/logout").status_code == 303
    browser.get("/login")
    assert post(browser, "/login", username="qualityviewer",
                password="Quality viewer safe test passphrase").status_code == 303
    assert browser.get("/finding-quality").status_code == 200
    assert post(browser, "/finding-quality/refresh").status_code == 403



def test_operations_show_three_workers_and_safe_analysis_backlog(browser, engine):
    from deepsnout.pipeline import stage_observations
    from conftest import evt, CLOCK
    with transaction(engine) as db:
        stage_observations(
            db, [evt(n=71234)], batch_id="synthetic-ui-batch",
            source_id="test-source", namespace="test",
            cohort="unassigned", collected_clock=CLOCK)
    page = browser.get("/operations")
    assert page.status_code == 200
    assert "Ingest worker" in page.text
    assert "Detection · shards 0/2" in page.text
    assert "Detection · shards 1/3" in page.text
    assert "Insight worker" in page.text
    assert "1</strong>" in page.text
    assert "Staged analysis batches" in page.text
    response = browser.get("/api/pipeline/metrics")
    assert response.status_code == 200
    metrics = response.json()
    assert metrics["pending_batches"] == 1
    assert metrics["pending_events"] == 1
    assert metrics["raw_observation_names_included"] is False
    assert "workstation.example" not in response.text
    assert "utility.exe" not in response.text
    assert set(metrics["workers"]) == {
        "ingest", "analysis_0_2", "analysis_1_3", "insight"}


def test_failed_batch_retry_requires_admin_and_preserves_cursor(browser, engine):
    from deepsnout.pipeline import stage_observations
    from deepsnout.db import StagedBatch
    from conftest import evt, CLOCK
    with transaction(engine) as db:
        stage_observations(
            db, [evt(n=71235)], batch_id="synthetic-retry-ui",
            source_id="test-source", namespace="test",
            cohort="unassigned", collected_clock=CLOCK)
        db.flush()
        staged = db.get(StagedBatch, "synthetic-retry-ui")
        staged.status = "failed"
        staged.last_error = "Synthetic test interruption"
    result = post(browser, "/analysis/batches/synthetic-retry-ui/retry")
    assert result.status_code == 303
    with transaction(engine) as db:
        staged = db.get(StagedBatch, "synthetic-retry-ui")
        assert staged.status == "pending" and staged.processed == 0
        assert staged.compressed_events is not None
    assert post(browser, "/analysis/batches/synthetic-retry-ui/retry").status_code == 400



def test_old_failed_batch_surfaces_above_recent_batches_and_has_detail(browser, engine):
    from conftest import evt, CLOCK
    from deepsnout.pipeline import stage_observations
    from deepsnout.db import StagedBatch
    with transaction(engine) as db:
        stage_observations(
            db, [evt(n=71300)], batch_id="old-failed-batch",
            source_id="synthetic-source", namespace="test",
            cohort="unassigned", collected_clock=CLOCK)
        db.flush()
        oldest = db.get(StagedBatch, "old-failed-batch")
        oldest.status = "failed"
        oldest.attempts = 2
        oldest.processed = 0
        oldest.last_error = "IntegrityError (SQLSTATE 23505) at ingest-chunk"
        oldest.stats = {
            "last_failure": {
                "stage": "ingest-chunk",
                "exception_type": "IntegrityError",
                "database_sqlstate": "23505",
                "occurred_at": CLOCK,
                "cursor_before_failure": 0,
                "hint": "Database constraint rejected an analysis write.",
                "message_redacted": True,
            },
            "secret_internal_log": "SECRET-HOST.example --password=PRIVATE",
        }
    # More than 15 newer records: the usual recent-batch table will omit
    # the older failure, but the dedicated failure list must never do so.
    for i in range(20):
        with transaction(engine) as db:
            stage_observations(
                db, [evt(n=71400+i)], batch_id=f"recent-record-{i}",
                source_id="synthetic-source", namespace="test",
                cohort="unassigned", collected_clock=CLOCK+i)
    page = browser.get("/operations")
    assert page.status_code == 200
    assert 'id="failed-analysis"' in page.text
    assert "/analysis/batches/old-failed-batch" in page.text
    assert "IntegrityError (SQLSTATE 23505)" in page.text
    assert "Inspect failures" in page.text
    details = browser.get("/analysis/batches/old-failed-batch")
    assert details.status_code == 200
    for expected in ("PostgreSQL SQLSTATE", "23505", "ingest-chunk",
                     "Retry remaining", "synthetic-source", "2</strong>"):
        assert expected in details.text
    assert "SECRET-HOST" not in details.text
    assert "PRIVATE" not in details.text
    assert "compressed_events" not in details.text
    assert browser.get("/analysis/batches/not-present").status_code == 404
    assert browser.post(
        "/analysis/batches/old-failed-batch/retry",
        data={"csrf": "forged"}).status_code == 403
    response = post(browser, "/analysis/batches/old-failed-batch/retry")
    assert response.status_code == 303
    assert response.headers["location"] == "/analysis/batches/old-failed-batch"
    with transaction(engine) as db:
        batch = db.get(StagedBatch, "old-failed-batch")
        assert batch.status == "pending"
        assert batch.processed == 0
        assert batch.stats["last_failure"]["database_sqlstate"] == "23505"
        assert batch.stats["last_retry_at"] > 0
    assert "Retry remaining" not in browser.get(
        "/analysis/batches/old-failed-batch").text


def test_batch_detail_requires_admin(browser, engine, config):
    from fastapi.testclient import TestClient
    from deepsnout.web import create_app
    app = create_app(config)
    with TestClient(app, follow_redirects=False) as guest:
        assert guest.get("/analysis/batches/not-present").status_code == 303
        assert guest.get("/operations").status_code == 303
        assert guest.post("/analysis/batches/not-present/retry",
                          data={}).status_code == 403
    app.state.engine.dispose()
    assert post(browser, "/accounts", username="batchviewer",
                password="Viewer safe synthetic passphrase",
                role="viewer").status_code == 303
    assert post(browser, "/logout").status_code == 303
    browser.get("/login")
    assert post(browser, "/login", username="batchviewer",
                password="Viewer safe synthetic passphrase").status_code == 303
    assert browser.get("/analysis/batches/not-present").status_code == 403
    assert browser.get("/operations").status_code == 403
    assert post(browser, "/analysis/batches/not-present/retry").status_code == 403
