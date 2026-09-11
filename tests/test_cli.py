import pytest
from sqlalchemy import select
from deepsnout import cli
from deepsnout.db import transaction,User,LoginSession
from deepsnout.security import PASSWORDS,check_password


def invoke(monkeypatch,config,*args):
    monkeypatch.setattr(cli,'Config',lambda:config)
    monkeypatch.setattr('sys.argv',['deepsnout',*args]); cli.main()


def test_cli_secrets_and_version(monkeypatch,config,capsys):
    invoke(monkeypatch,config,'secrets'); key=(config.data_dir/'app_key').read_bytes()
    invoke(monkeypatch,config,'init'); invoke(monkeypatch,config,'secrets')
    assert (config.data_dir/'app_key').read_bytes()==key
    assert (config.data_dir/'app_key').stat().st_mode & 0o077 == 0
    invoke(monkeypatch,config,'setup-token')
    assert (config.data_dir/'setup_token').read_text() in capsys.readouterr().out
    invoke(monkeypatch,config,'version'); assert '0.1.0a1' in capsys.readouterr().out


def test_password_recovery(monkeypatch,engine,config):
    with transaction(engine) as db:
        user=User(username='admin',role='admin',password=PASSWORDS.hash('old test password'))
        db.add(user); db.flush(); uid=user.id
        db.add(LoginSession(key='old-key',user_id=uid,expires=9999999999))
    monkeypatch.setattr('getpass.getpass',lambda _: 'replacement test passphrase')
    invoke(monkeypatch,config,'reset-password','--username','admin')
    with transaction(engine) as db:
        assert check_password(db.get(User,uid).password,'replacement test passphrase')
        assert not db.scalars(select(LoginSession)).all()


def test_missing_worker_heartbeat(monkeypatch,engine,config):
    with pytest.raises(SystemExit) as result: invoke(monkeypatch,config,'worker-health')
    assert result.value.code==1


def test_db_admin_secret_separate_from_app(monkeypatch,config,tmp_path):
    export=tmp_path/'db-only'/'password'
    monkeypatch.setenv('DEEPSNOUT_DB_SECRET_EXPORT',str(export))
    invoke(monkeypatch,config,'secrets')
    assert export.read_text()==(config.data_dir/'db_password').read_text()
    admin=(export.parent/'admin_password').read_text()
    assert admin!=export.read_text() and not (config.data_dir/'admin_password').exists()
    invoke(monkeypatch,config,'secrets')
    assert (export.parent/'admin_password').read_text()==admin
