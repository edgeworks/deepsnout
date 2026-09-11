"""Authenticated, server-rendered GUI; collection and analysis run in the worker."""
from collections import defaultdict
from datetime import datetime, timezone
import hmac
import json
from pathlib import Path
import re
import secrets
from urllib.parse import urlsplit
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy import select, func, delete
from . import __version__
from .config import Config, Policy
from .db import (make_engine, initialize, transaction, User, LoginSession, Source,
                 Job, Host, Coverage, BehaviorDay, Finding, Expectation, Audit,
                 State, Seen, Process, Window, policy, now, set_state, audit)
from .security import (initialize_secrets, csrf_token, check_csrf, token_hash,
                       PASSWORDS, check_password, validate_password, crypto)
from .normalize import parse_payload, digest
from .splunk import SplunkSettings, validate_url
from .worker import enqueue
from .engine import EXPECTABLE
from .features import psl_available

BASE = Path(__file__).parent


class TooLarge(Exception):
    pass


class SafetyMiddleware:
    def __init__(self, app, config):
        self.app, self.config = app, config

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        hosts = [v.decode("latin1") for k, v in scope.get("headers", []) if k.lower() == b"host"]
        allowed = {v.strip().lower().strip("[]") for v in self.config.allowed_hosts.split(",")}
        try:
            parsed = urlsplit("http://" + hosts[0]) if len(hosts) == 1 else None
            valid = (parsed and parsed.hostname in allowed and not parsed.username and not parsed.password
                     and not parsed.path and not parsed.query and not parsed.fragment)
        except ValueError:
            valid = False
        if not valid:
            return await JSONResponse({"detail": "Host not allowed; configure DEEPSNOUT_ALLOWED_HOSTS"}, 400)(scope, receive, send)
        consumed = 0
        async def bounded_receive():
            nonlocal consumed
            message = await receive()
            consumed += len(message.get("body", b""))
            if consumed > self.config.maximum_body:
                raise TooLarge()
            return message
        async def safe_send(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers += [(b"x-content-type-options", b"nosniff"), (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"), (b"cache-control", b"no-store"),
                    (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")]
                if self.config.secure_cookies:
                    headers.append((b"strict-transport-security", b"max-age=31536000"))
                message["headers"] = headers
            await send(message)
        await self.app(scope, bounded_receive, safe_send)


def create_app(config=None):
    config = config or Config()
    initialize_secrets(config.data_dir)
    engine = make_engine(config)
    initialize(engine)
    app = FastAPI(title="DeepSnout", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.engine, app.state.config = engine, config
    app.add_middleware(SafetyMiddleware, config=config)
    app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
    templates = Jinja2Templates(directory=BASE / "templates")
    templates.env.filters["utc"] = lambda v: datetime.fromtimestamp(float(v), timezone.utc).strftime("%d %b %Y %H:%M UTC") if v else "Not yet"
    templates.env.filters["pretty"] = lambda x: json.dumps(x, indent=2, sort_keys=True)
    attempts = defaultdict(list)

    def login_user(request, db, roles=None):
        token = request.cookies.get("ds_session", "")
        session = db.get(LoginSession, token_hash(token)) if token else None
        user = db.get(User, session.user_id) if session and session.expires > now() else None
        if not user or not user.active:
            raise HTTPException(303, headers={"Location": "/login"})
        if roles and user.role not in roles:
            raise HTTPException(403, "Your role cannot perform this action")
        return user

    async def form_data(request):
        form = await request.form(max_files=1, max_fields=40, max_part_size=config.maximum_body)
        if not check_csrf(config, request.cookies.get("ds_csrf", ""), str(form.get("csrf", ""))):
            raise HTTPException(403, "Form expired or CSRF check failed; reload the page")
        return form

    def view(request, name, **context):
        csrf = request.cookies.get("ds_csrf", "")
        if not check_csrf(config, csrf, csrf):
            csrf = csrf_token(config)
        context.update({"csrf": csrf, "version": __version__, "secure": config.secure_cookies,
                        "path": request.url.path, "now": now()})
        response = templates.TemplateResponse(request=request, name=name, context=context)
        response.set_cookie("ds_csrf", csrf, max_age=86400, httponly=True,
                            secure=config.secure_cookies, samesite="strict")
        return response

    def rate_limit(request):
        ip = request.client.host if request.client else "unknown"
        attempts[ip] = [t for t in attempts[ip] if now() - t < 300]
        if len(attempts[ip]) >= 15:
            raise HTTPException(429, "Too many attempts; wait five minutes")
        attempts[ip].append(now())
        if len(attempts) > 4096:
            attempts.pop(next(iter(attempts)))

    def found(db, cls, key):
        obj = db.get(cls, key)
        if obj is None:
            raise HTTPException(404, "Record not found")
        return obj

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        if exc.status_code == 303:
            return RedirectResponse(exc.headers["Location"], 303)
        return HTMLResponse(templates.get_template("error.html").render(error=str(exc.detail), status=exc.status_code), exc.status_code)

    @app.exception_handler(TooLarge)
    async def too_large(request, exc):
        return JSONResponse({"detail": "Request exceeds the configured size limit"}, 413)

    @app.exception_handler(ValueError)
    async def invalid_value(request, exc):
        message = "; ".join(e["msg"] for e in exc.errors()) if isinstance(exc, ValidationError) else str(exc)
        return HTMLResponse(templates.get_template("error.html").render(error=message, status=400), 400)

    @app.get("/healthz")
    def health():
        with transaction(engine) as db:
            db.execute(select(1))
        return {"status": "ok", "version": __version__}

    @app.get("/setup")
    def setup_page(request: Request):
        with transaction(engine) as db:
            if db.scalar(select(func.count()).select_from(User)):
                return RedirectResponse("/login", 303)
        return view(request, "auth.html", setup=True)

    @app.post("/setup")
    async def setup(request: Request):
        form = await form_data(request)
        rate_limit(request)
        expected = (config.data_dir / "setup_token").read_text().strip()
        if not hmac.compare_digest(str(form.get("setup_token", "")).encode(), expected.encode()):
            raise HTTPException(403, "Invalid setup token")
        username, password = str(form.get("username", "")).lower().strip(), str(form.get("password", ""))
        if not re.fullmatch(r"[a-z0-9_.@-]{3,80}", username):
            raise ValueError("Username must contain 3-80 letters, digits or . _ @ -")
        validate_password(password)
        with transaction(engine) as db:
            db.scalar(select(State).where(State.key == "schema_version").with_for_update())
            if db.scalar(select(func.count()).select_from(User)):
                raise HTTPException(409, "Setup has already been completed")
            db.add(User(username=username, password=PASSWORDS.hash(password), role="admin"))
            audit(db, username, "setup.completed", "application")
        return RedirectResponse("/login", 303)

    @app.get("/login")
    def login_page(request: Request):
        with transaction(engine) as db:
            if not db.scalar(select(func.count()).select_from(User)):
                return RedirectResponse("/setup", 303)
        return view(request, "auth.html", setup=False)

    @app.post("/login")
    async def login(request: Request):
        form = await form_data(request)
        rate_limit(request)
        with transaction(engine) as db:
            user = db.scalar(select(User).where(User.username == str(form.get("username", "")).lower().strip()))
            if not user or not user.active or not check_password(user.password, str(form.get("password", ""))):
                raise HTTPException(401, "Invalid username or password")
            token = secrets.token_urlsafe(32)
            old = request.cookies.get("ds_session", "")
            if old:
                db.execute(delete(LoginSession).where(LoginSession.key == token_hash(old)))
            db.add(LoginSession(key=token_hash(token), user_id=user.id, expires=now() + config.session_seconds))
            audit(db, user.username, "login", user.id)
        response = RedirectResponse("/", 303)
        response.set_cookie("ds_session", token, max_age=config.session_seconds,
                            httponly=True, secure=config.secure_cookies, samesite="lax")
        return response

    @app.post("/logout")
    async def logout(request: Request):
        await form_data(request)
        with transaction(engine) as db:
            db.execute(delete(LoginSession).where(LoginSession.key == token_hash(request.cookies.get("ds_session", ""))))
        response = RedirectResponse("/login", 303)
        response.delete_cookie("ds_session")
        return response

    @app.get("/")
    def inbox(request: Request, status: str = "open", q: str = "", page: int = 1):
        with transaction(engine) as db:
            user = login_user(request, db)
            query = select(Finding, Host).join(Host)
            if status == "open":
                query = query.where(Finding.state.in_(["new", "investigating", "malicious"]))
            elif status != "all":
                query = query.where(Finding.state == status)
            if q:
                query = query.where(Host.name.ilike("%" + q[:100] + "%"))
            total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
            rows = db.execute(query.order_by((Finding.priority == "high").desc(), Finding.last_seen.desc()).offset((max(1, page)-1)*30).limit(30)).all()
            counts = {"open": db.scalar(select(func.count()).select_from(Finding).where(Finding.active_key.is_not(None))),
                "endpoints": db.scalar(select(func.count()).select_from(Host)),
                "sources": db.scalar(select(func.count()).select_from(Source).where(Source.enabled.is_(True)))}
            return view(request, "inbox.html", user=user, rows=rows, counts=counts, total=total, status=status, q=q, page=max(1,page))

    @app.get("/findings/{finding_id}")
    def finding_page(request: Request, finding_id: str):
        with transaction(engine) as db:
            user = login_user(request, db)
            f = found(db, Finding, finding_id)
            history = db.scalars(select(Audit).where(Audit.target == finding_id).order_by(Audit.created.desc()).limit(30)).all()
            return view(request, "finding.html", user=user, f=f, host=db.get(Host,f.host_id), history=history,
                        can_expect=f.detector in EXPECTABLE and f.state != "malicious")

    @app.post("/findings/{finding_id}/state")
    async def update_finding(request: Request, finding_id: str):
        form = await form_data(request)
        state, reason = str(form.get("state","")), str(form.get("reason","")).strip()[:2000]
        if state not in {"new","investigating","resolved","malicious"} or len(reason)<5:
            raise ValueError("Select a valid state and add a short investigation note")
        with transaction(engine) as db:
            user = login_user(request, db, {"admin","analyst"})
            f = found(db, Finding, finding_id)
            if state != "resolved":
                key = digest(f.host_id,f.detector,f.context)
                if db.scalar(select(Finding).where(Finding.active_key==key, Finding.id != f.id)):
                    raise ValueError("A newer finding for this context is already open; update it instead")
                f.active_key, f.closed = key, None
            else:
                f.active_key, f.closed = None, now()
            f.state = state
            if state == "malicious":
                for w in db.scalars(select(Window).where(Window.host_id==f.host_id,
                        Window.start>=f.first_seen-3600, Window.start<=f.last_seen)):
                    w.reference_ok=False
            audit(db,user.username,"finding."+state,f.id,reason)
        return RedirectResponse("/findings/"+finding_id,303)

    @app.get("/findings/{finding_id}/expect")
    def expectation_preview(request: Request, finding_id: str):
        with transaction(engine) as db:
            user=login_user(request,db,{"admin","analyst"})
            f=found(db,Finding,finding_id)
            if f.detector not in EXPECTABLE or f.state=="malicious":
                raise HTTPException(400,"Expectation not allowed for this finding")
            matches=db.scalar(select(func.count()).select_from(Finding).where(
                Finding.host_id==f.host_id,Finding.detector==f.detector,Finding.context==f.context))
            return view(request,"expect.html",user=user,f=f,host=db.get(Host,f.host_id),matches=matches)

    @app.post("/findings/{finding_id}/expect")
    async def add_expectation(request: Request, finding_id: str):
        form=await form_data(request)
        days,reason=int(str(form.get("days","30"))),str(form.get("reason","")).strip()[:2000]
        if not 1<=days<=90 or len(reason)<10:
            raise ValueError("Use 1-90 days and an explanation of at least 10 characters")
        with transaction(engine) as db:
            user=login_user(request,db,{"admin","analyst"}); f=found(db,Finding,finding_id)
            if f.detector not in EXPECTABLE or f.state=="malicious":
                raise HTTPException(400,"Expectation not allowed for this finding")
            db.add(Expectation(host_id=f.host_id,detector=f.detector,context=f.context,
                owner=user.username,reason=reason,expires=now()+days*86400))
            f.state,f.active_key,f.closed="expected",None,now()
            audit(db,user.username,"finding.expected",f.id,reason)
        return RedirectResponse("/expectations",303)

    @app.get("/expectations")
    def expectations(request: Request):
        with transaction(engine) as db:
            user=login_user(request,db)
            rows=db.execute(select(Expectation,Host).join(Host).order_by(Expectation.created.desc()).limit(200)).all()
            return view(request,"expectations.html",user=user,rows=rows)

    @app.post("/expectations/{expectation_id}/revoke")
    async def revoke(request: Request, expectation_id: str):
        await form_data(request)
        with transaction(engine) as db:
            user=login_user(request,db,{"admin","analyst"})
            found(db,Expectation,expectation_id).revoked=True
            audit(db,user.username,"expectation.revoked",expectation_id)
        return RedirectResponse("/expectations",303)

    @app.get("/discover")
    def discover(request: Request,q: str=""):
        with transaction(engine) as db:
            user=login_user(request,db)
            query=select(BehaviorDay.host_id,Host.name,Host.namespace,BehaviorDay.context,BehaviorDay.app,
                BehaviorDay.parent,BehaviorDay.location,func.min(BehaviorDay.first_seen).label("first"),
                func.max(BehaviorDay.last_seen).label("last"),func.count().label("days"),
                func.sum(BehaviorDay.count).label("count")).join(Host).group_by(
                BehaviorDay.host_id,Host.name,Host.namespace,BehaviorDay.context,BehaviorDay.app,BehaviorDay.parent,BehaviorDay.location)
            if q:
                query=query.where(Host.name.ilike("%"+q[:100]+"%") | BehaviorDay.app.ilike("%"+q[:100]+"%"))
            rows=db.execute(query.order_by(func.min(BehaviorDay.first_seen).desc()).limit(100)).all()
            return view(request,"discover.html",user=user,rows=rows,q=q)

    @app.get("/endpoints")
    def endpoints(request: Request,q: str="",page: int=1):
        with transaction(engine) as db:
            user=login_user(request,db)
            query=select(Host)
            if q: query=query.where(Host.name.ilike("%"+q[:100]+"%"))
            total=db.scalar(select(func.count()).select_from(query.subquery()))
            rows=db.scalars(query.order_by(Host.last_seen.desc()).offset((max(1,page)-1)*50).limit(50)).all()
            return view(request,"endpoints.html",user=user,rows=rows,q=q,total=total,page=max(1,page))

    @app.get("/endpoints/{host_id}")
    def endpoint_page(request: Request,host_id: str):
        with transaction(engine) as db:
            user=login_user(request,db); host=found(db,Host,host_id)
            coverage=db.execute(select(Coverage.event_id,func.count().label("days"),
                func.sum(Coverage.count).label("count")).where(Coverage.host_id==host_id).group_by(Coverage.event_id)).all()
            findings=db.scalars(select(Finding).where(Finding.host_id==host_id).order_by(Finding.last_seen.desc()).limit(50)).all()
            return view(request,"endpoint.html",user=user,host=host,coverage=coverage,findings=findings)

    @app.post("/endpoints/{host_id}/cohort")
    async def cohort(request: Request,host_id: str):
        form=await form_data(request); value=str(form.get("cohort","")).strip().lower()
        if not re.fullmatch(r"[a-z0-9_-]{1,80}",value):
            raise ValueError("Use a short cohort name containing letters, numbers, - or _")
        with transaction(engine) as db:
            user=login_user(request,db,{"admin","analyst"})
            found(db,Host,host_id).cohort=value
            audit(db,user.username,"endpoint.cohort",host_id,value)
        return RedirectResponse("/endpoints/"+host_id,303)

    @app.get("/sources")
    def sources(request: Request,edit: str=""):
        with transaction(engine) as db:
            user=login_user(request,db,{"admin"}); source=db.get(Source,edit) if edit else None
            values=source.config if source else SplunkSettings(url="",indexes="placeholder").model_dump()
            if not source: values["indexes"]=""
            return view(request,"sources.html",user=user,rows=db.scalars(select(Source)).all(),source=source,values=values)

    @app.post("/sources/save")
    async def save_source(request: Request):
        form=await form_data(request)
        settings=SplunkSettings.model_validate({key:form[key] for key in SplunkSettings.model_fields if key in form})
        settings.url=validate_url(settings.url,config.allow_http_connectors)
        name,namespace=str(form.get("name","")).strip()[:100],str(form.get("namespace","default")).strip().lower()
        if not name or not re.fullmatch(r"[a-z0-9_-]{1,80}",namespace) or namespace=="demo":
            raise ValueError("Supply a source name and namespace; demo is reserved for synthetic data")
        with transaction(engine) as db:
            user=login_user(request,db,{"admin"}); source=db.get(Source,str(form.get("id","")))
            if source:
                busy=db.scalar(select(Job).where(Job.source_id==source.id,Job.status.in_(["queued","running"])))
                if source.enabled or busy:
                    raise ValueError("Pause the source and wait for pending jobs before editing")
                if source.namespace!=namespace:
                    raise ValueError("Namespace cannot be changed; add a separate source")
            else:
                source=Source(name=name,namespace=namespace,kind="splunk",config={}); db.add(source)
            credential=str(form.get("credential","")).strip()
            if credential:
                if len(credential)>8192 or "\n" in credential or "\r" in credential:
                    raise ValueError("Invalid token")
                source.credential=crypto(config).encrypt(credential.encode()).decode()
            if not source.credential: raise ValueError("A dedicated Splunk token is required")
            source.name,source.config=name,settings.model_dump()
            if form.get("reset_cursor"): source.checkpoint=None
            db.flush(); audit(db,user.username,"source.saved",source.id,"Credentials omitted from audit")
        return RedirectResponse("/sources",303)

    @app.post("/sources/{source_id}/{action}")
    async def source_action(request: Request,source_id: str,action: str):
        await form_data(request)
        with transaction(engine) as db:
            user=login_user(request,db,{"admin"}); source=found(db,Source,source_id)
            if action in {"poll","test"}:
                destination="/jobs/"+enqueue(db,action,source_id=source_id).id
            elif action=="toggle":
                source.enabled=not source.enabled; destination="/sources"
            else: raise ValueError("Unknown source action")
            audit(db,user.username,"source."+action,source_id)
        return RedirectResponse(destination,303)

    @app.get("/imports")
    def imports(request: Request):
        with transaction(engine) as db:
            return view(request,"imports.html",user=login_user(request,db,{"admin"}))

    @app.post("/imports")
    async def upload(request: Request):
        form=await form_data(request)
        with transaction(engine) as db:
            username=login_user(request,db,{"admin"}).username
        file=form.get("file")
        body=await file.read(config.maximum_body+1) if hasattr(file,"read") and getattr(file,"filename","") else str(form.get("text","")).encode()
        if len(body)>config.maximum_body: raise HTTPException(413,"Import exceeds 10 MiB")
        namespace=str(form.get("namespace","default")).strip().lower()
        if not re.fullmatch(r"[a-z0-9_-]{1,80}",namespace) or namespace=="demo":
            raise ValueError("Invalid or reserved namespace")
        records,report=parse_payload(body,config.maximum_import_events)
        if not records or report["invalid"]:
            raise ValueError("Import rejected before writing: "+json.dumps(report))
        batch=digest("import",namespace,sorted(e.id for e in records))
        with transaction(engine) as db:
            job=enqueue(db,"import",{"events":[e.to_dict() for e in records],"namespace":namespace,
                        "batch_id":batch,"parse_report":report})
            audit(db,username,"import.queued",job.id,f"{len(records)} normalized events; raw input discarded")
            destination="/jobs/"+job.id
        return RedirectResponse(destination,303)

    async def queue_action(request,kind):
        await form_data(request)
        with transaction(engine) as db:
            user=login_user(request,db,{"admin"}); job=enqueue(db,kind)
            audit(db,user.username,kind+".queued",job.id)
            destination="/jobs/"+job.id
        return RedirectResponse(destination,303)

    @app.post("/demo")
    async def demo(request: Request):
        return await queue_action(request,"demo")

    @app.post("/demo/remove")
    async def remove_demo(request: Request):
        return await queue_action(request,"remove_demo")

    @app.post("/maintenance")
    async def maintain(request: Request):
        return await queue_action(request,"maintenance")

    @app.get("/jobs/{job_id}")
    def job_page(request: Request,job_id: str):
        with transaction(engine) as db:
            user=login_user(request,db,{"admin"})
            return view(request,"job.html",user=user,job=found(db,Job,job_id))

    @app.post("/jobs/{job_id}/retry")
    async def retry(request: Request,job_id: str):
        await form_data(request)
        with transaction(engine) as db:
            user=login_user(request,db,{"admin"}); job=found(db,Job,job_id)
            if job.status!="failed": raise ValueError("Only failed jobs can be retried")
            if job.source_id and db.scalar(select(Job).where(Job.source_id==job.source_id,
                    Job.id!=job.id,Job.status.in_(["queued","running"]))):
                raise ValueError("This source already has a pending job")
            job.status,job.error,job.finished="queued","",0
            audit(db,user.username,"job.retry",job_id)
        return RedirectResponse("/jobs/"+job_id,303)

    @app.get("/operations")
    def operations(request: Request):
        with transaction(engine) as db:
            user=login_user(request,db,{"admin"})
            states={r.key:r.value for r in db.scalars(select(State))}
            counts={m.__tablename__:db.scalar(select(func.count()).select_from(m))
                    for m in [Host,Seen,Process,BehaviorDay,Window,Finding]}
            orphan=db.scalar(select(func.count()).select_from(Process).where(Process.created.is_(None)))
            jobs=db.scalars(select(Job).order_by(Job.created.desc()).limit(40)).all()
            logs=db.scalars(select(Audit).order_by(Audit.created.desc()).limit(60)).all()
            return view(request,"operations.html",user=user,states=states,counts=counts,jobs=jobs,logs=logs,orphan=orphan,psl=psl_available())

    @app.get("/settings")
    def settings_page(request: Request):
        with transaction(engine) as db:
            return view(request,"settings.html",user=login_user(request,db,{"admin"}),settings=policy(db).model_dump())

    @app.post("/settings")
    async def settings_update(request: Request):
        form=await form_data(request)
        values={k:form[k] for k in Policy.model_fields if k in form}
        for k in ("execution_enabled","contextual_enabled","network_enabled"): values[k]=form.get(k)=="on"
        new=Policy.model_validate(values)
        with transaction(engine) as db:
            user=login_user(request,db,{"admin"}); set_state(db,"policy",new.model_dump())
            audit(db,user.username,"policy.saved","analysis",json.dumps(new.model_dump()))
        return RedirectResponse("/settings",303)

    @app.get("/accounts")
    def accounts_page(request: Request):
        with transaction(engine) as db:
            user=login_user(request,db)
            rows=db.scalars(select(User).order_by(User.username)).all() if user.role=="admin" else []
            return view(request,"accounts.html",user=user,rows=rows)

    @app.post("/accounts")
    async def add_account(request: Request):
        form=await form_data(request)
        username=str(form.get("username","")).lower().strip()
        password,role=str(form.get("password","")),str(form.get("role","analyst"))
        validate_password(password)
        if not re.fullmatch(r"[a-z0-9_.@-]{3,80}",username) or role not in {"admin","analyst","viewer"}:
            raise ValueError("Invalid username or role")
        with transaction(engine) as db:
            user=login_user(request,db,{"admin"})
            if db.scalar(select(User).where(User.username==username)): raise ValueError("Username already exists")
            db.add(User(username=username,password=PASSWORDS.hash(password),role=role))
            audit(db,user.username,"account.created",username,role)
        return RedirectResponse("/accounts",303)

    @app.post("/accounts/{user_id}/toggle")
    async def toggle_account(request: Request,user_id: str):
        await form_data(request)
        with transaction(engine) as db:
            user=login_user(request,db,{"admin"}); target=found(db,User,user_id)
            if target.id==user.id: raise ValueError("You cannot deactivate your own account")
            target.active=not target.active
            db.execute(delete(LoginSession).where(LoginSession.user_id==user_id))
            audit(db,user.username,"account.active",user_id,str(target.active))
        return RedirectResponse("/accounts",303)

    @app.post("/accounts/{user_id}/manage")
    async def manage_account(request: Request,user_id: str):
        form=await form_data(request); role,password=str(form.get("role","")),str(form.get("password",""))
        if role not in {"admin","analyst","viewer"}: raise ValueError("Invalid role")
        if password: validate_password(password)
        with transaction(engine) as db:
            user=login_user(request,db,{"admin"}); target=found(db,User,user_id)
            if target.id==user.id: raise ValueError("Manage other accounts here; use Change passphrase for your own account")
            target.role=role
            if password: target.password=PASSWORDS.hash(password)
            db.execute(delete(LoginSession).where(LoginSession.user_id==user_id))
            audit(db,user.username,"account.updated",user_id,"role="+role+"; password_changed="+str(bool(password)))
        return RedirectResponse("/accounts",303)

    @app.post("/password")
    async def password_change(request: Request):
        form=await form_data(request); password=str(form.get("password","")); validate_password(password)
        with transaction(engine) as db:
            user=login_user(request,db)
            if not check_password(user.password,str(form.get("current_password",""))):
                raise HTTPException(403,"Current password did not match")
            user.password=PASSWORDS.hash(password)
            db.execute(delete(LoginSession).where(LoginSession.user_id==user.id))
            audit(db,user.username,"password.changed",user.id)
        return RedirectResponse("/login",303)

    @app.get("/help")
    def help_page(request: Request):
        with transaction(engine) as db:
            return view(request,"help.html",user=login_user(request,db))

    @app.get("/api/status")
    def api_status(request: Request):
        with transaction(engine) as db:
            login_user(request,db)
            return {"version":__version__,"endpoints":db.scalar(select(func.count()).select_from(Host)),
                    "open_findings":db.scalar(select(func.count()).select_from(Finding).where(Finding.active_key.is_not(None)))}

    @app.get("/findings/{finding_id}/export")
    def export_finding(request: Request,finding_id: str):
        with transaction(engine) as db:
            login_user(request,db); f=found(db,Finding,finding_id)
            return JSONResponse({"id":f.id,"detector":f.detector,"title":f.title,"state":f.state,"evidence":f.evidence},
                headers={"Content-Disposition":'attachment; filename="finding.json"'})
    return app
