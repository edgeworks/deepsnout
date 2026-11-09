"""Authenticated, server-rendered GUI; collection and analysis run in the worker."""
from collections import defaultdict
from datetime import datetime, timezone
import hmac
import json
from pathlib import Path
import re
import secrets
from urllib.parse import urlsplit, urlencode
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy import select, func, delete, or_
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
from .finding_table import finding_csv, finding_table_row
from .finding_quality import finding_quality_state, metrics_from_snapshot
from .features import psl_available
from .analytical_cohorts import analytical_cohort_state, anonymized_cohort_metrics
from .peer_groups import (suggestion_state, peer_group_catalog, approve_suggestion,
                          reject_suggestion, create_manual_group, assign_host_group,
                          group_options as peer_group_options, group_detail)

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

    # This read-only view is intentionally before /findings/{finding_id}.
    # Starlette matches routes in definition order; otherwise "table" becomes an ID.
    TABLE_PAGE_SIZE = 100
    CSV_EXPORT_LIMIT = 10000
    TABLE_STATES = ("open", "new", "investigating", "malicious",
                    "resolved", "expected", "all")
    TABLE_CATEGORIES = ("all", "rare_application", "rare_launch_relationship")
    TABLE_SORTS = ("when", "detector", "hostname", "parent", "process", "trigger")

    def _table_filters(status, detector, category, q, sort, order):
        return {
            "status": status if status in TABLE_STATES else "open",
            "detector": str(detector)[:64],
            "category": category if category in TABLE_CATEGORIES else "all",
            "q": str(q).strip()[:120],
            "sort": sort if sort in TABLE_SORTS else "when",
            "order": order if order in ("asc", "desc") else "desc",
        }

    def _table_query(filters):
        query = select(Finding, Host).join(Host)
        state = filters["status"]
        if state == "open":
            query = query.where(Finding.state.in_(("new", "investigating", "malicious")))
        elif state != "all":
            query = query.where(Finding.state == state)
        if filters["detector"]:
            query = query.where(Finding.detector == filters["detector"])
        if filters["category"] != "all":
            query = query.where(
                Finding.evidence["environment"]["category"].as_string()
                == filters["category"])
        if filters["q"]:
            # Explicit wildcard escaping: search text is literal and bound.
            needle = filters["q"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            pattern = "%" + needle + "%"
            query = query.where(or_(
                Host.name.ilike(pattern, escape="\\"),
                Finding.evidence["process"]["parent"].as_string().ilike(
                    pattern, escape="\\"),
                Finding.evidence["process"]["image"].as_string().ilike(
                    pattern, escape="\\"),
                Finding.evidence["app"].as_string().ilike(pattern, escape="\\"),
            ))
        return query

    def _table_order(query, filters):
        fields = {
            "when": Finding.last_seen,
            "detector": Finding.detector,
            "hostname": Host.name,
            "parent": func.coalesce(
                Finding.evidence["process"]["parent"].as_string(), ""),
            "process": func.coalesce(
                Finding.evidence["process"]["image"].as_string(),
                Finding.evidence["app"].as_string(),
                Finding.evidence["process"]["app"].as_string(), ""),
            "trigger": func.coalesce(
                Finding.evidence["environment"]["category"].as_string(),
                Finding.detector),
        }
        field = fields[filters["sort"]]
        order = field.asc() if filters["order"] == "asc" else field.desc()
        return query.order_by(order, Finding.id.asc())

    @app.get("/findings/table")
    def findings_table(request: Request, status: str = "open",
                       detector: str = "", category: str = "all",
                       q: str = "", sort: str = "when",
                       order: str = "desc", page: int = 1):
        filters = _table_filters(status, detector, category, q, sort, order)
        page = min(1000000, max(1, page))
        with transaction(engine) as db:
            user = login_user(request, db)
            query = _table_query(filters)
            total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
            results = db.execute(
                _table_order(query, filters)
                .offset((page - 1) * TABLE_PAGE_SIZE)
                .limit(TABLE_PAGE_SIZE)).all()
            rows = [{"finding": finding, "row": finding_table_row(finding, host)}
                    for finding, host in results]
            detectors = list(db.scalars(
                select(Finding.detector).distinct().order_by(Finding.detector)))

        def link(**changes):
            return "/findings/table?" + urlencode({**filters, **changes})

        sort_links = {}
        for column in TABLE_SORTS:
            direction = ("desc" if column == "when" else "asc")
            if filters["sort"] == column:
                direction = "asc" if filters["order"] == "desc" else "desc"
            sort_links[column] = link(sort=column, order=direction, page=1)

        return view(
            request, "findings_table.html", user=user, rows=rows,
            total=total, page=page, page_size=TABLE_PAGE_SIZE,
            filters=filters, detectors=detectors,
            categories=TABLE_CATEGORIES, sort_links=sort_links,
            previous_url=link(page=page - 1) if page > 1 else None,
            next_url=link(page=page + 1) if page * TABLE_PAGE_SIZE < total else None,
            full_csv_url="/findings/table.csv?" + urlencode({**filters, "privacy": "full"}),
            reduced_csv_url="/findings/table.csv?" + urlencode({**filters, "privacy": "reduced"}),
        )

    @app.get("/findings/table.csv")
    def findings_table_csv(request: Request, status: str = "open",
                           detector: str = "", category: str = "all",
                           q: str = "", sort: str = "when",
                           order: str = "desc", privacy: str = "full"):
        if privacy not in ("full", "reduced"):
            raise HTTPException(400, "Unknown CSV privacy mode")
        filters = _table_filters(status, detector, category, q, sort, order)
        with transaction(engine) as db:
            login_user(request, db)
            query = _table_query(filters)
            total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
            if total > CSV_EXPORT_LIMIT:
                raise HTTPException(
                    413, "CSV would exceed 10,000 rows. Narrow filters; no rows were truncated.")
            rows = db.execute(_table_order(query, filters)).all()
            content = finding_csv(rows, privacy_reduced=privacy == "reduced")
        date = datetime.now(timezone.utc).strftime("%Y%m%d")
        prefix = "deepsnout-findings-private-" if privacy == "reduced" else "deepsnout-findings-"
        return Response(
            content=content,
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{prefix}{date}.csv"'},
        )

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
            return view(request,"endpoint.html",user=user,host=host,coverage=coverage,findings=findings,
                        group_options=peer_group_options(db))

    @app.post("/endpoints/{host_id}/cohort")
    async def cohort(request: Request,host_id: str):
        form=await form_data(request); value=str(form.get("cohort","")).strip().lower()
        with transaction(engine) as db:
            user=login_user(request,db,{"admin","analyst"})
            host=found(db,Host,host_id)
            assign_host_group(db,host,value)
            audit(db,user.username,"endpoint.peer_group",host_id,value)
        return RedirectResponse("/endpoints/"+host_id,303)

    @app.get("/finding-quality")
    def finding_quality_page(request: Request):
        with transaction(engine) as db:
            user = login_user(request, db)
            snapshot = finding_quality_state(db)
            attempt = db.get(State, "finding_quality_last_attempt")
            jobs = list(db.scalars(
                select(Job).where(Job.kind == "finding_quality")
                .order_by(Job.created.desc()).limit(4)))
            return view(request, "finding_quality.html", user=user,
                        report=snapshot, attempt=attempt.value if attempt else None,
                        quality_jobs=jobs)

    @app.post("/finding-quality/refresh")
    async def finding_quality_refresh(request: Request):
        await form_data(request)
        with transaction(engine) as db:
            user = login_user(request, db, {"admin", "analyst"})
            job = enqueue(db, "finding_quality", {
                "origin": "operator", "requested_by": user.username})
            audit(db, user.username, "finding_quality.refresh", job.id)
        return RedirectResponse("/jobs/" + job.id, 303)

    @app.get("/finding-quality/families/{family_id}")
    def finding_quality_family_page(request: Request, family_id: str,
                                    page: int = 1):
        page = min(100000, max(1, page))
        page_size = 75
        with transaction(engine) as db:
            user = login_user(request, db)
            report = finding_quality_state(db)
            if not report:
                raise HTTPException(404, "Finding-quality snapshot not yet available")
            family = next(
                (g for g in report.get("families", [])
                 if g.get("id") == family_id), None)
            if family is None:
                raise HTTPException(404, "Finding family is not in the current snapshot")
            ids = family["member_ids"]
            current = ids[(page-1)*page_size:page*page_size]
            matches = db.execute(
                select(Finding, Host).join(Host, Finding.host_id == Host.id)
                .where(Finding.id.in_(current))).all() if current else []
            rows_by_id = {f.id: (f, h) for f, h in matches}
            rows = [{"finding": rows_by_id[fid][0],
                     "row": finding_table_row(*rows_by_id[fid])}
                    for fid in current if fid in rows_by_id]
            return view(
                request, "finding_quality_family.html", user=user,
                report=report, family=family, rows=rows,
                page=page, page_size=page_size,
                has_previous=page > 1,
                has_next=page*page_size < len(ids))

    @app.get("/api/finding-quality/metrics")
    def finding_quality_metrics(request: Request):
        with transaction(engine) as db:
            login_user(request, db)
            return JSONResponse(metrics_from_snapshot(finding_quality_state(db)))

    @app.get("/peer-groups")
    def peer_groups_page(request: Request):
        with transaction(engine) as db:
            user=login_user(request,db)
            suggestions=suggestion_state(db)
            analytical=analytical_cohort_state(db)
            catalog=peer_group_catalog(db)
            approved=[]
            for label,item in sorted(catalog.items()):
                approved.append({"label":label,"kind":item.get("kind","manual"),
                    "maturity":item.get("maturity","manual"),
                    "count":db.scalar(select(func.count()).select_from(Host).where(Host.cohort==label)) or 0})
            return view(request,"peer_groups.html",user=user,suggestions=suggestions,
                        analytical=analytical,approved=approved)

    @app.post("/peer-groups/refresh")
    async def peer_groups_refresh(request: Request):
        await form_data(request)
        with transaction(engine) as db:
            user=login_user(request,db,{"admin","analyst"})
            job=enqueue(db,"peer_groups",{"origin":"operator","requested_by":user.username})
            audit(db,user.username,"peer_groups.refresh",job.id)
            destination="/jobs/"+job.id if user.role=="admin" else "/peer-groups"
        return RedirectResponse(destination,303)

    @app.post("/peer-groups/manual")
    async def peer_group_manual(request: Request):
        form=await form_data(request)
        with transaction(engine) as db:
            user=login_user(request,db,{"admin","analyst"})
            label=create_manual_group(db,str(form.get("label","")),user.username)
            audit(db,user.username,"peer_group.manual_created",label)
        return RedirectResponse("/peer-groups",303)

    @app.post("/peer-groups/{group_id}/approve")
    async def peer_group_approve(request: Request,group_id: str):
        form=await form_data(request)
        with transaction(engine) as db:
            user=login_user(request,db,{"admin","analyst"})
            label=approve_suggestion(db,group_id,str(form.get("label","")),user.username)
            audit(db,user.username,"peer_group.approved",label,group_id)
        return RedirectResponse("/peer-groups/"+label,303)

    @app.post("/peer-groups/{group_id}/reject")
    async def peer_group_reject(request: Request,group_id: str):
        await form_data(request)
        with transaction(engine) as db:
            user=login_user(request,db,{"admin","analyst"})
            reject_suggestion(db,group_id)
            audit(db,user.username,"peer_group.rejected",group_id)
        return RedirectResponse("/peer-groups",303)

    @app.get("/api/peer-groups/metrics")
    def analytical_metrics(request: Request):
        with transaction(engine) as db:
            login_user(request, db)
            return JSONResponse(anonymized_cohort_metrics(analytical_cohort_state(db),
                                                        suggestion_state(db)))

    @app.get("/peer-groups/similarity/{identifier}")
    def similarity_detail_page(request: Request, identifier: str, q: str = ""):
        with transaction(engine) as db:
            user = login_user(request, db)
            group = next((g for g in analytical_cohort_state(db).get("similarity_groups", [])
                          if g.get("id") == identifier), None)
            if not group:
                raise HTTPException(404, "Similarity cohort not found")
            ids = group.get("members", [])
            query = (select(Host).where(Host.id.in_(ids)) if ids
                     else select(Host).where(Host.id == "__none__"))
            if q:
                query = query.where(Host.name.ilike("%" + q[:100] + "%"))
            members = db.scalars(query.order_by(Host.name).limit(500)).all()
            return view(request, "similarity_cohort.html", user=user, group=group,
                        members=members, q=q)

    @app.get("/peer-groups/automatic/{identifier}")
    def analytical_detail_page(request: Request, identifier: str, q: str = ""):
        with transaction(engine) as db:
            user = login_user(request, db)
            snapshot = analytical_cohort_state(db)
            group = next((g for g in snapshot.get("groups", [])
                          if g.get("id") == identifier), None)
            if not group:
                raise HTTPException(404, "Automatic cohort not found")
            ids = group.get("members", [])
            query = (select(Host).where(Host.id.in_(ids)) if ids
                     else select(Host).where(Host.id == "__none__"))
            if q:
                query = query.where(Host.name.ilike("%" + q[:100] + "%"))
            members = db.scalars(query.order_by(Host.name).limit(500)).all()
            return view(request, "analytical_cohort.html", user=user, group=group,
                        members=members, q=q)

    @app.get("/peer-groups/{identifier}")
    def peer_group_page(request: Request,identifier: str,q: str=""):
        with transaction(engine) as db:
            user=login_user(request,db)
            group=group_detail(db,identifier)
            if not group:
                raise HTTPException(404,"Peer group not found")
            ids=group.get("members",[])
            query=select(Host).where(Host.id.in_(ids)) if ids else select(Host).where(Host.id=="__none__")
            if q:
                query=query.where(Host.name.ilike("%"+q[:100]+"%"))
            members=db.scalars(query.order_by(Host.name).limit(500)).all()
            return view(request,"peer_group.html",user=user,group=group,members=members,q=q)

    @app.get("/sources")
    def sources(request: Request,edit: str=""):
        with transaction(engine) as db:
            user=login_user(request,db,{"admin"}); source=db.get(Source,edit) if edit else None
            values=(SplunkSettings.model_validate(source.config).model_dump() if source
                    else SplunkSettings(url="",indexes="placeholder").model_dump())
            if not source: values["indexes"]=""
            rows=db.scalars(select(Source)).all()
            tunings={}
            for row in rows:
                state=db.get(State,"splunk_tuning:"+row.id)
                tunings[row.id]=dict(state.value) if state and isinstance(state.value,dict) else {}
            return view(request,"sources.html",user=user,rows=rows,source=source,values=values,tunings=tunings)

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
                busy=db.scalar(select(Job).where(Job.source_id==source.id,Job.status.in_(["queued","running","cancel_requested"])))
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
                destination="/jobs/"+enqueue(db,action,{"origin":"operator","requested_by":user.username},source_id=source_id).id
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
            user=login_user(request,db,{"admin"}); job=enqueue(db,kind,{"origin":"operator","requested_by":user.username})
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
            if job.status not in {"failed","cancelled"}: raise ValueError("Only failed or cancelled jobs can be retried")
            if job.source_id and db.scalar(select(Job).where(Job.source_id==job.source_id,
                    Job.id!=job.id,Job.status.in_(["queued","running"]))):
                raise ValueError("This source already has a pending job")
            job.status,job.error,job.finished,job.started="queued","",0,0
            audit(db,user.username,"job.retry",job_id)
        return RedirectResponse("/jobs/"+job_id,303)

    @app.post("/jobs/{job_id}/cancel")
    async def cancel_job(request: Request,job_id: str):
        await form_data(request)
        with transaction(engine) as db:
            user=login_user(request,db,{"admin"}); job=found(db,Job,job_id)
            if job.status=="queued":
                kept={"origin":job.payload.get("origin")} if isinstance(job.payload,dict) and job.payload.get("origin") else {}
                job.status,job.finished,job.error,job.payload="cancelled",now(),"Cancelled by operator",kept
            elif job.status=="running":
                job.status,job.error="cancel_requested","Cancellation requested; the worker will stop at the next safe check."
            elif job.status=="cancel_requested":
                pass
            else:
                raise ValueError("Only queued or running jobs can be cancelled")
            audit(db,user.username,"job.cancel_requested",job_id,job.kind)
        return RedirectResponse("/operations",303)

    @app.get("/operations")
    def operations(request: Request):
        with transaction(engine) as db:
            user=login_user(request,db,{"admin"})
            states={r.key:r.value for r in db.scalars(select(State))}
            counts={m.__tablename__:db.scalar(select(func.count()).select_from(m))
                    for m in [Host,Seen,Process,BehaviorDay,Window,Finding]}
            orphan=db.scalar(select(func.count()).select_from(Process).where(Process.created.is_(None)))
            jobs=db.scalars(select(Job).order_by(Job.created.desc()).limit(40)).all()
            source_names={row.id:row.name for row in db.scalars(select(Source)).all()}
            logs=db.scalars(select(Audit).order_by(Audit.created.desc()).limit(60)).all()
            return view(request,"operations.html",user=user,states=states,counts=counts,jobs=jobs,logs=logs,orphan=orphan,psl=psl_available(),source_names=source_names)

    @app.get("/settings")
    def settings_page(request: Request):
        with transaction(engine) as db:
            return view(request,"settings.html",user=login_user(request,db,{"admin"}),settings=policy(db).model_dump())

    @app.post("/settings")
    async def settings_update(request: Request):
        form=await form_data(request)
        values={k:form[k] for k in Policy.model_fields if k in form}
        for k in ("execution_enabled","contextual_enabled","network_enabled","behavioral_enabled"):
            values[k]=form.get(k)=="on"
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

    @app.get("/api/behavioral-discovery/metrics")
    def behavioral_discovery_metrics(request: Request):
        """Counts-only operational feedback for environment-relative findings."""
        with transaction(engine) as db:
            login_user(request, db)
            query = (select(Finding.state, func.count())
                     .where(Finding.detector == "DS-BEH-001")
                     .group_by(Finding.state))
            by_state = {state: count for state, count in db.execute(query)}
            seven_days = (db.scalar(select(func.count()).select_from(Finding).where(
                Finding.detector == "DS-BEH-001",
                Finding.created >= now() - 7 * 86400)) or 0)
            cfg = policy(db)
            state = db.get(State, "behavioral_discovery_pipeline")
            pipeline = state.value if state else {}
            today = int(now()) // 86400
            pipeline_last_7d = {}
            for bucket_day, counters in pipeline.get("by_day", {}).items():
                if (not isinstance(counters, dict)
                        or not str(bucket_day).lstrip("-").isdigit()
                        or not today - 6 <= int(bucket_day) <= today):
                    continue
                for label, count in counters.items():
                    if isinstance(count, int) and not isinstance(count, bool):
                        pipeline_last_7d[label] = pipeline_last_7d.get(label, 0) + count
            return {
                "detector": "DS-BEH-001",
                "behavioral_enabled": cfg.behavioral_enabled,
                "evaluation_pipeline_last_7d": pipeline_last_7d,
                "evaluation_last_updated": pipeline.get("last_updated"),
                "evaluation_window": "last seven processing UTC days, including today",
                "evaluation_counts_are_events_not_distinct_hosts": True,
                "findings_total": sum(by_state.values()),
                "findings_last_7d": seven_days,
                "by_state": by_state,
                "reference_days": cfg.baseline_days,
                "minimum_local_observed_days": cfg.minimum_days,
                "minimum_fleet_hosts": cfg.behavioral_min_fleet_hosts,
                "rare_application_fraction": cfg.behavioral_rare_app_fraction,
                "rare_launch_relation_fraction": cfg.behavioral_rare_relation_fraction,
                "includes_endpoints_or_executable_names": False,
            }

    @app.get("/findings/{finding_id}/export")
    def export_finding(request: Request,finding_id: str):
        with transaction(engine) as db:
            login_user(request,db); f=found(db,Finding,finding_id)
            return JSONResponse({"id":f.id,"detector":f.detector,"title":f.title,"state":f.state,"evidence":f.evidence},
                headers={"Content-Disposition":'attachment; filename="finding.json"'})
    return app