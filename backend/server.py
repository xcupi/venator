"""FastAPI backend for reflected-xss-hunter.

Portable design:
- Database via SQLAlchemy (PostgreSQL in docker-compose, SQLite for zero-infra dev).
- Long-running scans persisted in DB, executed by an out-of-process worker
  (see /app/scanner). When RUN_EMBEDDED_WORKER=true (used only for local preview),
  a background task inside the API also drains QUEUED scans so users can try the
  full flow without launching the worker separately.
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session
from starlette.middleware.cors import CORSMiddleware

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

from db import SessionLocal, get_db, init_db  # noqa: E402
from models import AuthProfile, Candidate, DiscoveredURL, Finding, Project, Scan, User  # noqa: E402,F401
from auth import (  # noqa: E402
    create_token,
    current_user,
    ensure_admin,
    hash_password,
    verify_password,
)
from scanner_engine import run_scan, _preflight_auth  # noqa: E402
from auth_http import build_auth  # noqa: E402
from redact import public_auth_profile, redact_text_evidence  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("api")


app = FastAPI(title="Reflected XSS Hunter", version="0.1.0")
api = APIRouter(prefix="/api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


_embedded_task: Optional[asyncio.Task] = None


@app.on_event("startup")
async def _startup():
    init_db()
    with SessionLocal() as db:
        ensure_admin(db)
    if os.environ.get("RUN_EMBEDDED_WORKER", "true").lower() == "true":
        global _embedded_task
        _embedded_task = asyncio.create_task(_embedded_worker_loop())
        log.info("embedded scanner worker started")


async def _embedded_worker_loop():
    while True:
        try:
            with SessionLocal() as db:
                s = db.query(Scan).filter(Scan.status == "QUEUED").order_by(Scan.created_at.asc()).first()
                sid = s.id if s else None
            if sid:
                await run_scan(sid)
            else:
                await asyncio.sleep(2)
        except Exception:
            log.exception("embedded worker error")
            await asyncio.sleep(2)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ProjectIn(BaseModel):
    name: str
    description: str = ""
    allowed_domains: List[str] = Field(default_factory=list)
    excluded_paths: List[str] = Field(default_factory=list)


class ProjectOut(ProjectIn):
    id: str
    created_at: datetime


class ScanIn(BaseModel):
    project_id: str
    target_url: str
    max_urls: int = 100
    max_depth: int = 3
    request_timeout: int = 15
    auth_profile_id: Optional[str] = None


class ScanOut(BaseModel):
    id: str
    project_id: str
    auth_profile_id: Optional[str] = None
    target_url: str
    status: str
    stats: dict
    error: str = ""
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class FindingOut(BaseModel):
    id: str
    scan_id: str
    url: str
    method: str
    param: str
    context: str
    classification: str
    severity: str
    payload: str
    evidence: str
    validated: bool
    created_at: datetime
    response_snippet: str = ""
    request_dump: str = ""


@api.post("/auth/register", response_model=TokenOut)
def register(body: LoginIn, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(400, "Email already exists")
    u = User(email=body.email, password_hash=hash_password(body.password), is_admin=True)
    db.add(u); db.commit()
    return TokenOut(access_token=create_token(u.id))


@api.post("/auth/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form.username).first()
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    return TokenOut(access_token=create_token(user.id))


@api.post("/auth/login-json", response_model=TokenOut)
def login_json(body: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    return TokenOut(access_token=create_token(user.id))


@api.get("/auth/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "email": user.email, "is_admin": user.is_admin}


@api.get("/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@api.get("/projects", response_model=List[ProjectOut])
def list_projects(user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(Project).order_by(Project.created_at.desc()).all()
    return [ProjectOut(
        id=p.id, name=p.name, description=p.description or "",
        allowed_domains=p.allowed_domains or [], excluded_paths=p.excluded_paths or [],
        created_at=p.created_at,
    ) for p in rows]


@api.post("/projects", response_model=ProjectOut)
def create_project(body: ProjectIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = Project(
        name=body.name, description=body.description,
        allowed_domains=body.allowed_domains, excluded_paths=body.excluded_paths,
    )
    db.add(p); db.commit(); db.refresh(p)
    return ProjectOut(
        id=p.id, name=p.name, description=p.description or "",
        allowed_domains=p.allowed_domains or [], excluded_paths=p.excluded_paths or [],
        created_at=p.created_at,
    )


@api.delete("/projects/{project_id}")
def delete_project(project_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = db.query(Project).filter(Project.id == project_id).first()
    if not p:
        raise HTTPException(404, "Project not found")
    db.delete(p); db.commit()
    return {"deleted": project_id}


# ---------- Auth Profiles ----------
class AuthProfileIn(BaseModel):
    project_id: str
    name: str
    type: str  # cookie|header|bearer|basic
    enabled: bool = True
    config: dict = Field(default_factory=dict)


@api.get("/auth-profiles")
def list_auth_profiles(project_id: Optional[str] = None,
                        user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(AuthProfile)
    if project_id:
        q = q.filter(AuthProfile.project_id == project_id)
    return [public_auth_profile(p) for p in q.order_by(AuthProfile.created_at.desc()).all()]


@api.post("/auth-profiles")
def create_auth_profile(body: AuthProfileIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if body.type not in ("cookie", "header", "bearer", "basic"):
        raise HTTPException(400, "type must be cookie|header|bearer|basic")
    if not db.query(Project).filter(Project.id == body.project_id).first():
        raise HTTPException(404, "Project not found")
    p = AuthProfile(project_id=body.project_id, name=body.name, type=body.type,
                    enabled=body.enabled, config=body.config or {})
    db.add(p); db.commit(); db.refresh(p)
    return public_auth_profile(p)


@api.put("/auth-profiles/{profile_id}")
def update_auth_profile(profile_id: str, body: AuthProfileIn,
                        user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = db.query(AuthProfile).filter(AuthProfile.id == profile_id).first()
    if not p:
        raise HTTPException(404, "Auth profile not found")
    p.name = body.name
    p.type = body.type
    p.enabled = body.enabled
    p.config = body.config or {}
    db.commit(); db.refresh(p)
    return public_auth_profile(p)


@api.delete("/auth-profiles/{profile_id}")
def delete_auth_profile(profile_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = db.query(AuthProfile).filter(AuthProfile.id == profile_id).first()
    if not p:
        raise HTTPException(404, "Auth profile not found")
    db.delete(p); db.commit()
    return {"deleted": profile_id}


class TestAuthIn(BaseModel):
    check_url: Optional[str] = None  # override profile.check_url


@api.post("/auth-profiles/{profile_id}/test")
async def test_auth_profile(profile_id: str, body: TestAuthIn,
                             user: User = Depends(current_user), db: Session = Depends(get_db)):
    p = db.query(AuthProfile).filter(AuthProfile.id == profile_id).first()
    if not p:
        raise HTTPException(404, "Auth profile not found")
    project = db.query(Project).filter(Project.id == p.project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")
    allowed = list(project.allowed_domains or [])
    headers, cookies = build_auth(p)
    cfg = p.config or {}
    check_url = body.check_url or cfg.get("check_url")
    if not check_url:
        raise HTTPException(400, "Provide a check_url (either in the profile config or in the request)")
    login_indicators = list(cfg.get("login_indicators", []))
    valid, status_code, final_url, notes = await _preflight_auth(
        target=check_url, allowed=allowed,
        auth_headers=headers, auth_cookies=cookies,
        check_url=check_url, login_indicators=login_indicators, timeout=15,
    )
    return {
        "status": "VALID" if valid else "INVALID",
        "http_status": status_code,
        "final_url": final_url,
        "notes": notes,
        "cookies_attached": len(cookies),
        "headers_attached": len(headers),
    }


# ---------- Browser Login Capture ----------
# Flow: user clicks "Capture Login" -> backend mints short-lived JWT bound to the
# profile id. User runs `python scripts/capture_login.py --token ... --login-url ...`
# on their machine. That script launches Playwright chromium in headed mode,
# waits for the user to complete login, then POSTs cookies here. Backend replaces
# the profile's config.cookies with the captured session.

CAPTURE_TOKEN_TTL = 600  # 10 minutes


class CaptureTokenIn(BaseModel):
    login_url: str
    success_url_contains: Optional[str] = None  # optional heuristic: URL must contain this to be considered "logged in"


class CaptureImportIn(BaseModel):
    token: str
    cookies: List[dict]        # [{"name": "session", "value": "..."}, ...]
    final_url: Optional[str] = None
    user_agent: Optional[str] = None


@api.post("/auth-profiles/{profile_id}/capture-token")
def issue_capture_token(profile_id: str, body: CaptureTokenIn,
                         user: User = Depends(current_user), db: Session = Depends(get_db)):
    """Issue a short-lived, single-purpose JWT for the capture-login CLI helper."""
    import jwt as pyjwt
    from datetime import timedelta as _td
    p = db.query(AuthProfile).filter(AuthProfile.id == profile_id).first()
    if not p:
        raise HTTPException(404, "Auth profile not found")
    project = db.query(Project).filter(Project.id == p.project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")
    # Scope guard: login_url must be inside project scope so we never send
    # a capture flow to an unrelated host.
    from scanner_core import in_scope as _in_scope
    if not _in_scope(body.login_url, list(project.allowed_domains or []), []):
        raise HTTPException(400, "login_url is outside project scope")

    from auth import SECRET_KEY, ALGORITHM  # noqa: WPS433
    payload = {
        "purpose": "capture_login",
        "profile_id": profile_id,
        "login_url": body.login_url,
        "success_url_contains": body.success_url_contains or "",
        "exp": datetime.now(timezone.utc) + _td(seconds=CAPTURE_TOKEN_TTL),
    }
    token = pyjwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {
        "token": token,
        "expires_in": CAPTURE_TOKEN_TTL,
        "profile_id": profile_id,
        "login_url": body.login_url,
        "helper_command": (
            f"python scripts/capture_login.py "
            f"--api {os.environ.get('PUBLIC_API_URL','http://localhost:8001')} "
            f"--token {token}"
        ),
    }


@api.post("/auth-profiles/import-session")
def import_captured_session(body: CaptureImportIn, db: Session = Depends(get_db)):
    """Endpoint the capture-login CLI helper posts to. Auth via the capture token,
    NOT the user JWT — this lets the helper run standalone on the user's machine."""
    import jwt as pyjwt
    from auth import SECRET_KEY, ALGORITHM  # noqa: WPS433
    try:
        claims = pyjwt.decode(body.token, SECRET_KEY, algorithms=[ALGORITHM])
    except pyjwt.PyJWTError as e:
        raise HTTPException(401, f"invalid capture token: {e}")
    if claims.get("purpose") != "capture_login":
        raise HTTPException(401, "wrong token purpose")

    profile_id = claims.get("profile_id")
    p = db.query(AuthProfile).filter(AuthProfile.id == profile_id).first()
    if not p:
        raise HTTPException(404, "Auth profile not found")
    project = db.query(Project).filter(Project.id == p.project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")

    # Only import cookies for hosts inside project scope. Auth material NEVER
    # crosses scope, not even during capture.
    allowed = list(project.allowed_domains or [])
    from scanner_core import in_scope as _in_scope
    kept = []
    dropped = []
    for c in body.cookies or []:
        name = str(c.get("name", "")).strip()
        value = str(c.get("value", ""))
        # Cookie may not have a URL; check both explicit URL and each allowed domain
        cookie_url = c.get("url")
        if cookie_url and not _in_scope(cookie_url, allowed, []):
            dropped.append(name)
            continue
        # If domain is provided, ensure it matches an allowed domain
        c_domain = str(c.get("domain", "")).lstrip(".")
        if c_domain:
            def _match(d):
                pat = str(d).lower().lstrip("*.").strip()
                return c_domain.lower() == pat or c_domain.lower().endswith("." + pat)
            if not any(_match(d) for d in allowed):
                dropped.append(name)
                continue
        if name:
            kept.append({"name": name, "value": value})

    if not kept:
        raise HTTPException(400, f"No in-scope cookies captured (dropped: {dropped})")

    # Replace stored cookies; keep other config keys (check_url, indicators…)
    new_cfg = dict(p.config or {})
    new_cfg["cookies"] = kept
    new_cfg["captured_at"] = datetime.now(timezone.utc).isoformat()
    if body.final_url:
        new_cfg["captured_final_url"] = body.final_url
    p.type = "cookie"
    p.config = new_cfg
    db.commit(); db.refresh(p)
    return {
        "imported": len(kept),
        "dropped_out_of_scope": dropped,
        "profile": public_auth_profile(p),
    }


def _serialize_scan(s: Scan) -> ScanOut:
    return ScanOut(
        id=s.id, project_id=s.project_id, auth_profile_id=s.auth_profile_id,
        target_url=s.target_url, status=s.status, stats=s.stats or {}, error=s.error or "",
        created_at=s.created_at, started_at=s.started_at, completed_at=s.completed_at,
    )


@api.post("/scans", response_model=ScanOut)
def create_scan(body: ScanIn, user: User = Depends(current_user), db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == body.project_id).first()
    if not project:
        raise HTTPException(404, "Project not found")
    if body.auth_profile_id:
        prof = db.query(AuthProfile).filter(
            AuthProfile.id == body.auth_profile_id,
            AuthProfile.project_id == body.project_id,
        ).first()
        if not prof:
            raise HTTPException(400, "auth_profile_id does not belong to this project")
    s = Scan(
        project_id=body.project_id, auth_profile_id=body.auth_profile_id,
        target_url=body.target_url, status="QUEUED",
        config={"max_urls": body.max_urls, "max_depth": body.max_depth, "request_timeout": body.request_timeout},
        stats={},
    )
    db.add(s); db.commit(); db.refresh(s)
    return _serialize_scan(s)


@api.get("/scans", response_model=List[ScanOut])
def list_scans(project_id: Optional[str] = None, user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(Scan)
    if project_id:
        q = q.filter(Scan.project_id == project_id)
    return [_serialize_scan(s) for s in q.order_by(Scan.created_at.desc()).all()]


@api.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = db.query(Scan).filter(Scan.id == scan_id).first()
    if not s:
        raise HTTPException(404, "Scan not found")
    return _serialize_scan(s)


@api.post("/scans/{scan_id}/action")
def scan_action(scan_id: str, action: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = db.query(Scan).filter(Scan.id == scan_id).first()
    if not s:
        raise HTTPException(404, "Scan not found")
    mapping = {"pause": ("RUNNING", "PAUSED"), "resume": ("PAUSED", "RUNNING"), "stop": (None, "STOPPING")}
    if action not in mapping:
        raise HTTPException(400, "Unknown action")
    frm, to = mapping[action]
    if frm and s.status != frm:
        raise HTTPException(400, f"Scan not in {frm} state (currently {s.status})")
    s.status = to
    db.commit()
    return _serialize_scan(s)


@api.get("/scans/{scan_id}/urls")
def scan_urls(scan_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    urls = db.query(DiscoveredURL).filter(DiscoveredURL.scan_id == scan_id).all()
    return [{"id": u.id, "url": u.url, "method": u.method, "params": u.params or [], "depth": u.depth} for u in urls]


def _serialize_finding(f: Finding) -> FindingOut:
    return FindingOut(
        id=f.id, scan_id=f.scan_id, url=f.url, method=f.method, param=f.param,
        context=f.context, classification=f.classification, severity=f.severity,
        payload=f.payload or "", evidence=f.evidence or "", validated=f.validated,
        created_at=f.created_at,
        response_snippet=redact_text_evidence(f.response_snippet or ""),
        request_dump=redact_text_evidence(f.request_dump or ""),
    )


@api.get("/findings", response_model=List[FindingOut])
def list_findings(scan_id: Optional[str] = None, user: User = Depends(current_user), db: Session = Depends(get_db)):
    q = db.query(Finding)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    return [_serialize_finding(f) for f in q.order_by(Finding.created_at.desc()).all()]


@api.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    return _serialize_finding(f)


@api.get("/scans/{scan_id}/export")
def export_scan(scan_id: str, format: str = "json", user: User = Depends(current_user), db: Session = Depends(get_db)):
    s = db.query(Scan).filter(Scan.id == scan_id).first()
    if not s:
        raise HTTPException(404, "Scan not found")
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    fmt = format.lower()
    if fmt == "json":
        payload = {
            "scan_id": scan_id, "target": s.target_url, "status": s.status,
            "findings": [_serialize_finding(f).model_dump() for f in findings],
        }
        return Response(
            content=json.dumps(payload, default=str, indent=2), media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.json"},
        )
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["url", "method", "param", "context", "classification", "severity", "validated", "payload", "evidence"])
        for f in findings:
            w.writerow([f.url, f.method, f.param, f.context, f.classification, f.severity, f.validated, f.payload, f.evidence])
        return Response(content=buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.csv"})
    if fmt in ("md", "markdown"):
        lines = [f"# Scan report — {s.target_url}", f"Status: **{s.status}**", "",
                 "| URL | Param | Context | Classification | Severity | Validated |",
                 "|---|---|---|---|---|---|"]
        for f in findings:
            lines.append(f"| {f.url} | {f.param} | {f.context} | {f.classification} | {f.severity} | {f.validated} |")
        return Response(content="\n".join(lines), media_type="text/markdown",
                        headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.md"})
    raise HTTPException(400, "format must be json|csv|md")


@api.get("/dashboard/summary")
def dashboard_summary(user: User = Depends(current_user), db: Session = Depends(get_db)):
    total_projects = db.query(Project).count()
    total_scans = db.query(Scan).count()
    running = db.query(Scan).filter(Scan.status.in_(["RUNNING", "QUEUED", "PAUSED"])).count()
    findings_total = db.query(Finding).count()
    validated = db.query(Finding).filter(Finding.classification == "validated").count()
    potential = db.query(Finding).filter(Finding.classification == "potential").count()
    return {
        "projects": total_projects, "scans": total_scans, "active_scans": running,
        "findings": findings_total, "validated_findings": validated, "potential_findings": potential,
    }


app.include_router(api)


@app.get("/")
def root_health():
    return {"service": "reflected-xss-hunter", "docs": "/docs"}
