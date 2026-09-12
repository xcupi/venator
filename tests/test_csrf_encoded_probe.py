"""CSRF-protected POST encoded reflection probe tests (Phase 1, item 2).

Proves:
- A CSRF-protected POST endpoint that reflects input with safe HTML encoding is
  classified as safely_encoded rather than potential (live test target E2E).
- A CSRF-protected POST endpoint whose reflection is NOT safely encoded remains
  potential and is NOT marked validated (live test target E2E), with the encoded
  probe actually accepted after token rotation inside the same session.
- CSRF token refresh failure produces csrf_token_required and does NOT blindly
  submit the encoded probe (stateful fake server).
- A rotated CSRF token is refreshed and used for the encoded probe inside the
  SAME session (stateful fake server with strict token checking).
- Existing GET and non-CSRF POST behavior is unchanged.
"""
import asyncio
import html as _html
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

# Dedicated sqlite file so this test never touches other tests' state.
os.environ["DATABASE_URL"] = "sqlite:///./data/xsshunter_csrf_enc_test.db"
os.environ["RUN_EMBEDDED_WORKER"] = "false"
for _p in ("./data/xsshunter_csrf_enc_test.db", "./data/xsshunter_csrf_enc_test.db-journal"):
    try:
        os.remove(_p)
    except FileNotFoundError:
        pass

from db import SessionLocal, init_db  # noqa: E402
from models import Project, Scan, DiscoveredURL, Finding  # noqa: E402
import server as _srv  # noqa: F401,E402  triggers table create + admin bootstrap
import scanner_engine  # noqa: E402
from scanner_core import ENCODED_PROBE, DEFAULT_MARKER  # noqa: E402


@pytest.fixture(autouse=True)
def _init():
    init_db()


# ---------------------------------------------------------------------------
# Live test-target fixture (the real /app/test-target/app.py, in a subprocess)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def target():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    app_py = os.path.join(os.path.dirname(__file__), "..", "test-target", "app.py")
    proc = subprocess.Popen(
        [sys.executable, app_py],
        env={**os.environ, "PORT": str(port)},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            urllib.request.urlopen(base + "/", timeout=1)
            break
        except Exception:
            time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail("test target did not start")
    yield base
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


def _stats(base):
    with urllib.request.urlopen(base + "/_stats", timeout=5) as r:
        return json.loads(r.read().decode())


def _seed_csrf_scan(base, path):
    """Seed a scan with one CSRF-protected POST DiscoveredURL pointing at the
    live test target, exactly as the crawler would have recorded it."""
    with SessionLocal() as db:
        proj = Project(name="csrf-live", allowed_domains=["127.0.0.1"], excluded_paths=[])
        db.add(proj); db.commit(); db.refresh(proj)
        scan = Scan(
            project_id=proj.id, target_url=base + "/", status="RUNNING",
            config={"max_urls": 5, "max_depth": 1, "request_timeout": 10},
            stats={"urls_crawled": 0, "params_tested": 0, "candidates": 0},
        )
        db.add(scan); db.commit(); db.refresh(scan)
        db.add(DiscoveredURL(
            scan_id=scan.id, url=base + path, method="POST", params=["comment"], depth=0,
            origin_url=base + path, csrf_fields=["csrf_token"], hidden_fields={"csrf_token": ""},
        ))
        db.commit()
        return scan.id


def _run(scan_id):
    asyncio.run(scanner_engine._test_reflection(
        scan_id, cfg={"request_timeout": 10}, allowed=["127.0.0.1"],
        auth_headers={}, auth_cookies={}, login_indicators=[],
    ))


# ---------------------------------------------------------------------------
# Live E2E tests against the real vulnerable test target
# ---------------------------------------------------------------------------

def test_csrf_post_safely_encoded_reflection_is_safely_encoded(target):
    """The /csrf-form-encoded endpoint escapes the comment. The scanner must
    run the encoded probe (with a refreshed, rotated token, same session) and
    classify the finding safely_encoded instead of potential."""
    scan_id = _seed_csrf_scan(target, "/csrf-form-encoded")
    before = _stats(target)["csrf_form_encoded"]

    _run(scan_id)

    after = _stats(target)["csrf_form_encoded"]
    # primary probe + encoded probe must BOTH have been accepted by the target
    # (fresh token each time) — proves rotation handling and session reuse.
    assert after - before == 2, (
        f"expected 2 accepted POSTs (primary + encoded probe), got {after - before}"
    )

    with SessionLocal() as db:
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(findings) == 1, f"expected 1 finding, got {[(f.classification, f.context) for f in findings]}"
        f = findings[0]
        assert f.classification == "safely_encoded", (
            f"safely-encoding CSRF endpoint must be safely_encoded, got {f.classification}"
        )
        assert f.context == "encoded"
        assert f.validated is False  # browser validation is the ONLY path to validated


def test_csrf_post_unsafe_reflection_stays_potential_after_rotation(target):
    """The /csrf-form endpoint reflects raw and rotates the token on every POST.
    The finding must remain potential (NOT validated) and the encoded probe
    must have been accepted with a refreshed token (2 accepted POSTs)."""
    scan_id = _seed_csrf_scan(target, "/csrf-form")
    before = _stats(target)["csrf_form"]

    _run(scan_id)

    after = _stats(target)["csrf_form"]
    assert after - before == 2, (
        f"expected 2 accepted POSTs (primary + encoded probe), got {after - before}. "
        "If only 1 was accepted, the encoded probe failed after token rotation."
    )

    with SessionLocal() as db:
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(findings) == 1, f"expected 1 finding, got {[(f.classification, f.context) for f in findings]}"
        f = findings[0]
        assert f.classification == "potential", f"raw-reflecting CSRF endpoint must stay potential, got {f.classification}"
        assert f.context == "html"
        assert f.validated is False


# ---------------------------------------------------------------------------
# Stateful fake server (unit-level, no network)
# ---------------------------------------------------------------------------

def _make_fake_csrf_server(*, reflect_mode="raw", fail_refresh=False):
    """Emulate a CSRF-protected form endpoint with rotating tokens.

    - GET  /form : issues a token tied to the CALLING SESSION (proves jar reuse)
    - POST /form : rejects stale/missing tokens with 403, rotates on success
    - fail_refresh=True: the origin refetch after the primary POST returns a
      page without any CSRF field (simulates refresh failure)
    """
    sessions = {}          # id(session) -> current token
    token_counter = {"n": 0}
    log = []               # (kind, session_id, data)

    def _new_token():
        token_counter["n"] += 1
        return f"TOK{token_counter['n']}"

    async def fake_fetch(session, method, url, params=None, data=None, timeout=15,
                        auth_headers=None, auth_cookies=None, allowed_domains=None):
        sid = id(session)
        if method == "GET" and url.endswith("/form"):
            if fail_refresh and any(e[0] == "POST" for e in log):
                log.append(("GET-origin-no-token", sid, None))
                return 200, "<html><body>temporarily unavailable</body></html>", url
            tok = _new_token()
            sessions[sid] = tok
            log.append(("GET-origin", sid, None))
            return 200, f"<form><input name='csrf_token' value='{tok}'></form>", url
        if method == "POST":
            log.append(("POST", sid, dict(data or {})))
            supplied = (data or {}).get("csrf_token", "")
            if not supplied or supplied != sessions.get(sid):
                return 403, "<html><body>403 CSRF token invalid</body></html>", url
            comment = str((data or {}).get("comment", ""))
            sessions[sid] = _new_token()  # rotate on every accepted POST
            if reflect_mode == "raw":
                return 200, f"<html><body>Posted: {comment}</body></html>", url
            return 200, f"<html><body>Posted: {_html.escape(comment)}</body></html>", url
        return 404, "", url

    return fake_fetch, log


def _seed_fake_scan(monkeypatch, fake_fetch, *, method="POST", csrf_fields=("csrf_token",),
                    url="http://localhost/form", origin_url="http://localhost/form",
                    params=("comment",)):
    monkeypatch.setattr(scanner_engine, "_fetch", fake_fetch)
    with SessionLocal() as db:
        proj = Project(name="csrf-fake", allowed_domains=["localhost"], excluded_paths=[])
        db.add(proj); db.commit(); db.refresh(proj)
        scan = Scan(
            project_id=proj.id, target_url="http://localhost/", status="RUNNING",
            config={"request_timeout": 5},
            stats={"urls_crawled": 0, "params_tested": 0, "candidates": 0},
        )
        db.add(scan); db.commit(); db.refresh(scan)
        db.add(DiscoveredURL(
            scan_id=scan.id, url=url, method=method, params=list(params), depth=0,
            origin_url=origin_url, csrf_fields=list(csrf_fields),
            hidden_fields={n: "" for n in csrf_fields},
        ))
        db.commit()
        return scan.id


def test_csrf_refresh_failure_yields_csrf_required_and_no_blind_encoded_post(monkeypatch):
    """Primary probe succeeds, but the token refresh before the encoded probe
    fails. Expect csrf_token_required and exactly ONE POST (no blind submit)."""
    fake_fetch, log = _make_fake_csrf_server(reflect_mode="raw", fail_refresh=True)
    scan_id = _seed_fake_scan(monkeypatch, fake_fetch)

    asyncio.run(scanner_engine._test_reflection(
        scan_id, cfg={"request_timeout": 5}, allowed=["localhost"],
        auth_headers={}, auth_cookies={}, login_indicators=[],
    ))

    posts = [e for e in log if e[0] == "POST"]
    assert len(posts) == 1, f"encoded probe must NOT be blindly submitted; posts: {posts}"

    with SessionLocal() as db:
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(findings) == 1
        f = findings[0]
        assert f.classification == "csrf_token_required"
        assert f.context == "csrf_required"
        assert f.validated is False


def test_csrf_rotation_uses_refreshed_token_in_same_session(monkeypatch):
    """The fake server REJECTS stale tokens. The encoded probe must therefore
    carry the freshly-issued token from the origin refetch, inside the SAME
    session as the primary probe, or it would receive a 403."""
    fake_fetch, log = _make_fake_csrf_server(reflect_mode="raw", fail_refresh=False)
    scan_id = _seed_fake_scan(monkeypatch, fake_fetch)

    asyncio.run(scanner_engine._test_reflection(
        scan_id, cfg={"request_timeout": 5}, allowed=["localhost"],
        auth_headers={}, auth_cookies={}, login_indicators=[],
    ))

    posts = [e for e in log if e[0] == "POST"]
    gets = [e for e in log if e[0] == "GET-origin"]
    assert len(posts) == 2, f"expected primary + encoded POST, got {len(posts)}"
    assert len(gets) == 2, f"expected origin fetch + refresh fetch, got {len(gets)}"

    # Session preservation: every request must have used the same session object
    sids = {e[1] for e in log}
    assert len(sids) == 1, "primary and encoded probes must share one session"

    # Rotation: the encoded POST must carry a DIFFERENT token than the primary
    tok_primary = posts[0][2]["csrf_token"]
    tok_encoded = posts[1][2]["csrf_token"]
    assert tok_primary != tok_encoded, "encoded probe must use the rotated token"
    # And the encoded probe must contain the encoded probe marker
    assert posts[1][2]["comment"] == ENCODED_PROBE
    assert posts[0][2]["comment"] == f"pre_{DEFAULT_MARKER}_post"

    with SessionLocal() as db:
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(findings) == 1
        f = findings[0]
        assert f.classification == "potential"
        assert f.validated is False


# ---------------------------------------------------------------------------
# Regression guards: GET and non-CSRF POST behavior unchanged
# ---------------------------------------------------------------------------

def _make_echo_fake(*, escape_values=False):
    async def fake_fetch(session, method, url, params=None, data=None, timeout=15,
                        auth_headers=None, auth_cookies=None, allowed_domains=None):
        parts = []
        if params:
            parts.extend(str(v) for v in params.values())
        if data:
            parts.extend(str(v) for v in data.values())
        vals = " ".join(parts)
        if escape_values:
            vals = _html.escape(vals)
        return 200, f"<html><body>Hello {vals} world</body></html>", url
    return fake_fetch


def test_get_path_raw_reflection_stays_potential(monkeypatch):
    monkeypatch.setattr(scanner_engine, "_fetch", _make_echo_fake())
    scan_id = _seed_fake_scan(monkeypatch, scanner_engine._fetch, method="GET",
                              csrf_fields=(), url="http://localhost/s?q=x",
                              origin_url="", params=("q",))
    asyncio.run(scanner_engine._test_reflection(
        scan_id, cfg={"request_timeout": 5}, allowed=["localhost"],
        auth_headers={}, auth_cookies={}, login_indicators=[],
    ))
    with SessionLocal() as db:
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(findings) == 1
        assert findings[0].classification == "potential"
        assert findings[0].context == "html"


def test_get_path_encoded_reflection_stays_safely_encoded(monkeypatch):
    monkeypatch.setattr(scanner_engine, "_fetch", _make_echo_fake(escape_values=True))
    scan_id = _seed_fake_scan(monkeypatch, scanner_engine._fetch, method="GET",
                              csrf_fields=(), url="http://localhost/s?q=x",
                              origin_url="", params=("q",))
    asyncio.run(scanner_engine._test_reflection(
        scan_id, cfg={"request_timeout": 5}, allowed=["localhost"],
        auth_headers={}, auth_cookies={}, login_indicators=[],
    ))
    with SessionLocal() as db:
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(findings) == 1
        assert findings[0].classification == "safely_encoded"


def test_non_csrf_post_raw_reflection_stays_potential(monkeypatch):
    monkeypatch.setattr(scanner_engine, "_fetch", _make_echo_fake())
    scan_id = _seed_fake_scan(monkeypatch, scanner_engine._fetch, method="POST",
                              csrf_fields=(), url="http://localhost/p",
                              origin_url="", params=("comment",))
    asyncio.run(scanner_engine._test_reflection(
        scan_id, cfg={"request_timeout": 5}, allowed=["localhost"],
        auth_headers={}, auth_cookies={}, login_indicators=[],
    ))
    with SessionLocal() as db:
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(findings) == 1
        assert findings[0].classification == "potential"
        assert findings[0].context == "html"


def test_non_csrf_post_encoded_reflection_stays_safely_encoded(monkeypatch):
    monkeypatch.setattr(scanner_engine, "_fetch", _make_echo_fake(escape_values=True))
    scan_id = _seed_fake_scan(monkeypatch, scanner_engine._fetch, method="POST",
                              csrf_fields=(), url="http://localhost/p",
                              origin_url="", params=("comment",))
    asyncio.run(scanner_engine._test_reflection(
        scan_id, cfg={"request_timeout": 5}, allowed=["localhost"],
        auth_headers={}, auth_cookies={}, login_indicators=[],
    ))
    with SessionLocal() as db:
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(findings) == 1
        assert findings[0].classification == "safely_encoded"
