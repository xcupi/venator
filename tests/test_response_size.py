"""HTTP response body size protection tests (Phase 1, item 4).

Uses a stdlib ThreadingHTTPServer (no new dependencies) to serve controlled
bodies and exercises both _fetch directly and the reflection engine end-to-end.

Proves:
- Responses below the limit behave exactly as before (complete body, detection unchanged).
- Oversized responses are truncated at the configured cap.
- A marker inside the retained prefix still produces the existing classification.
- A marker beyond the retained prefix is treated as INCONCLUSIVE (Candidate
  context 'unknown', NO Finding) — never as reflection_only / safely_encoded /
  false_positive.
- The cap is enforced even when the server omits Content-Length.
- The SCANNER_MAX_BODY_BYTES env var controls the limit (default 5 MiB).
"""
import asyncio
import importlib
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

import aiohttp
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

# Dedicated sqlite file so this test never touches other tests' state.
os.environ["DATABASE_URL"] = "sqlite:///./data/xsshunter_rsize_test.db"
os.environ["RUN_EMBEDDED_WORKER"] = "false"
os.environ.pop("SCANNER_MAX_BODY_BYTES", None)  # ensure default for most tests
for _p in ("./data/xsshunter_rsize_test.db", "./data/xsshunter_rsize_test.db-journal"):
    try:
        os.remove(_p)
    except FileNotFoundError:
        pass

from db import SessionLocal, init_db  # noqa: E402
from models import Project, Scan, DiscoveredURL, Finding, Candidate  # noqa: E402
import server as _srv  # noqa: F401,E402  triggers table create + admin bootstrap
import scanner_engine  # noqa: E402


# ---------------------------------------------------------------------------
# Controlled HTTP server (stdlib only)
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    # HTTP/1.0 (default): no keep-alive, connection close terminates the body,
    # which lets us omit Content-Length entirely for the /no-length route.
    def log_message(self, *args):  # silence test noise
        pass

    def _send(self, body: bytes, with_length: bool = True):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if with_length:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        q = dict(parse_qsl(parts.query))
        path = parts.path
        if path == "/small":
            self._send(f"<html><body>Hello {q.get('q', '')}!</body></html>".encode())
        elif path == "/big":
            self._send(b"A" * (2 * 1024 * 1024))  # 2 MiB, Content-Length set
        elif path == "/no-length":
            self._send(b"B" * (2 * 1024 * 1024), with_length=False)
        elif path == "/early":
            # reflection lands in the first bytes, followed by a large tail
            body = (f"<html><body>Val: {q.get('q', '')} " + "x" * (1024 * 1024) + "</body></html>")
            self._send(body.encode())
        elif path == "/late":
            # reflection lands AFTER a 256 KiB prefix — beyond small test limits
            body = ("<html><body>" + "y" * (256 * 1024) + f" Val: {q.get('q', '')}</body></html>")
            self._send(body.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self.do_GET()


@pytest.fixture(scope="module")
def httpd():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.daemon_threads = True
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def _init():
    init_db()


def _get(url):
    async def go():
        async with aiohttp.ClientSession() as s:
            return await scanner_engine._fetch(s, "GET", url, timeout=20)
    return asyncio.run(go())


def _seed_get_scan(url, params=("q",)):
    with SessionLocal() as db:
        proj = Project(name="rsize", allowed_domains=["127.0.0.1"], excluded_paths=[])
        db.add(proj); db.commit(); db.refresh(proj)
        scan = Scan(
            project_id=proj.id, target_url=url, status="RUNNING",
            config={"request_timeout": 20},
            stats={"urls_crawled": 0, "params_tested": 0, "candidates": 0},
        )
        db.add(scan); db.commit(); db.refresh(scan)
        db.add(DiscoveredURL(scan_id=scan.id, url=url, method="GET", params=list(params), depth=0))
        db.commit()
        return scan.id


def _run_engine(scan_id):
    asyncio.run(scanner_engine._test_reflection(
        scan_id, cfg={"request_timeout": 20}, allowed=["127.0.0.1"],
        auth_headers={}, auth_cookies={}, login_indicators=[],
    ))


# ---------------------------------------------------------------------------
# Test 1 — normal response below the limit behaves exactly as before
# ---------------------------------------------------------------------------

def test_small_response_below_limit_is_complete(httpd):
    status, body, final_url, truncated = _get(httpd + "/small?q=hello")
    assert status == 200
    assert truncated is False
    assert body == "<html><body>Hello hello!</body></html>"  # complete, untruncated
    assert final_url.startswith(httpd)


def test_small_reflection_detection_unchanged(httpd):
    """Below-limit scan: reflection detection and classification are unchanged."""
    scan_id = _seed_get_scan(httpd + "/small?q=x")
    _run_engine(scan_id)
    with SessionLocal() as db:
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(findings) == 1
        assert findings[0].classification == "potential"
        assert findings[0].context == "html"
        assert findings[0].validated is False


# ---------------------------------------------------------------------------
# Test 2 — oversized response is truncated, memory stays bounded
# ---------------------------------------------------------------------------

def test_oversized_response_is_truncated(httpd, monkeypatch):
    monkeypatch.setattr(scanner_engine, "MAX_BODY_BYTES", 64 * 1024)
    status, body, _, truncated = _get(httpd + "/big")  # 2 MiB body
    assert status == 200
    assert truncated is True
    # The returned body never exceeds the configured cap.
    assert len(body.encode("utf-8", "ignore")) <= 64 * 1024
    # And it is a strict prefix of the full body ('A's only).
    assert set(body) == {"A"}


# ---------------------------------------------------------------------------
# Test 3 — marker inside the retained prefix: detection unchanged
# ---------------------------------------------------------------------------

def test_marker_before_truncation_still_detected(httpd, monkeypatch):
    monkeypatch.setattr(scanner_engine, "MAX_BODY_BYTES", 64 * 1024)
    scan_id = _seed_get_scan(httpd + "/early?q=x")  # marker lands in first bytes
    _run_engine(scan_id)
    with SessionLocal() as db:
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(findings) == 1
        f = findings[0]
        assert f.classification == "potential"
        assert f.context == "html"
        assert f.validated is False


# ---------------------------------------------------------------------------
# Test 4 — marker beyond the retained prefix: inconclusive, never "absent"
# ---------------------------------------------------------------------------

def test_marker_after_truncation_is_inconclusive_not_absent(httpd, monkeypatch):
    monkeypatch.setattr(scanner_engine, "MAX_BODY_BYTES", 64 * 1024)
    scan_id = _seed_get_scan(httpd + "/late?q=x")  # marker lands after 256 KiB
    _run_engine(scan_id)
    with SessionLocal() as db:
        # NO finding may be created — in particular not reflection_only,
        # safely_encoded, or false_positive, because truncation could be
        # hiding the reflection.
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert findings == [], f"no finding expected for truncated-undetermined, got {findings}"
        # ...but an honest 'unknown' candidate records the inconclusive test.
        cands = db.query(Candidate).filter(Candidate.scan_id == scan_id).all()
        assert len(cands) == 1
        assert cands[0].context == "unknown"
        assert cands[0].reflected_raw is False


# ---------------------------------------------------------------------------
# Test 5 — limit enforced even without Content-Length
# ---------------------------------------------------------------------------

def test_limit_enforced_without_content_length(httpd, monkeypatch):
    monkeypatch.setattr(scanner_engine, "MAX_BODY_BYTES", 64 * 1024)
    status, body, _, truncated = _get(httpd + "/no-length")  # 2 MiB, no Content-Length
    assert status == 200
    assert truncated is True
    assert len(body.encode("utf-8", "ignore")) <= 64 * 1024


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def test_default_limit_is_5mb():
    assert scanner_engine.MAX_BODY_BYTES == 5 * 1024 * 1024


def test_env_override_changes_limit():
    old = os.environ.get("SCANNER_MAX_BODY_BYTES")
    os.environ["SCANNER_MAX_BODY_BYTES"] = "131072"
    try:
        importlib.reload(scanner_engine)
        assert scanner_engine.MAX_BODY_BYTES == 131072
    finally:
        if old is None:
            os.environ.pop("SCANNER_MAX_BODY_BYTES", None)
        else:
            os.environ["SCANNER_MAX_BODY_BYTES"] = old
        importlib.reload(scanner_engine)
    assert scanner_engine.MAX_BODY_BYTES == 5 * 1024 * 1024
