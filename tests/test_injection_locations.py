"""Injection-LOCATION coverage tests (reflected XSS beyond query/form params).

Exercises the scanner engine end-to-end against a controlled stdlib HTTP
server (no new deps) that reflects input from NON-query locations:

  /hdr            — echoes the ``Referer`` request header in the HTML body.
  /ck             — echoes the ``trace`` request cookie in the HTML body.
  /custom         — echoes the ``X-Custom`` request header in the HTML body.
  /pathreflect/*  — echoes the trailing path segment in the HTML body.
  /clean          — reflects nothing.

Proves:
- Header injection produces a ``header:<name>`` finding when enabled.
- Cookie injection produces a ``cookie:<name>`` finding when enabled.
- Path-segment injection produces a ``path:append`` finding when enabled.
- The new locations are OFF unless enabled in the scan config (backward compat).
- A fuzz header that collides with configured auth is skipped (auth wins, so
  the probe can never carry the marker — and must never clobber the session).
- The pure scanner_core location helpers round-trip correctly.
"""
import asyncio
import os
import sys
import threading
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

# Dedicated sqlite file so this test never touches other tests' state.
os.environ["DATABASE_URL"] = "sqlite:///./data/xsshunter_injloc_test.db"
os.environ["RUN_EMBEDDED_WORKER"] = "false"
for _p in ("./data/xsshunter_injloc_test.db", "./data/xsshunter_injloc_test.db-journal"):
    try:
        os.remove(_p)
    except FileNotFoundError:
        pass

from db import SessionLocal, init_db  # noqa: E402
from models import Project, Scan, DiscoveredURL, Finding  # noqa: E402
import server as _srv  # noqa: F401,E402  triggers table create + admin bootstrap
import scanner_engine  # noqa: E402
from scanner_core import (  # noqa: E402
    COOKIE_LOCATION,
    HEADER_LOCATION,
    PATH_LOCATION,
    PATH_PARAM,
    QUERY_LOCATION,
    cookie_param_label,
    decode_injection_location,
    header_param_label,
    inject_path_marker,
    normalize_cookie_names,
    resolve_fuzz_headers,
)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, body: bytes, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _cookie(self, name: str) -> str:
        jar = SimpleCookie(self.headers.get("Cookie", ""))
        return jar[name].value if name in jar else ""

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/hdr":
            val = self.headers.get("Referer", "")
            self._send(f"<html><body>ref {val}!</body></html>".encode())
        elif path == "/ck":
            val = self._cookie("trace")
            self._send(f"<html><body>trace {val}!</body></html>".encode())
        elif path == "/custom":
            val = self.headers.get("X-Custom", "")
            self._send(f"<html><body>x {val}!</body></html>".encode())
        elif path.startswith("/pathreflect/"):
            seg = path[len("/pathreflect/"):]
            self._send(f"<html><body>page {seg}!</body></html>".encode())
        elif path in ("/pathreflect", "/clean"):
            self._send(b"<html><body>nothing here</body></html>")
        else:
            self._send(b"<html><body>nf</body></html>", status=404)


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


def _seed_get_scan(url, params=("q",)):
    with SessionLocal() as db:
        proj = Project(name="injloc", allowed_domains=["127.0.0.1"], excluded_paths=[])
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


def _run_engine(scan_id, cfg=None, auth_headers=None, auth_cookies=None):
    base = {"request_timeout": 20}
    base.update(cfg or {})
    asyncio.run(scanner_engine._test_reflection(
        scan_id, cfg=base, allowed=["127.0.0.1"],
        auth_headers=auth_headers or {}, auth_cookies=auth_cookies or {},
        login_indicators=[],
    ))


# ---------------------------------------------------------------------------
# Header injection
# ---------------------------------------------------------------------------

def test_header_injection_produces_header_finding(httpd):
    scan_id = _seed_get_scan(httpd + "/hdr")
    _run_engine(scan_id, {"fuzz_headers": True, "fuzz_header_names": ["Referer"]})
    with SessionLocal() as db:
        fs = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        labels = {f.param for f in fs}
        assert header_param_label("Referer") in labels, labels
        hf = next(f for f in fs if f.param == header_param_label("Referer"))
        assert hf.context == "html"
        assert hf.classification == "potential"


def test_header_injection_off_by_default(httpd):
    scan_id = _seed_get_scan(httpd + "/hdr")
    _run_engine(scan_id)  # no fuzz config
    with SessionLocal() as db:
        fs = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert all(not f.param.startswith(HEADER_LOCATION + ":") for f in fs), \
            [f.param for f in fs]


def test_fuzz_header_colliding_with_auth_is_skipped(httpd):
    """When a fuzz header name collides with configured auth, the probe is
    skipped: auth material wins the collision so the marker can never ride the
    request, and probing it must never risk breaking the session."""
    scan_id = _seed_get_scan(httpd + "/custom")
    _run_engine(
        scan_id,
        {"fuzz_headers": True, "fuzz_header_names": ["X-Custom"]},
        auth_headers={"X-Custom": "authvalue"},
    )
    with SessionLocal() as db:
        fs = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert all(f.param != header_param_label("X-Custom") for f in fs), \
            [f.param for f in fs]


# ---------------------------------------------------------------------------
# Cookie injection
# ---------------------------------------------------------------------------

def test_cookie_injection_produces_cookie_finding(httpd):
    scan_id = _seed_get_scan(httpd + "/ck")
    _run_engine(scan_id, {"fuzz_cookies": True, "fuzz_cookie_names": ["trace"]})
    with SessionLocal() as db:
        fs = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        labels = {f.param for f in fs}
        assert cookie_param_label("trace") in labels, labels
        cf = next(f for f in fs if f.param == cookie_param_label("trace"))
        assert cf.context == "html"
        assert cf.classification == "potential"


def test_cookie_injection_noop_without_names(httpd):
    scan_id = _seed_get_scan(httpd + "/ck")
    _run_engine(scan_id, {"fuzz_cookies": True})  # enabled but no names
    with SessionLocal() as db:
        fs = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert all(not f.param.startswith(COOKIE_LOCATION + ":") for f in fs), \
            [f.param for f in fs]


# ---------------------------------------------------------------------------
# Path-segment injection
# ---------------------------------------------------------------------------

def test_path_injection_produces_path_finding(httpd):
    scan_id = _seed_get_scan(httpd + "/pathreflect")
    _run_engine(scan_id, {"fuzz_path": True})
    with SessionLocal() as db:
        fs = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        labels = {f.param for f in fs}
        assert PATH_PARAM in labels, labels
        pf = next(f for f in fs if f.param == PATH_PARAM)
        assert pf.context == "html"
        assert pf.classification == "potential"


def test_path_injection_off_by_default(httpd):
    scan_id = _seed_get_scan(httpd + "/pathreflect")
    _run_engine(scan_id)
    with SessionLocal() as db:
        fs = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert fs == []


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_decode_injection_location_roundtrip():
    assert decode_injection_location(header_param_label("Referer")) == (HEADER_LOCATION, "Referer")
    assert decode_injection_location(cookie_param_label("sid")) == (COOKIE_LOCATION, "sid")
    assert decode_injection_location(PATH_PARAM) == (PATH_LOCATION, "append")
    # Bare names decode to query (legacy query/form params).
    assert decode_injection_location("q") == (QUERY_LOCATION, "q")
    assert decode_injection_location("") == (QUERY_LOCATION, "")


def test_resolve_fuzz_headers_dedup_and_default():
    assert resolve_fuzz_headers(None)  # falls back to defaults, non-empty
    assert resolve_fuzz_headers(["Referer", "referer", " ", "X-Y"]) == ["Referer", "X-Y"]


def test_normalize_cookie_names():
    assert normalize_cookie_names(["a", "a", " ", "b"]) == ["a", "b"]
    assert normalize_cookie_names(None) == []


def test_inject_path_marker_appends_segment():
    assert inject_path_marker("http://h/p", "seg") == "http://h/p/seg"
    assert inject_path_marker("http://h/p/", "seg") == "http://h/p/seg"
    # Query preserved, fragment dropped (HTTP never sends fragments).
    assert inject_path_marker("http://h/p?a=1#f", "seg") == "http://h/p/seg?a=1"
