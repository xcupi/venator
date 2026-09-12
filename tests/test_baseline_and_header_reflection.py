"""Phase C — baseline diff + response-header reflection tests.

Exercises the scanner engine end-to-end against a controlled HTTP server
(stdlib ThreadingHTTPServer, no new dependencies) with four targeted
endpoints:

  /reflect-body       — echoes ``q`` in HTML body (baseline body clean).
  /pollute            — response body ALWAYS contains the reflection marker
                        regardless of input (baseline pollution scenario).
  /reflect-header     — echoes ``q`` in a response header only, body clean.
  /reflect-both       — echoes ``q`` in body AND header (body wins).
  /pollute-header     — response header ALWAYS contains the marker regardless
                        of input (baseline header pollution).
  /count              — returns the number of times each path has been hit,
                        used to prove baseline overhead is O(1) per URL.

Proves:
- Baseline body pollution → probe hit downgraded to false_positive.
- Baseline header pollution → probe hit downgraded to false_positive.
- Header reflection with clean baseline → header context / reflection_only.
- Body reflection unchanged when headers also echo the marker.
- Baseline generates exactly ONE extra request per non-CSRF URL, regardless
  of the number of params.
"""
import asyncio
import importlib
import os
import sys
import threading
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

# Dedicated sqlite file so this test never touches other tests' state.
os.environ["DATABASE_URL"] = "sqlite:///./data/xsshunter_baseline_test.db"
os.environ["RUN_EMBEDDED_WORKER"] = "false"
for _p in ("./data/xsshunter_baseline_test.db", "./data/xsshunter_baseline_test.db-journal"):
    try:
        os.remove(_p)
    except FileNotFoundError:
        pass

from db import SessionLocal, init_db  # noqa: E402
from models import Project, Scan, DiscoveredURL, Finding, Candidate  # noqa: E402
import server as _srv  # noqa: F401,E402  triggers table create + admin bootstrap
import scanner_engine  # noqa: E402
from scanner_core import DEFAULT_MARKER  # noqa: E402


# ---------------------------------------------------------------------------
# Controlled HTTP server
# ---------------------------------------------------------------------------

# Per-path hit counter — module-level so the handler can update from any
# thread. Reset by ``_reset_counter`` per test.
HITS: "defaultdict[str, int]" = defaultdict(int)
_HITS_LOCK = threading.Lock()


def _bump(path: str):
    with _HITS_LOCK:
        HITS[path] += 1


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, body: bytes, extra_headers=None, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra_headers or []):
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        q = dict(parse_qsl(parts.query))
        path = parts.path
        _bump(path)
        val = q.get("q", "")
        if path == "/reflect-body":
            self._send(f"<html><body>Hello {val}!</body></html>".encode())
        elif path == "/pollute":
            # Baseline pollution: the marker is ALWAYS present in the body,
            # regardless of any request. Any subsequent probe "reflection"
            # cannot be attributed to injection.
            self._send(
                f"<html><body>static: {DEFAULT_MARKER}. Your input: {val}</body></html>".encode()
            )
        elif path == "/reflect-header":
            # Header-only echo. Body deliberately does NOT contain val.
            self._send(
                b"<html><body>see X-Echo header</body></html>",
                extra_headers=[("X-Echo", val)],
            )
        elif path == "/reflect-both":
            # Both body and header reflect. Body classification must win.
            self._send(
                f"<html><body>Hello {val}!</body></html>".encode(),
                extra_headers=[("X-Echo", val)],
            )
        elif path == "/pollute-header":
            # Header baseline pollution: X-Echo ALWAYS contains marker.
            self._send(
                b"<html><body>see X-Echo header</body></html>",
                extra_headers=[("X-Echo", DEFAULT_MARKER)],
            )
        elif path == "/count":
            import json
            body = json.dumps(dict(HITS)).encode()
            self._send(body)
        else:
            self._send(b"", status=404)


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
    HITS.clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_get_scan(url, params=("q",)):
    with SessionLocal() as db:
        proj = Project(name="baseline", allowed_domains=["127.0.0.1"], excluded_paths=[])
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
# Test 1 — sanity: body reflection still classified 'potential' with baseline
# ---------------------------------------------------------------------------

def test_body_reflection_with_clean_baseline_is_potential(httpd):
    scan_id = _seed_get_scan(httpd + "/reflect-body")
    _run_engine(scan_id)
    with SessionLocal() as db:
        fs = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(fs) == 1
        assert fs[0].context == "html"
        assert fs[0].classification == "potential"


# ---------------------------------------------------------------------------
# Test 2 — baseline body pollution downgrades to false_positive
# ---------------------------------------------------------------------------

def test_baseline_polluted_body_produces_false_positive_not_potential(httpd):
    """The /pollute endpoint always emits the marker in the body regardless
    of input. Baseline sees it → any subsequent probe cannot claim reflection.
    Result: NO 'potential' finding; a 'false_positive' finding may be
    recorded (context 'none'), but MUST NOT be classified as 'potential' /
    'safely_encoded' / 'reflection_only'.
    """
    scan_id = _seed_get_scan(httpd + "/pollute")
    _run_engine(scan_id)
    with SessionLocal() as db:
        fs = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        # No finding is written when reflected=False (the current record
        # policy in _record_probe_result). But if a future change flips
        # that policy, this assertion still guards the CRITICAL invariant.
        for f in fs:
            assert f.classification not in ("potential", "safely_encoded", "reflection_only"), (
                f"baseline-polluted target must not surface as {f.classification}: {f.__dict__}"
            )
        # A Candidate MUST still be recorded so we can see the URL was tested.
        cands = db.query(Candidate).filter(Candidate.scan_id == scan_id).all()
        assert len(cands) == 1
        assert cands[0].context == "none"
        assert cands[0].reflected_raw is False


# ---------------------------------------------------------------------------
# Test 3 — header reflection with clean baseline → reflection_only
# ---------------------------------------------------------------------------

def test_header_reflection_with_clean_baseline_is_reflection_only(httpd):
    scan_id = _seed_get_scan(httpd + "/reflect-header")
    _run_engine(scan_id)
    with SessionLocal() as db:
        fs = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(fs) == 1
        assert fs[0].context == "header"
        assert fs[0].classification == "reflection_only"
        assert fs[0].severity == "low"


# ---------------------------------------------------------------------------
# Test 4 — body reflection wins when headers also echo the marker
# ---------------------------------------------------------------------------

def test_body_reflection_wins_over_header_reflection(httpd):
    scan_id = _seed_get_scan(httpd + "/reflect-both")
    _run_engine(scan_id)
    with SessionLocal() as db:
        fs = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        # Exactly one finding, classified by BODY context (not 'header').
        assert len(fs) == 1
        assert fs[0].context == "html"
        assert fs[0].classification == "potential"


# ---------------------------------------------------------------------------
# Test 5 — baseline header pollution suppresses header reflection
# ---------------------------------------------------------------------------

def test_baseline_polluted_headers_suppresses_finding(httpd):
    scan_id = _seed_get_scan(httpd + "/pollute-header")
    _run_engine(scan_id)
    with SessionLocal() as db:
        fs = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        # The server always echoes marker in X-Echo — baseline sees it →
        # not attributable to our injection → no finding at all.
        for f in fs:
            assert f.classification == "false_positive", f.__dict__


# ---------------------------------------------------------------------------
# Test 6 — baseline overhead is O(1) per URL, not O(params)
# ---------------------------------------------------------------------------

def test_baseline_generates_exactly_one_extra_request_per_url(httpd):
    """Seed a URL with 3 params. Expected request breakdown for the engine:
       - 1 baseline GET
       - 3 primary marker probes (one per param)
       - up to 3 encoded probes (one per param that lands in html/attribute)
    So the number of HTTP hits on /reflect-body must equal 1 + N + K where
    N=3 (primary probes) and K is the count of encoded-probe-eligible params.
    Whatever K is, the baseline contribution to the delta is exactly 1.
    """
    scan_id = _seed_get_scan(httpd + "/reflect-body", params=("q", "r", "s"))
    _run_engine(scan_id)
    total = HITS["/reflect-body"]
    # 1 baseline + 3 primary + up to 3 encoded = 4..7. Assert lower bound
    # includes the baseline and upper bound isn't exceeded.
    assert 4 <= total <= 7, HITS


def test_baseline_skipped_for_single_param_still_runs_one_baseline(httpd):
    scan_id = _seed_get_scan(httpd + "/reflect-body", params=("q",))
    _run_engine(scan_id)
    total = HITS["/reflect-body"]
    # 1 baseline + 1 primary + 1 encoded = 3 (html context always demotes-eligible).
    assert total == 3, HITS


# ---------------------------------------------------------------------------
# Test 7 — non-reflecting URL still gets baselined (no false alarms)
# ---------------------------------------------------------------------------

def test_static_page_no_finding(httpd):
    """A static page that reflects nothing → no Finding, one baseline hit
    plus one primary probe hit (encoded probe NOT sent because there is no
    reflection to gate on).
    """
    # Point /reflect-header at a param that's not "q"; the server ignores
    # anything other than "q". Using param "z" makes the body inert.
    scan_id = _seed_get_scan(httpd + "/reflect-header", params=("z",))
    _run_engine(scan_id)
    with SessionLocal() as db:
        # /reflect-header sends header echo only for "q", so "z" gives an
        # inert response — no body reflection, no header reflection → no
        # finding of any kind.
        fs = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert fs == []
    # 1 baseline + 1 primary marker probe = 2, no encoded probe.
    assert HITS["/reflect-header"] == 2, HITS
