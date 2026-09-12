"""Per-host concurrency + request throttling tests (Phase 2, item 5).

Uses TWO stdlib ThreadingHTTPServer instances (different ports = different
authorities) with server-side tracking of in-flight concurrency and request
receipt times. No new dependencies.

Proves:
1. Per-host concurrency cap is enforced (max observed concurrency == limit).
2. Different hosts progress independently (no global serialization).
3. Minimum delay spaces request starts per host.
4. The delay on host A does not delay the first request to host B.
5. A failed request releases its slot (subsequent request proceeds).
6. Item 4 response-size protection still works with the limiter active.
Plus: authority normalization, config normalization, default-limit fallback.
"""
import asyncio
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import aiohttp
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

os.environ["DATABASE_URL"] = "sqlite:///./data/xsshunter_throttle_test.db"
os.environ["RUN_EMBEDDED_WORKER"] = "false"
os.environ.pop("SCANNER_MAX_CONCURRENCY_PER_HOST", None)
os.environ.pop("SCANNER_MIN_DELAY_MS", None)

import scanner_engine  # noqa: E402
from scanner_engine import RequestLimiter, _fetch, _env_int  # noqa: E402


# ---------------------------------------------------------------------------
# Tracked HTTP servers
# ---------------------------------------------------------------------------

class _Track:
    def __init__(self):
        self.lock = threading.Lock()
        self.current = 0
        self.maximum = 0
        self.intervals = []   # (start, end) monotonic, per /slow request
        self.receipts = []    # monotonic receipt times for /fast requests


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, body: bytes):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        tr = self.server.track
        if path == "/slow":
            start = time.monotonic()
            with tr.lock:
                tr.current += 1
                tr.maximum = max(tr.maximum, tr.current)
            time.sleep(0.2)
            with tr.lock:
                tr.current -= 1
                tr.intervals.append((start, time.monotonic()))
            self._send(b"slow-ok")
        elif path == "/fast":
            with tr.lock:
                tr.receipts.append(time.monotonic())
            self._send(b"fast-ok")
        elif path == "/boom":
            # Drop the connection without a response -> client-side error
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            finally:
                self.connection.close()
        elif path == "/big":
            self._send(b"A" * (2 * 1024 * 1024))
        else:
            self.send_response(404)
            self.end_headers()


_SERVERS = {}


def _start_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    srv.track = _Track()
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    _SERVERS[srv.server_address[1]] = srv
    return srv


def _track(base):
    """Return the server-side tracker for a base URL like http://127.0.0.1:PORT."""
    return _SERVERS[int(base.rsplit(":", 1)[1])].track


def _reset(*bases):
    """Clear server-side trackers (module-scoped servers are shared across tests)."""
    for base in bases:
        tr = _track(base)
        with tr.lock:
            tr.current = 0
            tr.maximum = 0
            tr.intervals.clear()
            tr.receipts.clear()


@pytest.fixture(scope="module")
def server_a():
    srv = _start_server()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


@pytest.fixture(scope="module")
def server_b():
    srv = _start_server()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    return asyncio.run(coro)


async def _gather(base, path, n, limiter):
    async with aiohttp.ClientSession() as s:
        return await asyncio.gather(*[
            _fetch(s, "GET", base + path, limiter=limiter, timeout=20)
            for _ in range(n)
        ])


# ---------------------------------------------------------------------------
# Test 1 — per-host concurrency cap
# ---------------------------------------------------------------------------

def test_per_host_concurrency_cap_enforced(server_a):
    _reset(server_a)
    async def go():
        lim = RequestLimiter(max_concurrency=2, min_delay_ms=0)
        return await _gather(server_a, "/slow", 5, lim)
    results = _run(go())
    assert all(r[0] == 200 for r in results), f"all requests complete: {results}"
    assert _track(server_a).maximum == 2, (
        f"server observed max concurrency {_track(server_a).maximum}, limit was 2"
    )


# ---------------------------------------------------------------------------
# Test 2 — different hosts are independent (no global semaphore)
# ---------------------------------------------------------------------------

def test_different_hosts_progress_concurrently(server_a, server_b):
    _reset(server_a, server_b)
    async def go():
        lim = RequestLimiter(max_concurrency=1, min_delay_ms=0)  # 1 per host
        async with aiohttp.ClientSession() as s:
            return await asyncio.gather(
                _fetch(s, "GET", server_a + "/slow", limiter=lim, timeout=20),
                _fetch(s, "GET", server_b + "/slow", limiter=lim, timeout=20),
            )
    results = _run(go())
    assert all(r[0] == 200 for r in results)

    ta = _track(server_a)
    tb = _track(server_b)
    assert ta.maximum == 1 and tb.maximum == 1
    # With per-host limit 1, a global serializer would run them back-to-back.
    # Overlapping server-side intervals prove the hosts progressed concurrently.
    (a0, a1), = ta.intervals
    (b0, b1), = tb.intervals
    assert a0 < b1 and b0 < a1, "requests to different hosts must overlap in time"


# ---------------------------------------------------------------------------
# Test 3 — minimum delay spaces request starts per host
# ---------------------------------------------------------------------------

def test_min_delay_spaces_request_starts(server_a):
    _reset(server_a)

    async def go():
        lim = RequestLimiter(max_concurrency=2, min_delay_ms=100)
        return await _gather(server_a, "/fast", 3, lim)
    _run(go())

    receipts = sorted(_track(server_a).receipts)
    assert len(receipts) == 3
    gaps = [receipts[i + 1] - receipts[i] for i in range(2)]
    for g in gaps:
        assert g >= 0.085, f"request starts must be >= ~100ms apart, got gaps {gaps}"


# ---------------------------------------------------------------------------
# Test 4 — delay is per host
# ---------------------------------------------------------------------------

def test_delay_on_host_a_does_not_delay_host_b(server_a, server_b):
    _reset(server_a, server_b)

    async def go():
        lim = RequestLimiter(max_concurrency=1, min_delay_ms=250)
        async with aiohttp.ClientSession() as s:
            await _fetch(s, "GET", server_a + "/fast", limiter=lim, timeout=20)
            t0 = time.monotonic()
            await _fetch(s, "GET", server_b + "/fast", limiter=lim, timeout=20)
            return t0
    t0 = _run(go())

    b_receipt = _track(server_b).receipts[-1]
    assert b_receipt - t0 < 0.15, (
        f"first request to host B must not wait on host A's pacing (took {b_receipt - t0:.3f}s)"
    )


# ---------------------------------------------------------------------------
# Test 5 — exceptions release the limiter slot
# ---------------------------------------------------------------------------

def test_failed_request_releases_slot(server_a):
    async def go():
        lim = RequestLimiter(max_concurrency=1, min_delay_ms=0)
        async with aiohttp.ClientSession() as s:
            r1 = await _fetch(s, "GET", server_a + "/boom", limiter=lim, timeout=5)
            # If the slot leaked, this second request would never acquire it.
            r2 = await asyncio.wait_for(
                _fetch(s, "GET", server_a + "/fast", limiter=lim, timeout=5),
                timeout=10,
            )
            return r1, r2
    r1, r2 = _run(go())
    assert r1[0] == 0, f"failed request must surface as status 0, got {r1}"
    assert r2[0] == 200 and r2[1] == "fast-ok"


# ---------------------------------------------------------------------------
# Test 6 — response-size protection still works with the limiter active
# ---------------------------------------------------------------------------

def test_size_cap_still_enforced_with_limiter(server_a, monkeypatch):
    monkeypatch.setattr(scanner_engine, "MAX_BODY_BYTES", 64 * 1024)
    async def go():
        lim = RequestLimiter(max_concurrency=2, min_delay_ms=0)
        async with aiohttp.ClientSession() as s:
            return await _fetch(s, "GET", server_a + "/big", limiter=lim, timeout=20)
    status, body, _, truncated = _run(go())
    assert status == 200
    assert truncated is True
    assert len(body.encode("utf-8", "ignore")) <= 64 * 1024


# ---------------------------------------------------------------------------
# Authority identity + configuration validation
# ---------------------------------------------------------------------------

def test_authority_normalization():
    a = RequestLimiter.authority_for
    assert a("http://example.com/x") == a("http://example.com:80/x")     # default port normalized
    assert a("https://example.com") == a("https://example.com:443")
    assert a("http://example.com") != a("https://example.com")           # scheme matters
    assert a("http://example.com:8080") != a("http://example.com")       # non-default port distinct
    assert a("https://example.com:8443") != a("https://example.com")     # 8443 is its own service
    assert a("http://EXAMPLE.com/Path") == a("http://example.com/")      # host case-insensitive


def test_limiter_config_is_normalized_never_unlimited():
    lim = RequestLimiter(max_concurrency=0, min_delay_ms=-50)
    assert lim._max == 1          # 0 -> 1, never unlimited
    assert lim._delay == 0.0      # negative delay -> 0
    lim2 = RequestLimiter(max_concurrency="bogus", min_delay_ms="bogus")
    assert lim2._max == 1
    assert lim2._delay == 0.0


def test_env_int_helper_rejects_invalid_values():
    assert _env_int("XSS_TEST_MISSING_ENV", 5, 1) == 5
    os.environ["XSS_TEST_BAD_ENV"] = "not-a-number"
    try:
        assert _env_int("XSS_TEST_BAD_ENV", 7, 1) == 7   # invalid -> default
    finally:
        os.environ.pop("XSS_TEST_BAD_ENV", None)
    os.environ["XSS_TEST_NEG_ENV"] = "-3"
    try:
        assert _env_int("XSS_TEST_NEG_ENV", 7, 1) == 1   # below floor -> floor
    finally:
        os.environ.pop("XSS_TEST_NEG_ENV", None)


def test_default_limiter_covers_out_of_scan_fetch(server_a):
    """_fetch called WITHOUT an explicit limiter (e.g. Test-Auth endpoint path)
    still passes through the per-loop default limiter."""
    async def go():
        async with aiohttp.ClientSession() as s:
            return await _fetch(s, "GET", server_a + "/fast", timeout=10)
    status, body, _, truncated = _run(go())
    assert status == 200 and body == "fast-ok"
    assert scanner_engine.MAX_CONCURRENCY_PER_HOST == 5  # env default
    assert scanner_engine.MIN_DELAY_MS == 0
