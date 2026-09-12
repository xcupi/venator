"""Async scanner engine that consumes a Scan record and populates findings.

Runs standalone in the scanner worker container, and can also be invoked in-process
for the Emergent preview (see server.py background task).

Authenticated scanning:
- Auth material comes exclusively from a user-provided AuthProfile.
- Scope is validated before every request, and auth material is NEVER attached
  to out-of-scope hosts (see auth_http.should_attach_auth).
- Session loss is detected via 401/403 or configured login indicators; the scan
  transitions to AUTHENTICATION_REQUIRED and stops instead of retrying.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
import weakref
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlsplit

import aiohttp
from sqlalchemy import update

from db import SessionLocal
from models import Scan, Project, DiscoveredURL, Candidate, Finding, AuthProfile
from scanner_core import (
    DEFAULT_MARKER,
    ENCODED_PROBE,
    apply_baseline_and_header_context,
    classify_context,
    classify_finding,
    extract_csrf_values,
    extract_get_params,
    extract_links_and_forms,
    guess_severity,
    in_scope,
    normalize_url,
)
from auth_http import build_auth, looks_like_auth_loss, should_attach_auth

log = logging.getLogger("scanner")

DESTRUCTIVE_KEYWORDS = ("logout", "signout", "delete", "destroy", "remove")

# Placeholder value used for baseline (pre-injection) probes. Chosen so that
# it CANNOT contain the reflection marker and CANNOT trigger CSRF/tokenised
# processing on the target. Human-readable so requests remain benign.
BASELINE_PLACEHOLDER = "baseline"


def _now():
    return datetime.now(timezone.utc)


class AuthLostError(RuntimeError):
    """Raised when the configured authentication session appears to have expired."""


def _finding_exists(db, scan_id: str, url: str, method: str, param: str, context: str) -> bool:
    """Return True if a Finding with the same (scan_id, url, method, param, context)
    already exists. Used to prevent duplicate findings when the same reflecting
    endpoint is reached via multiple DiscoveredURL rows (e.g. crawled through
    several internal links). Dedup is intentionally scoped per-scan so distinct
    scans still record independent findings for the same URL.
    """
    return db.query(Finding.id).filter(
        Finding.scan_id == scan_id,
        Finding.url == url,
        Finding.method == method,
        Finding.param == param,
        Finding.context == context,
    ).first() is not None


# Maximum DECOMPRESSED response body bytes retained per request. Bodies larger
# than this are read incrementally and cut at the limit; the caller receives a
# `truncated` flag so the reflection engine can stay conservative.
MAX_BODY_BYTES = max(1024, int(os.environ.get("SCANNER_MAX_BODY_BYTES", str(5 * 1024 * 1024))))


def _env_int(name: str, default: int, floor: int) -> int:
    """Parse an int env var, normalized to >= floor. Invalid values fall back
    to the default with a warning — never to an unlimited/disabled setting."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return max(floor, int(raw))
    except ValueError:
        log.warning("invalid %s=%r; using default %d", name, raw, default)
        return default


# Per-host request governance (Phase 2). Defaults keep existing functional
# behavior: 5 concurrent requests per host, no artificial delay.
MAX_CONCURRENCY_PER_HOST = _env_int("SCANNER_MAX_CONCURRENCY_PER_HOST", 5, 1)
MIN_DELAY_MS = _env_int("SCANNER_MIN_DELAY_MS", 0, 0)

_DEFAULT_PORTS = {"http": 80, "https": 443}


class _HostThrottle:
    """Concurrency slot + start-pacing state for ONE authority."""

    __slots__ = ("sem", "delay", "pace_lock", "last_start")

    def __init__(self, max_concurrency: int, delay: float):
        self.sem = asyncio.Semaphore(max_concurrency)
        self.delay = delay
        self.pace_lock = asyncio.Lock()
        self.last_start = 0.0

    async def acquire(self):
        await self.sem.acquire()
        if self.delay > 0:
            # Serialize request STARTS for this host so they are spaced by at
            # least `delay` seconds. The concurrency slot stays held during
            # pacing, the request, and body consumption.
            async with self.pace_lock:
                now = time.monotonic()
                wait = self.last_start + self.delay - now
                if wait > 0:
                    await asyncio.sleep(wait)
                self.last_start = time.monotonic()

    def release(self):
        self.sem.release()


class RequestLimiter:
    """In-process per-authority request limiter, scoped to a single scan.

    - max_concurrency: max simultaneous in-flight requests per authority (>= 1).
    - min_delay_ms:    minimum milliseconds between request STARTS per
                       authority (>= 0; 0 disables pacing).

    The per-host registry lives and dies with the owning scan, so state cannot
    accumulate across scans. Invalid values are normalized (never unlimited).
    """

    def __init__(self, max_concurrency: int = 5, min_delay_ms: int = 0):
        try:
            self._max = max(1, int(max_concurrency))
        except (TypeError, ValueError):
            log.warning("invalid max_concurrency=%r; normalized to 1", max_concurrency)
            self._max = 1
        try:
            self._delay = max(0.0, float(min_delay_ms) / 1000.0)
        except (TypeError, ValueError):
            log.warning("invalid min_delay_ms=%r; normalized to 0", min_delay_ms)
            self._delay = 0.0
        self._hosts: dict = {}

    @staticmethod
    def authority_for(url: str) -> str:
        """Host identity: scheme + hostname + effective port (default ports
        normalized, so http://h == http://h:80 but https://h:8443 differs)."""
        try:
            p = urlsplit(url)
            scheme = (p.scheme or "http").lower()
            host = (p.hostname or "unknown").lower()
            try:
                port = p.port or _DEFAULT_PORTS.get(scheme, 0)
            except ValueError:
                port = _DEFAULT_PORTS.get(scheme, 0)
            return f"{scheme}://{host}:{port}"
        except Exception:
            return "unknown://unknown:0"

    def for_url(self, url: str) -> _HostThrottle:
        key = self.authority_for(url)
        th = self._hosts.get(key)
        if th is None:
            th = _HostThrottle(self._max, self._delay)
            self._hosts[key] = th
        return th


# Fallback limiter for _fetch calls that run OUTSIDE a scan context (e.g. the
# Test-Authentication endpoint). One instance per event loop: asyncio
# primitives must not be shared across loops, and entries die with their loop.
_DEFAULT_LIMITERS: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def _get_default_limiter() -> RequestLimiter:
    loop = asyncio.get_running_loop()
    lim = _DEFAULT_LIMITERS.get(loop)
    if lim is None:
        lim = RequestLimiter(MAX_CONCURRENCY_PER_HOST, MIN_DELAY_MS)
        _DEFAULT_LIMITERS[loop] = lim
    return lim


async def _read_bounded(resp: aiohttp.ClientResponse, limit: int) -> Tuple[str, bool]:
    """Read a response body incrementally, capped at ``limit`` bytes.

    aiohttp's default auto-decompression applies to ``resp.content``, so the cap
    bounds the DECOMPRESSED body held in memory — not merely the compressed wire
    size — and Content-Length is never trusted for allocation. Memory overhead
    beyond ``limit`` is at most one chunk (64 KiB).

    Returns (text, truncated). When the body exceeds the limit, ``truncated`` is
    True and ``text`` is a strict prefix of the full body — callers must NOT
    treat "marker not found" in a truncated body as "no reflection".
    """
    buf = bytearray()
    truncated = False
    async for chunk in resp.content.iter_chunked(65536):
        overflow = len(buf) + len(chunk) - limit
        if overflow > 0:
            buf.extend(chunk[: len(chunk) - overflow])
            truncated = True
            break
        buf.extend(chunk)
    # Match resp.text() decoding when a charset is declared. When it is not,
    # aiohttp's chardet fallback requires resp._body, which incremental reads
    # never populate — fall back to utf-8 in that case.
    try:
        encoding = resp.get_encoding()
    except Exception:
        encoding = resp.charset or "utf-8"
    return bytes(buf).decode(encoding, errors="ignore"), truncated


async def _fetch(session: aiohttp.ClientSession, method: str, url: str,
                 params=None, data=None, timeout: int = 15,
                 auth_headers=None, auth_cookies=None, allowed_domains=None,
                 limiter: Optional[RequestLimiter] = None):
    """Scope-safe HTTP fetch. Never attaches auth to out-of-scope hosts.

    Every request passes through the per-authority limiter (scan-scoped, or the
    per-loop default outside scan context): acquire a concurrency slot, pace the
    request start if configured, perform the request, consume the bounded body,
    then release the slot — including on exceptions, so a failed request can
    never permanently exhaust a host's slots.

    Redirects: aiohttp follows redirects internally; the limiter keys on the
    INITIAL request URL. Intermediate redirect targets are not separately
    throttled (documented limitation — changing that would require redesigning
    aiohttp's redirect handling).

    Returns ``(status, body, final_url, truncated, headers)``.
    ``headers`` is a list of ``(name, value)`` tuples captured from the
    final response — list form preserves multi-value headers such as
    ``Set-Cookie``. On transport errors returns ``(0, "", str(exc), False, [])``.
    """
    hdrs = {}
    cookies = None
    if auth_headers or auth_cookies:
        if allowed_domains and should_attach_auth(url, allowed_domains):
            hdrs.update(auth_headers or {})
            if auth_cookies:
                cookies = dict(auth_cookies)
    throttle = (limiter or _get_default_limiter()).for_url(url)
    await throttle.acquire()
    try:
        async with session.request(
            method, url, params=params, data=data, timeout=timeout,
            allow_redirects=True, headers=hdrs or None, cookies=cookies,
        ) as resp:
            body, truncated = await _read_bounded(resp, MAX_BODY_BYTES)
            # Snapshot response headers as a list of (name, value) tuples.
            # This preserves multi-value headers (e.g. Set-Cookie) that the
            # baseline / header-reflection guard needs to inspect.
            resp_headers = [(str(k), str(v)) for k, v in resp.headers.items()]
            return resp.status, body, str(resp.url), truncated, resp_headers
    except Exception as e:
        return 0, "", str(e), False, []
    finally:
        throttle.release()


async def _crawl(scan_id: str, allowed: list, excluded: list, target: str, cfg: dict,
                 auth_headers: dict, auth_cookies: dict, login_indicators: list,
                 limiter: Optional[RequestLimiter] = None):
    """BFS crawl within scope. Persists discovered URLs (+ form param targets)."""
    max_urls = int(cfg.get("max_urls", 100))
    max_depth = int(cfg.get("max_depth", 3))
    timeout = int(cfg.get("request_timeout", 15))

    seen: Set[str] = set()
    queue: List[tuple] = [(target, 0)]
    async with aiohttp.ClientSession(headers={"User-Agent": "reflected-xss-hunter/1.0"}) as session:
        while queue and len(seen) < max_urls:
            url, depth = queue.pop(0)
            n = normalize_url(url)
            if n in seen:
                continue
            if not in_scope(n, allowed, excluded):
                continue
            seen.add(n)

            status, body, final_url, truncated, _ = await _fetch(
                session, "GET", n, timeout=timeout,
                auth_headers=auth_headers, auth_cookies=auth_cookies, allowed_domains=allowed,
                limiter=limiter,
            )
            if status == 0:
                continue
            if truncated:
                # Only the retained prefix is parsed for links/forms; never crash
                # or treat truncation as an empty page.
                log.debug("crawl: response truncated at %d bytes for %s", MAX_BODY_BYTES, n)

            # Auth-loss detection on crawler responses
            if (auth_headers or auth_cookies) and looks_like_auth_loss(status, body, login_indicators):
                raise AuthLostError(f"Authentication lost while crawling {n} (status {status})")

            with SessionLocal() as db:
                s = db.query(Scan).filter(Scan.id == scan_id).first()
                if not s or s.status in ("STOPPING", "STOPPED"):
                    return
                params = extract_get_params(n)
                db.add(DiscoveredURL(scan_id=scan_id, url=n, method="GET", params=params, depth=depth))
                s.stats = {**(s.stats or {}), "urls_crawled": len(seen)}
                db.commit()

            if depth < max_depth:
                links, forms = extract_links_and_forms(final_url, body)
                for l in links:
                    ln = normalize_url(l)
                    if ln in seen:
                        continue
                    if not in_scope(ln, allowed, excluded):
                        continue
                    # Never auto-visit obviously destructive endpoints
                    if any(k in ln.lower() for k in DESTRUCTIVE_KEYWORDS):
                        continue
                    queue.append((ln, depth + 1))
                with SessionLocal() as db:
                    for f in forms:
                        low = f.url.lower()
                        if any(k in low for k in DESTRUCTIVE_KEYWORDS):
                            continue
                        if in_scope(f.url, allowed, excluded):
                            db.add(DiscoveredURL(
                                scan_id=scan_id, url=normalize_url(f.url),
                                method=f.method, params=f.params, depth=depth + 1,
                                origin_url=f.origin_url or final_url,
                                csrf_fields=list(f.csrf_fields or []),
                                hidden_fields=dict(f.hidden_fields or {}),
                            ))
                    db.commit()


@dataclass
class _ProbeOutcome:
    """Structured result of running the marker + optional encoded probe for
    ONE (url, param) pair. Populated identically by all three probe helpers so
    _test_reflection can stay branch-free.

    - status/body/truncated/req_dump/headers: primary marker probe response
      (headers is a list of (name, value) tuples). Used by classify_context
      AND the header-reflection guard.
    - encoded_body/encoded_truncated: encoded-probe response used ONLY to
      demote reflections in html/attribute context to 'encoded'. Set to
      (None, False) when no encoded probe was applicable/sent.
    - csrf_missing / csrf_refresh_failed: the CSRF-protected POST probe could
      not obtain / refresh the required token; primary probe was NOT sent
      (missing) or the encoded probe was NOT sent (refresh_failed). The caller
      records a csrf_token_required finding and skips the URL/param.
    """
    status: int = 0
    body: str = ""
    truncated: bool = False
    req_dump: str = ""
    headers: list = None  # type: ignore[assignment]
    encoded_body: Optional[str] = None
    encoded_truncated: bool = False
    csrf_missing: bool = False
    csrf_refresh_failed: bool = False

    def __post_init__(self):
        if self.headers is None:
            self.headers = []


def _should_probe_encoding(body: str, marker: str) -> bool:
    """Encoded-probe gate: only send the encoded probe when the primary marker
    landed in a rendering sink where HTML-escaping would matter (html or
    attribute context). Matches the pre-refactor gate exactly."""
    return bool(body) and classify_context(body, marker) in ("html", "attribute")


async def _probe_get(
    session: aiohttp.ClientSession, base_url: str, other: dict,
    pname: str, inj: str, marker: str,
    auth_headers: dict, auth_cookies: dict, allowed: list,
    timeout: int, limiter: Optional["RequestLimiter"],
) -> _ProbeOutcome:
    """GET probe: primary marker + (optional) encoded probe on the shared session."""
    q = {**other, pname: inj}
    status, body, _, truncated, resp_headers = await _fetch(
        session, "GET", base_url, params=q, timeout=timeout,
        auth_headers=auth_headers, auth_cookies=auth_cookies, allowed_domains=allowed,
        limiter=limiter,
    )
    out = _ProbeOutcome(
        status=status, body=body, truncated=truncated,
        req_dump=f"GET {base_url}?{pname}={inj}",
        headers=resp_headers,
    )
    if _should_probe_encoding(body, marker):
        q2 = {**other, pname: ENCODED_PROBE}
        _, eb, _, et, _ = await _fetch(
            session, "GET", base_url, params=q2, timeout=timeout,
            auth_headers=auth_headers, auth_cookies=auth_cookies, allowed_domains=allowed,
            limiter=limiter,
        )
        out.encoded_body, out.encoded_truncated = eb, et
    return out


async def _probe_post_plain(
    session: aiohttp.ClientSession, url: str, pname: str, inj: str,
    hidden_fields: dict, marker: str,
    auth_headers: dict, auth_cookies: dict, allowed: list,
    timeout: int, limiter: Optional["RequestLimiter"],
) -> _ProbeOutcome:
    """POST probe (no CSRF fields): primary + optional encoded probe on the shared session."""
    data = {**(hidden_fields or {}), pname: inj}
    status, body, _, truncated, resp_headers = await _fetch(
        session, "POST", url, data=data, timeout=timeout,
        auth_headers=auth_headers, auth_cookies=auth_cookies, allowed_domains=allowed,
        limiter=limiter,
    )
    out = _ProbeOutcome(
        status=status, body=body, truncated=truncated,
        req_dump=f"POST {url}\n" + "\n".join(f"{k}={v}" for k, v in data.items()),
        headers=resp_headers,
    )
    if _should_probe_encoding(body, marker):
        _, eb, _, et, _ = await _fetch(
            session, "POST", url,
            data={**(hidden_fields or {}), pname: ENCODED_PROBE}, timeout=timeout,
            auth_headers=auth_headers, auth_cookies=auth_cookies, allowed_domains=allowed,
            limiter=limiter,
        )
        out.encoded_body, out.encoded_truncated = eb, et
    return out


async def _probe_post_csrf(
    url: str, origin_url: str, pname: str, inj: str,
    csrf_fields: list, hidden_fields: dict, marker: str,
    auth_headers: dict, auth_cookies: dict, allowed: list,
    timeout: int, limiter: Optional["RequestLimiter"],
) -> _ProbeOutcome:
    """CSRF-protected POST probe. Primary + encoded probe live inside the SAME
    ``aiohttp.CookieJar``-backed session so any framework session cookie
    (Flask/Django/Rails) set on the origin refetch is replayed on the follow-up
    POST. Auth cookies (from the profile) are seeded into the jar and remain
    scoped to the target host by aiohttp. If a required CSRF field cannot be
    obtained/refreshed, the corresponding request is NOT sent — never bypass
    CSRF."""
    jar = aiohttp.CookieJar(unsafe=True)
    async with aiohttp.ClientSession(
        cookie_jar=jar,
        cookies=auth_cookies or None,
        headers={"User-Agent": "reflected-xss-hunter/1.0", **(auth_headers or {})},
    ) as csrf_session:
        _, origin_body, _, _, _ = await _fetch(
            csrf_session, "GET", origin_url, timeout=timeout,
            allowed_domains=allowed, limiter=limiter,
        )
        fresh_csrf = extract_csrf_values(origin_body, csrf_fields)
        if not fresh_csrf or any(not fresh_csrf.get(n) for n in csrf_fields):
            return _ProbeOutcome(csrf_missing=True)

        data = {**(hidden_fields or {}), **fresh_csrf, pname: inj}
        status, body, _, truncated, resp_headers = await _fetch(
            csrf_session, "POST", url, data=data, timeout=timeout,
            allowed_domains=allowed, limiter=limiter,
        )
        out = _ProbeOutcome(
            status=status, body=body, truncated=truncated,
            req_dump=f"POST {url}\n" + "\n".join(f"{k}={v}" for k, v in data.items()),
            headers=resp_headers,
        )

        # Encoded reflection probe for CSRF-protected POSTs. Same jar-session
        # so the authenticated framework session is preserved. Frameworks
        # commonly rotate the token on every POST, so refresh the origin and
        # require a full fresh token set before sending; if refresh fails we
        # do NOT blind-submit.
        if _should_probe_encoding(body, marker):
            _, origin_body2, _, _, _ = await _fetch(
                csrf_session, "GET", origin_url, timeout=timeout,
                allowed_domains=allowed, limiter=limiter,
            )
            fresh_csrf2 = extract_csrf_values(origin_body2, csrf_fields)
            if not fresh_csrf2 or any(not fresh_csrf2.get(n) for n in csrf_fields):
                out.csrf_refresh_failed = True
            else:
                data2 = {**(hidden_fields or {}), **fresh_csrf2, pname: ENCODED_PROBE}
                _, eb, _, et, _ = await _fetch(
                    csrf_session, "POST", url, data=data2, timeout=timeout,
                    allowed_domains=allowed, limiter=limiter,
                )
                out.encoded_body, out.encoded_truncated = eb, et
        return out


def _record_csrf_required(scan_id: str, url: str, method: str, pname: str,
                          csrf_fields: list, origin_url: str,
                          csrf_missing: bool) -> None:
    """Record a csrf_token_required finding (idempotent via _finding_exists).

    Two reasons feed this: (a) origin refetch produced no CSRF value at all
    (``csrf_missing=True``) — primary probe was never sent; (b) origin refetch
    succeeded for the primary probe but the token rotation after the primary
    could not be refreshed for the encoded probe (``csrf_missing=False``).
    The evidence text reflects which case occurred, matching pre-refactor
    behaviour."""
    with SessionLocal() as db:
        if _finding_exists(db, scan_id, url, method, pname, "csrf_required"):
            return
        reason = (
            f"required CSRF field(s) {csrf_fields} could not be refreshed from {origin_url}"
            if csrf_missing else
            f"CSRF token refresh at {origin_url} failed before the encoded probe; "
            f"reflection confirmed by primary probe but encoding state unknown"
        )
        db.add(Finding(
            scan_id=scan_id, url=url, method=method, param=pname,
            context="csrf_required",
            classification=classify_finding("csrf_required", validated=False),
            severity="low",
            payload="",
            evidence=reason,
            request_dump=f"POST {url}\n(missing CSRF token: {csrf_fields})",
            response_snippet="",
        ))
        db.commit()


def _record_probe_result(scan_id: str, url: str, method: str, pname: str,
                          context: str, reflected: bool, marker: str,
                          body: str, req_dump: str) -> None:
    """Persist Candidate + (optionally) Finding for one probe outcome.

    Always increments ``params_tested`` and records a Candidate. Only creates
    a Finding when the marker was observed (``reflected=True``) and no
    prior finding for the same (scan, url, method, param, context) exists."""
    with SessionLocal() as db:
        db.add(Candidate(
            scan_id=scan_id, url=url, method=method, param=pname,
            context=context, reflected_raw=reflected, payload_marker=marker,
        ))
        s = db.query(Scan).filter(Scan.id == scan_id).first()
        if s:
            s.stats = {**(s.stats or {}), "params_tested": (s.stats or {}).get("params_tested", 0) + 1}
        db.commit()

        if reflected and not _finding_exists(db, scan_id, url, method, pname, context):
            snippet_idx = body.find(marker) if marker in body else -1
            snippet = body[max(0, snippet_idx - 80): snippet_idx + 160] if snippet_idx >= 0 else ""
            db.add(Finding(
                scan_id=scan_id, url=url, method=method, param=pname,
                context=context,
                classification=classify_finding(context, validated=False),
                severity=guess_severity(context, validated=False),
                payload="<probe>",
                evidence=f"marker reflected in {context} context",
                request_dump=req_dump,
                response_snippet=snippet,
            ))
            if s:
                s.stats = {**(s.stats or {}), "candidates": (s.stats or {}).get("candidates", 0) + 1}
            db.commit()


async def _fetch_baseline_get(
    session: aiohttp.ClientSession, base_url: str, all_query_params: list,
    auth_headers: dict, auth_cookies: dict, allowed: list,
    timeout: int, limiter: Optional["RequestLimiter"],
):
    """Fetch a neutral (pre-injection) baseline for a GET URL.

    Sends the URL once with EVERY discovered query param set to
    :data:`BASELINE_PLACEHOLDER`. Returns ``(body, headers)`` where headers is
    the list of ``(name, value)`` tuples from :func:`_fetch`, or ``(None, [])``
    on transport error.

    One baseline per URL — not per param — so cost is O(1) requests per URL
    regardless of param count. Same auth-scope guard, same throttling, same
    body-size cap as any other request.
    """
    q = {p: BASELINE_PLACEHOLDER for p in all_query_params}
    status, body, _, _, resp_headers = await _fetch(
        session, "GET", base_url, params=q, timeout=timeout,
        auth_headers=auth_headers, auth_cookies=auth_cookies, allowed_domains=allowed,
        limiter=limiter,
    )
    if status == 0:
        return None, []
    return body, resp_headers


async def _fetch_baseline_post(
    session: aiohttp.ClientSession, url: str, all_params: list,
    hidden_fields: dict,
    auth_headers: dict, auth_cookies: dict, allowed: list,
    timeout: int, limiter: Optional["RequestLimiter"],
):
    """Fetch a neutral baseline for a POST-plain URL.

    Sends the URL once with EVERY discovered form param set to
    :data:`BASELINE_PLACEHOLDER`, preserving hidden fields. NOT called for
    CSRF-protected POSTs (see :func:`_test_reflection` for rationale).
    """
    data = {**(hidden_fields or {}), **{p: BASELINE_PLACEHOLDER for p in all_params}}
    status, body, _, _, resp_headers = await _fetch(
        session, "POST", url, data=data, timeout=timeout,
        auth_headers=auth_headers, auth_cookies=auth_cookies, allowed_domains=allowed,
        limiter=limiter,
    )
    if status == 0:
        return None, []
    return body, resp_headers


async def _test_reflection(scan_id: str, cfg: dict, allowed: list,
                           auth_headers: dict, auth_cookies: dict, login_indicators: list,
                           limiter: Optional[RequestLimiter] = None):
    """Iterate every DiscoveredURL / param for a scan and probe for reflection.

    Pipeline:

        plan -> baseline (once per URL) -> probe -> classify
             -> apply baseline + header guard -> encoded demote -> record

    ``plan`` is one of {GET, POST_PLAIN, POST_CSRF} decided by the stored
    DiscoveredURL metadata. Each ``_probe_*`` helper returns a
    :class:`_ProbeOutcome` (which includes response headers) so the outer loop
    does not branch on method for classification either.

    Baseline: **one** GET / POST-plain request per URL with all discovered
    params replaced by :data:`BASELINE_PLACEHOLDER`. Its body + headers are
    passed to :func:`apply_baseline_and_header_context` after each param
    probe to (a) suppress false positives when the marker appears in the
    response independently of our injection and (b) promote reflections that
    only appear in response headers to the ``header`` context (classified as
    ``reflection_only`` — an echoed header is not directly executable XSS
    but is worth recording). CSRF-protected POSTs SKIP baseline: an extra
    origin-refetch + token-consuming POST would nearly double the CSRF
    overhead AND POST to state-mutating endpoints an extra time, both of
    which violate "avoid destructive/unnecessary requests".

    All pre-refactor invariants are preserved: same jar-backed session for
    CSRF primary + encoded probes, same encoded-probe gate
    (``classify_context in (html, attribute)``), same truncation-aware
    ``unknown`` context handling, same auth-loss detection, same finding
    dedup semantics, same per-authority throttling.
    """
    timeout = int(cfg.get("request_timeout", 15))
    marker = DEFAULT_MARKER

    with SessionLocal() as db:
        urls = db.query(DiscoveredURL).filter(DiscoveredURL.scan_id == scan_id).all()
        url_snapshot = [
            (u.id, u.url, u.method, u.params, u.origin_url or "",
             list(u.csrf_fields or []), dict(u.hidden_fields or {}))
            for u in urls
        ]

    async with aiohttp.ClientSession(headers={"User-Agent": "reflected-xss-hunter/1.0"}) as session:
        for uid, url, method, params, origin_url, csrf_fields, hidden_fields in url_snapshot:
            # Per-URL: honour STOPPING / PAUSED before touching the network.
            with SessionLocal() as db:
                s = db.query(Scan).filter(Scan.id == scan_id).first()
                if not s or s.status in ("STOPPING", "STOPPED"):
                    return
                while s and s.status == "PAUSED":
                    await asyncio.sleep(1)
                    db.refresh(s)

            if not params:
                params = ["q"]

            base_url_for_get = url.split("?", 1)[0]

            # Collect the FULL param set for this URL — used only to build the
            # baseline request. For GET this must include any query params
            # already present in the discovered URL, since those params can
            # affect page behaviour (routing, tabs, etc.); replacing them
            # with the placeholder gives a fair control response.
            all_url_params: list = list(params)
            if method == "GET" and "?" in url:
                for k, _v in parse_qsl(url.split("?", 1)[1], keep_blank_values=True):
                    if k not in all_url_params:
                        all_url_params.append(k)

            # Baseline: one request per URL, GET / POST-plain only. CSRF POST
            # baseline is intentionally skipped (see docstring).
            baseline_body = None
            baseline_headers: list = []
            if method == "GET":
                baseline_body, baseline_headers = await _fetch_baseline_get(
                    session, base_url_for_get, all_url_params,
                    auth_headers, auth_cookies, allowed, timeout, limiter,
                )
            elif method == "POST" and not (csrf_fields and origin_url):
                baseline_body, baseline_headers = await _fetch_baseline_post(
                    session, url, params, hidden_fields,
                    auth_headers, auth_cookies, allowed, timeout, limiter,
                )

            for pname in params:
                inj = f"pre_{marker}_post"
                base_url = base_url_for_get if method == "GET" else url
                other = {}
                if method == "GET" and "?" in url:
                    for k, v in parse_qsl(url.split("?", 1)[1], keep_blank_values=True):
                        if k != pname:
                            other[k] = v

                # Plan selection — exactly the pre-refactor branch conditions.
                if method == "POST" and csrf_fields and origin_url:
                    outcome = await _probe_post_csrf(
                        url, origin_url, pname, inj, csrf_fields, hidden_fields, marker,
                        auth_headers, auth_cookies, allowed, timeout, limiter,
                    )
                elif method == "GET":
                    outcome = await _probe_get(
                        session, base_url, other, pname, inj, marker,
                        auth_headers, auth_cookies, allowed, timeout, limiter,
                    )
                else:  # POST without CSRF fields
                    outcome = await _probe_post_plain(
                        session, url, pname, inj, hidden_fields, marker,
                        auth_headers, auth_cookies, allowed, timeout, limiter,
                    )

                # CSRF token unavailable / not refreshable: record and skip.
                if outcome.csrf_missing or outcome.csrf_refresh_failed:
                    _record_csrf_required(
                        scan_id, url, method, pname, csrf_fields, origin_url,
                        csrf_missing=outcome.csrf_missing,
                    )
                    continue

                # Transport error: do not record; move on.
                if outcome.status == 0:
                    continue

                # Auth-loss on the primary probe → escalate.
                if (auth_headers or auth_cookies) and looks_like_auth_loss(
                        outcome.status, outcome.body, login_indicators):
                    raise AuthLostError(
                        f"Authentication lost while testing {url} (status {outcome.status})"
                    )

                context = classify_context(outcome.body, marker)
                reflected = context != "none"
                if outcome.truncated and not reflected:
                    # Body was cut at MAX_BODY_BYTES before the marker could be
                    # observed — reflection state is UNKNOWN. Preserve pre-
                    # refactor behaviour: record a Candidate with context
                    # 'unknown' and DO NOT create a Finding (reflected stays
                    # False).
                    log.warning(
                        "response truncated at %d bytes before marker could be observed: %s %s param=%s",
                        MAX_BODY_BYTES, method, url, pname,
                    )
                    context = "unknown"

                # Baseline diff + header-reflection guard. Pure function; may
                # downgrade a body reflection to ("none", False) when the
                # baseline already contained the marker (→ false_positive) or
                # promote a header-only reflection to ("header", True)
                # (→ reflection_only). Truncated results (context=="unknown")
                # are passed through unchanged — see rule 1 of the helper.
                context, reflected = apply_baseline_and_header_context(
                    context, reflected, outcome.truncated, marker,
                    outcome.headers, baseline_body, baseline_headers,
                )

                # Demote html/attribute reflections to 'encoded' when the
                # encoded probe proves the target HTML-escapes the input.
                # A truncated probe response cannot prove safe encoding —
                # "probe not found" in a cut body may just mean the reflection
                # lies beyond the retained prefix, so the demotion requires
                # the FULL body.
                if reflected and context in ("html", "attribute"):
                    if (outcome.encoded_body and not outcome.encoded_truncated
                            and ENCODED_PROBE not in outcome.encoded_body
                            and ("&lt;" in outcome.encoded_body or "&gt;" in outcome.encoded_body)):
                        context = "encoded"

                _record_probe_result(
                    scan_id, url, method, pname, context, reflected,
                    marker, outcome.body, outcome.req_dump,
                )


async def _preflight_auth(target: str, allowed: list,
                          auth_headers: dict, auth_cookies: dict,
                          check_url: str, login_indicators: list, timeout: int,
                          limiter: Optional[RequestLimiter] = None) -> tuple:
    """Return (valid: bool, status: int, final_url: str, notes: str)."""
    probe_url = check_url or target
    if not in_scope(probe_url, allowed, []):
        return False, 0, probe_url, "check_url is outside project scope"
    async with aiohttp.ClientSession(headers={"User-Agent": "reflected-xss-hunter/1.0"}) as session:
        status, body, final, _, _ = await _fetch(
            session, "GET", probe_url, timeout=timeout,
            auth_headers=auth_headers, auth_cookies=auth_cookies, allowed_domains=allowed,
            limiter=limiter,
        )
    if status == 0:
        return False, 0, probe_url, "network error"
    if looks_like_auth_loss(status, body, login_indicators):
        return False, status, final, "response looks unauthenticated"
    return True, status, final, "ok"


async def run_scan(scan_id: str):
    """Main entrypoint executed by the worker."""
    with SessionLocal() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        project = db.query(Project).filter(Project.id == scan.project_id).first()
        if not project:
            scan.status = "FAILED"
            scan.error = "Project not found"
            db.commit()
            return
        profile = None
        if scan.auth_profile_id:
            profile = db.query(AuthProfile).filter(AuthProfile.id == scan.auth_profile_id).first()
        scan.status = "RUNNING"
        scan.started_at = _now()
        scan.stats = {"urls_crawled": 0, "params_tested": 0, "candidates": 0, "auth_status": "n/a"}
        db.commit()
        cfg = dict(scan.config or {})
        target = scan.target_url
        allowed = list(project.allowed_domains or [])
        excluded = list(project.excluded_paths or [])
        auth_headers, auth_cookies = build_auth(profile) if profile else ({}, {})
        login_indicators = list((profile.config or {}).get("login_indicators", [])) if profile else []
        check_url = (profile.config or {}).get("check_url") if profile else None
        # Per-scan request governance: per-authority concurrency cap + optional
        # pacing. Per-scan config keys override the process env defaults; the
        # limiter registry lives only for the duration of this scan.
        limiter = RequestLimiter(
            max_concurrency=cfg.get("max_concurrency_per_host", MAX_CONCURRENCY_PER_HOST),
            min_delay_ms=cfg.get("min_delay_ms", MIN_DELAY_MS),
        )

    try:
        # Session preflight when auth is configured
        if profile:
            valid, status, final, notes = await _preflight_auth(
                target, allowed, auth_headers, auth_cookies,
                check_url, login_indicators, int(cfg.get("request_timeout", 15)),
                limiter=limiter,
            )
            with SessionLocal() as db:
                s = db.query(Scan).filter(Scan.id == scan_id).first()
                s.stats = {**(s.stats or {}), "auth_status": "VALID" if valid else "INVALID"}
                db.commit()
            if not valid:
                raise AuthLostError(f"Preflight failed ({notes}, status {status}, final {final})")

        await _crawl(scan_id, allowed, excluded, target, cfg,
                     auth_headers, auth_cookies, login_indicators, limiter=limiter)
        await _test_reflection(scan_id, cfg, allowed,
                               auth_headers, auth_cookies, login_indicators, limiter=limiter)
        with SessionLocal() as db:
            s = db.query(Scan).filter(Scan.id == scan_id).first()
            if s.status == "STOPPING":
                s.status = "STOPPED"
            else:
                s.status = "COMPLETED"
            s.completed_at = _now()
            db.commit()
    except AuthLostError as e:
        log.warning("auth lost: %s", e)
        with SessionLocal() as db:
            s = db.query(Scan).filter(Scan.id == scan_id).first()
            if s:
                s.status = "AUTHENTICATION_REQUIRED"
                s.error = str(e)
                s.completed_at = _now()
                db.commit()
    except Exception as e:
        log.exception("scan failed")
        with SessionLocal() as db:
            s = db.query(Scan).filter(Scan.id == scan_id).first()
            if s:
                s.status = "FAILED"
                s.error = str(e)
                s.completed_at = _now()
                db.commit()


def try_claim_scan(scan_id: str) -> bool:
    """Atomically transition a single scan QUEUED -> RUNNING.

    Uses a conditional UPDATE (``WHERE id = :id AND status = 'QUEUED'``) so that
    exactly one competing worker can win the claim: on PostgreSQL the second
    updater blocks on the row lock and then re-evaluates the WHERE against the
    committed row (0 rows matched); on SQLite the single-statement update is
    atomic under the database write lock. Compatible with both supported
    databases, no schema changes required.

    The transaction is deliberately short — it commits before the caller ever
    invokes the long-running run_scan().

    Returns True iff THIS caller performed the transition.
    """
    with SessionLocal() as db:
        res = db.execute(
            update(Scan)
            .where(Scan.id == scan_id, Scan.status == "QUEUED")
            .values(status="RUNNING", started_at=_now())
        )
        db.commit()
        return res.rowcount == 1


def claim_next_queued_scan(max_attempts: int = 3) -> Optional[str]:
    """Select the oldest QUEUED scan and atomically claim it.

    If a competing worker wins the race for the selected candidate, the next
    oldest QUEUED scan is tried (up to ``max_attempts``), so queued work is not
    skipped merely because of a lost race. Returns the claimed scan id, or
    None when no QUEUED scan could be claimed. Used identically by the
    standalone worker and the embedded API worker.
    """
    for _ in range(max_attempts):
        with SessionLocal() as db:
            row = (
                db.query(Scan.id)
                .filter(Scan.status == "QUEUED")
                .order_by(Scan.created_at.asc())
                .first()
            )
            if not row:
                return None
            scan_id = row[0]
        if try_claim_scan(scan_id):
            log.info("claimed scan %s", scan_id)
            return scan_id
        log.debug("lost claim race for scan %s; trying next queued scan", scan_id)
    return None


def poll_and_run_forever(poll_interval: float = 2.0):
    """Blocking loop used by the standalone scanner worker container."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    log.info("scanner worker started, polling every %.1fs", poll_interval)
    while True:
        try:
            scan_id = claim_next_queued_scan()
            if scan_id:
                asyncio.run(run_scan(scan_id))
            else:
                time.sleep(poll_interval)
        except Exception:
            log.exception("worker loop error")
            time.sleep(poll_interval)
