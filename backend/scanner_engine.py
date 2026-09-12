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
from datetime import datetime, timezone
from typing import List, Set

import aiohttp

from db import SessionLocal
from models import Scan, Project, DiscoveredURL, Candidate, Finding, AuthProfile
from scanner_core import (
    DEFAULT_MARKER,
    ENCODED_PROBE,
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


async def _fetch(session: aiohttp.ClientSession, method: str, url: str,
                 params=None, data=None, timeout: int = 15,
                 auth_headers=None, auth_cookies=None, allowed_domains=None):
    """Scope-safe HTTP fetch. Never attaches auth to out-of-scope hosts."""
    hdrs = {}
    cookies = None
    if auth_headers or auth_cookies:
        if allowed_domains and should_attach_auth(url, allowed_domains):
            hdrs.update(auth_headers or {})
            if auth_cookies:
                cookies = dict(auth_cookies)
    try:
        async with session.request(
            method, url, params=params, data=data, timeout=timeout,
            allow_redirects=True, headers=hdrs or None, cookies=cookies,
        ) as resp:
            body = await resp.text(errors="ignore")
            return resp.status, body, str(resp.url)
    except Exception as e:
        return 0, "", str(e)


async def _crawl(scan_id: str, allowed: list, excluded: list, target: str, cfg: dict,
                 auth_headers: dict, auth_cookies: dict, login_indicators: list):
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

            status, body, final_url = await _fetch(
                session, "GET", n, timeout=timeout,
                auth_headers=auth_headers, auth_cookies=auth_cookies, allowed_domains=allowed,
            )
            if status == 0:
                continue

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


async def _test_reflection(scan_id: str, cfg: dict, allowed: list,
                           auth_headers: dict, auth_cookies: dict, login_indicators: list):
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
            with SessionLocal() as db:
                s = db.query(Scan).filter(Scan.id == scan_id).first()
                if not s or s.status in ("STOPPING", "STOPPED"):
                    return
                while s and s.status == "PAUSED":
                    await asyncio.sleep(1)
                    db.refresh(s)

            if not params:
                params = ["q"]

            for pname in params:
                inj = f"pre_{marker}_post"
                base_url = url.split("?", 1)[0] if method == "GET" else url
                other = {}
                if method == "GET" and "?" in url:
                    from urllib.parse import parse_qsl
                    for k, v in parse_qsl(url.split("?", 1)[1], keep_blank_values=True):
                        if k != pname:
                            other[k] = v

                # For POST forms with CSRF fields: refetch origin using a jar-backed session so
                # any Flask/framework session cookie (e.g. flask_session) set on the refetch is
                # automatically replayed on the POST. Auth cookies (from the profile) are seeded
                # into the jar and remain scoped to the target host by aiohttp.
                fresh_csrf = {}
                csrf_missing = False
                if method == "POST" and csrf_fields and origin_url:
                    jar = aiohttp.CookieJar(unsafe=True)
                    async with aiohttp.ClientSession(
                        cookie_jar=jar,
                        cookies=auth_cookies or None,
                        headers={"User-Agent": "reflected-xss-hunter/1.0", **(auth_headers or {})},
                    ) as csrf_session:
                        _, origin_body, _ = await _fetch(
                            csrf_session, "GET", origin_url, timeout=timeout,
                            allowed_domains=allowed,
                        )
                        fresh_csrf = extract_csrf_values(origin_body, csrf_fields)
                        if not fresh_csrf or any(not fresh_csrf.get(n) for n in csrf_fields):
                            csrf_missing = True

                        if not csrf_missing:
                            data = {**(hidden_fields or {}), **fresh_csrf, pname: inj}
                            status, body, _ = await _fetch(
                                csrf_session, "POST", url, data=data, timeout=timeout,
                                allowed_domains=allowed,
                            )
                            req_dump = f"POST {url}\n" + "\n".join(f"{k}={v}" for k, v in data.items())
                            # Run the encoded-probe with a re-issued token inside the same jar
                            _, origin_body2, _ = await _fetch(
                                csrf_session, "GET", origin_url, timeout=timeout,
                                allowed_domains=allowed,
                            )
                            fresh_csrf2 = extract_csrf_values(origin_body2, csrf_fields) or fresh_csrf
                    if csrf_missing:
                        with SessionLocal() as db:
                            if not _finding_exists(db, scan_id, url, method, pname, "csrf_required"):
                                db.add(Finding(
                                    scan_id=scan_id, url=url, method=method, param=pname,
                                    context="csrf_required",
                                    classification=classify_finding("csrf_required", validated=False),
                                    severity="low",
                                    payload="",
                                    evidence=f"required CSRF field(s) {csrf_fields} could not be refreshed from {origin_url}",
                                    request_dump=f"POST {url}\n(missing CSRF token: {csrf_fields})",
                                    response_snippet="",
                                ))
                                db.commit()
                        continue
                elif method == "GET":
                    q = {**other, pname: inj}
                    status, body, _ = await _fetch(
                        session, "GET", base_url, params=q, timeout=timeout,
                        auth_headers=auth_headers, auth_cookies=auth_cookies, allowed_domains=allowed,
                    )
                    req_dump = f"GET {base_url}?{pname}={inj}"
                else:
                    # POST without CSRF fields
                    data = {**(hidden_fields or {}), pname: inj}
                    status, body, _ = await _fetch(
                        session, "POST", url, data=data, timeout=timeout,
                        auth_headers=auth_headers, auth_cookies=auth_cookies, allowed_domains=allowed,
                    )
                    req_dump = f"POST {url}\n" + "\n".join(f"{k}={v}" for k, v in data.items())

                if status == 0:
                    continue

                if (auth_headers or auth_cookies) and looks_like_auth_loss(status, body, login_indicators):
                    raise AuthLostError(f"Authentication lost while testing {url} (status {status})")

                context = classify_context(body, marker)
                reflected = context != "none"

                if reflected and context in ("html", "attribute"):
                    probe = ENCODED_PROBE
                    if method == "GET":
                        q2 = {**other, pname: probe}
                        _, body2, _ = await _fetch(
                            session, "GET", base_url, params=q2, timeout=timeout,
                            auth_headers=auth_headers, auth_cookies=auth_cookies, allowed_domains=allowed,
                        )
                    elif method == "POST" and not csrf_fields:
                        _, body2, _ = await _fetch(
                            session, "POST", url, data={**(hidden_fields or {}), pname: probe},
                            timeout=timeout,
                            auth_headers=auth_headers, auth_cookies=auth_cookies, allowed_domains=allowed,
                        )
                    else:
                        # CSRF-protected POST: skip encoded probe (needs fresh token in same jar)
                        body2 = None
                    if body2 and probe not in body2 and ("&lt;" in body2 or "&gt;" in body2):
                        context = "encoded"

                with SessionLocal() as db:
                    db.add(Candidate(
                        scan_id=scan_id, url=url, method=method, param=pname,
                        context=context, reflected_raw=reflected, payload_marker=marker,
                    ))
                    s = db.query(Scan).filter(Scan.id == scan_id).first()
                    if s:
                        s.stats = {**(s.stats or {}), "params_tested": (s.stats or {}).get("params_tested", 0) + 1}
                    db.commit()

                    if reflected:
                        if not _finding_exists(db, scan_id, url, method, pname, context):
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
                            s.stats = {**(s.stats or {}), "candidates": (s.stats or {}).get("candidates", 0) + 1}
                            db.commit()


async def _preflight_auth(target: str, allowed: list,
                          auth_headers: dict, auth_cookies: dict,
                          check_url: str, login_indicators: list, timeout: int) -> tuple:
    """Return (valid: bool, status: int, final_url: str, notes: str)."""
    probe_url = check_url or target
    if not in_scope(probe_url, allowed, []):
        return False, 0, probe_url, "check_url is outside project scope"
    async with aiohttp.ClientSession(headers={"User-Agent": "reflected-xss-hunter/1.0"}) as session:
        status, body, final = await _fetch(
            session, "GET", probe_url, timeout=timeout,
            auth_headers=auth_headers, auth_cookies=auth_cookies, allowed_domains=allowed,
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

    try:
        # Session preflight when auth is configured
        if profile:
            valid, status, final, notes = await _preflight_auth(
                target, allowed, auth_headers, auth_cookies,
                check_url, login_indicators, int(cfg.get("request_timeout", 15)),
            )
            with SessionLocal() as db:
                s = db.query(Scan).filter(Scan.id == scan_id).first()
                s.stats = {**(s.stats or {}), "auth_status": "VALID" if valid else "INVALID"}
                db.commit()
            if not valid:
                raise AuthLostError(f"Preflight failed ({notes}, status {status}, final {final})")

        await _crawl(scan_id, allowed, excluded, target, cfg,
                     auth_headers, auth_cookies, login_indicators)
        await _test_reflection(scan_id, cfg, allowed,
                               auth_headers, auth_cookies, login_indicators)
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


def poll_and_run_forever(poll_interval: float = 2.0):
    """Blocking loop used by the standalone scanner worker container."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    log.info("scanner worker started, polling every %.1fs", poll_interval)
    while True:
        try:
            with SessionLocal() as db:
                scan = db.query(Scan).filter(Scan.status == "QUEUED").order_by(Scan.created_at.asc()).first()
                scan_id = scan.id if scan else None
                if scan_id:
                    scan.status = "RUNNING"
                    scan.started_at = _now()
                    db.commit()
            if scan_id:
                asyncio.run(run_scan(scan_id))
            else:
                time.sleep(poll_interval)
        except Exception:
            log.exception("worker loop error")
            time.sleep(poll_interval)
