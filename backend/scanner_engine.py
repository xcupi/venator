"""Async scanner engine that consumes a Scan record and populates findings.

Runs standalone in the scanner worker container, and can also be invoked in-process
for the Emergent preview (see server.py background task).
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime, timezone
from typing import Iterable, List, Set

import aiohttp

from db import SessionLocal
from models import Scan, Project, DiscoveredURL, Candidate, Finding
from scanner_core import (
    DEFAULT_MARKER,
    ENCODED_PROBE,
    ParamTarget,
    classify_context,
    classify_finding,
    extract_get_params,
    extract_links_and_forms,
    guess_severity,
    in_scope,
    normalize_url,
)

log = logging.getLogger("scanner")


def _now():
    return datetime.now(timezone.utc)


def _cfg(scan: Scan, key: str, default):
    return (scan.config or {}).get(key, default)


async def _fetch(session: aiohttp.ClientSession, method: str, url: str, params=None, data=None, timeout: int = 15):
    try:
        async with session.request(method, url, params=params, data=data, timeout=timeout, allow_redirects=True) as resp:
            body = await resp.text(errors="ignore")
            return resp.status, body, str(resp.url)
    except Exception as e:
        return 0, "", str(e)


async def _crawl(scan_id: str, allowed: list, excluded: list, target: str, cfg: dict):
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

            status, body, final_url = await _fetch(session, "GET", n, timeout=timeout)
            if status == 0:
                continue

            # Persist URL + any GET params
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
                    if ln not in seen and in_scope(ln, allowed, excluded):
                        queue.append((ln, depth + 1))
                # store forms as POST targets
                with SessionLocal() as db:
                    for f in forms:
                        if in_scope(f.url, allowed, excluded):
                            db.add(DiscoveredURL(
                                scan_id=scan_id, url=normalize_url(f.url),
                                method=f.method, params=f.params, depth=depth + 1,
                            ))
                    db.commit()


async def _test_reflection(scan_id: str, cfg: dict):
    """For each discovered URL/param, inject a marker and detect reflection + context."""
    timeout = int(cfg.get("request_timeout", 15))
    marker = DEFAULT_MARKER

    with SessionLocal() as db:
        urls = db.query(DiscoveredURL).filter(DiscoveredURL.scan_id == scan_id).all()
        url_snapshot = [(u.id, u.url, u.method, u.params) for u in urls]

    async with aiohttp.ClientSession(headers={"User-Agent": "reflected-xss-hunter/1.0"}) as session:
        for uid, url, method, params in url_snapshot:
            with SessionLocal() as db:
                s = db.query(Scan).filter(Scan.id == scan_id).first()
                if not s or s.status in ("STOPPING", "STOPPED"):
                    return
                while s and s.status == "PAUSED":
                    await asyncio.sleep(1)
                    db.refresh(s)

            if not params:
                # test a synthetic 'q' param to spot templates that echo query
                params = ["q"]

            for pname in params:
                inj = f"pre_{marker}_post"
                # Strip existing query so aiohttp doesn't add a duplicate key
                base_url = url.split("?", 1)[0] if method == "GET" else url
                # Preserve other params from original URL
                other = {}
                if method == "GET" and "?" in url:
                    from urllib.parse import parse_qsl
                    for k, v in parse_qsl(url.split("?", 1)[1], keep_blank_values=True):
                        if k != pname:
                            other[k] = v
                if method == "GET":
                    q = {**other, pname: inj}
                    status, body, _ = await _fetch(session, "GET", base_url, params=q, timeout=timeout)
                    req_dump = f"GET {base_url}?{pname}={inj}"
                else:
                    data = {pname: inj}
                    status, body, _ = await _fetch(session, "POST", url, data=data, timeout=timeout)
                    req_dump = f"POST {url}\n{pname}={inj}"

                if status == 0:
                    continue

                context = classify_context(body, marker)
                reflected = context != "none"

                # Second probe with special chars to distinguish encoded vs raw reflection
                if reflected and context in ("html", "attribute"):
                    probe = ENCODED_PROBE
                    if method == "GET":
                        q2 = {**other, pname: probe}
                        _, body2, _ = await _fetch(session, "GET", base_url, params=q2, timeout=timeout)
                    else:
                        _, body2, _ = await _fetch(session, "POST", url, data={pname: probe}, timeout=timeout)
                    if body2 and probe not in body2 and ("&lt;" in body2 or "&gt;" in body2):
                        # special chars encoded => safely encoded
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
                        # produce a candidate finding, unvalidated by browser worker for now
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
        scan.status = "RUNNING"
        scan.started_at = _now()
        scan.stats = {"urls_crawled": 0, "params_tested": 0, "candidates": 0}
        db.commit()
        cfg = dict(scan.config or {})
        target = scan.target_url
        allowed = list(project.allowed_domains or [])
        excluded = list(project.excluded_paths or [])

    try:
        await _crawl(scan_id, allowed, excluded, target, cfg)
        await _test_reflection(scan_id, cfg)
        with SessionLocal() as db:
            s = db.query(Scan).filter(Scan.id == scan_id).first()
            if s.status == "STOPPING":
                s.status = "STOPPED"
            else:
                s.status = "COMPLETED"
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
