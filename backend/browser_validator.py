"""Browser-based validation using Playwright.

Auth-aware: each candidate finding is validated in a FRESH, ISOLATED browser context
that contains ONLY the authentication material explicitly configured for the scan's
AuthProfile. No persistent profile, no shared cookies, no extensions.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Optional
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

from db import SessionLocal
from models import Finding, Scan, AuthProfile
from scanner_core import (
    COOKIE_LOCATION,
    HEADER_LOCATION,
    PATH_LOCATION,
    PAYLOADS_BY_CONTEXT,
    decode_injection_location,
    in_scope,
    inject_path_marker,
)
from auth_http import build_auth

log = logging.getLogger("browser-worker")

BROWSER_TIMEOUT = int(os.environ.get("BROWSER_TIMEOUT", "15000"))
HEADLESS = os.environ.get("BROWSER_HEADLESS", "true").lower() == "true"


def _inject_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


async def _drive_page(context, finding: Finding, payload: str, kind: str, name: str) -> bool:
    """Load one payload attempt in a fresh page and report whether an alert
    dialog fired. ``kind``/``name`` come from
    :func:`scanner_core.decode_injection_location` and select how the payload is
    delivered: query/path via navigation, form via auto-submit. Header and
    cookie payloads are delivered by the CONTEXT (see :func:`_try_validate`),
    so here they behave like a plain navigation to the finding URL.
    """
    fired = {"hit": False}
    page = await context.new_page()

    async def _on_dialog(dialog):
        fired["hit"] = True
        await dialog.dismiss()

    page.on("dialog", _on_dialog)
    try:
        if finding.method == "POST" and kind not in (HEADER_LOCATION, COOKIE_LOCATION, PATH_LOCATION):
            form_html = (
                f"<html><body><form id=f method='POST' action='{finding.url}'>"
                f"<input name='{name}' value='{payload}'></form>"
                "<script>document.getElementById('f').submit()</script></body></html>"
            )
            try:
                await page.set_content(form_html, timeout=BROWSER_TIMEOUT)
                await page.wait_for_load_state("load", timeout=BROWSER_TIMEOUT)
            except Exception:
                return False
        else:
            if kind == PATH_LOCATION:
                url = inject_path_marker(finding.url, payload)
            elif kind in (HEADER_LOCATION, COOKIE_LOCATION):
                # Payload rides on the context's header/cookie; just load the URL.
                url = finding.url
            else:  # query
                url = _inject_param(finding.url, name, payload)
            try:
                await page.goto(url, timeout=BROWSER_TIMEOUT, wait_until="load")
            except Exception:
                return False

        await asyncio.sleep(0.4)
        return fired["hit"]
    finally:
        await page.close()


async def _try_validate(pw_browser, profile, allowed_domains, finding: Finding) -> Optional[str]:
    """Attempt to trigger a real alert() for ``finding`` and return the payload
    that fired, or None.

    Query/path payloads reuse ONE context (payload varies by URL only). Header
    and cookie payloads must be baked into the context/cookie jar, so each
    payload gets a fresh context carrying that payload as the injected
    header/cookie value (auth material still layered in via _make_context).
    """
    kind, name = decode_injection_location(finding.param)
    payloads = PAYLOADS_BY_CONTEXT.get(finding.context, [])
    if not payloads:
        return None

    if kind in (HEADER_LOCATION, COOKIE_LOCATION):
        for payload in payloads:
            extra_headers = {name: payload} if kind == HEADER_LOCATION else None
            extra_cookies = {name: payload} if kind == COOKIE_LOCATION else None
            ctx = await _make_context(
                pw_browser, profile, allowed_domains,
                extra_headers=extra_headers, extra_cookies=extra_cookies,
            )
            try:
                if await _drive_page(ctx, finding, payload, kind, name):
                    return payload
            finally:
                await ctx.close()
        return None

    ctx = await _make_context(pw_browser, profile, allowed_domains)
    try:
        for payload in payloads:
            if await _drive_page(ctx, finding, payload, kind, name):
                return payload
    finally:
        await ctx.close()
    return None


def _cookie_entries(cookies: dict, allowed_domains, http_only: bool = True):
    """Build Playwright cookie dicts for ``cookies`` across each allowed host."""
    batch = []
    for domain in allowed_domains or []:
        host = domain.replace("*.", "")
        for name, value in cookies.items():
            batch.append({
                "name": name,
                "value": str(value),
                "domain": host,
                "path": "/",
                "httpOnly": http_only,
                "secure": False,
                "sameSite": "Lax",
            })
    return batch


async def _make_context(pw_browser, profile, allowed_domains,
                        extra_headers=None, extra_cookies=None):
    """Build a Playwright browser context pre-seeded with the auth profile's material.

    - Cookies go into the storage context, scoped to the target host only.
    - Headers/bearer/basic become extra_http_headers.
    - Scope guard: cookies are attached ONLY when the host is in-scope.
    - ``extra_headers`` / ``extra_cookies`` carry a validation PAYLOAD into the
      request header / cookie for header/cookie-location findings. Auth material
      wins any name collision so the authenticated session is never broken.
    """
    headers, cookies = build_auth(profile) if profile else ({}, {})
    merged_headers = {**(extra_headers or {}), **headers}
    ctx = await pw_browser.new_context(extra_http_headers=merged_headers or None)
    cookie_batch = _cookie_entries(cookies, allowed_domains)
    # Payload cookies must NOT be httpOnly (the app must be able to read them the
    # same way a victim's browser would); auth cookies keep httpOnly semantics.
    if extra_cookies:
        payload_cookies = {k: v for k, v in extra_cookies.items() if k not in cookies}
        cookie_batch += _cookie_entries(payload_cookies, allowed_domains, http_only=False)
    if cookie_batch:
        try:
            await ctx.add_cookies(cookie_batch)
        except Exception as e:
            log.warning("failed to seed cookies: %s", e)
    return ctx


async def validate_pending():
    from playwright.async_api import async_playwright

    with SessionLocal() as db:
        pending = db.query(Finding).filter(
            Finding.classification == "potential",
            Finding.validated == False,   # noqa: E712
        ).limit(25).all()
        snapshot = []
        for f in pending:
            scan = db.query(Scan).filter(Scan.id == f.scan_id).first()
            profile_id = scan.auth_profile_id if scan else None
            profile = None
            allowed = []
            if scan:
                if profile_id:
                    profile = db.query(AuthProfile).filter(AuthProfile.id == profile_id).first()
                from models import Project
                proj = db.query(Project).filter(Project.id == scan.project_id).first()
                if proj:
                    allowed = list(proj.allowed_domains or [])
            snapshot.append((f.id, f.url, f.method, f.param, f.context, profile, allowed))

    if not snapshot:
        return 0

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=HEADLESS, args=["--no-sandbox"])
        validated = 0
        try:
            for fid, url, method, param, context, profile, allowed in snapshot:
                # Scope-check the finding URL before spending browser resources or attaching auth
                if allowed and not in_scope(url, allowed, []):
                    continue
                with SessionLocal() as db:
                    f = db.query(Finding).filter(Finding.id == fid).first()
                    if not f:
                        continue
                try:
                    # _try_validate builds (and closes) its own context(s): a
                    # single one for query/path findings, one-per-payload for
                    # header/cookie findings (payload rides on the request).
                    confirmed_payload = await _try_validate(browser, profile, allowed, f)
                except Exception:
                    log.exception("validation error")
                    confirmed_payload = None

                with SessionLocal() as db:
                    f = db.query(Finding).filter(Finding.id == fid).first()
                    if not f:
                        continue
                    if confirmed_payload:
                        f.validated = True
                        f.classification = "validated"
                        f.severity = "high"
                        f.payload = confirmed_payload
                        f.evidence = f"Payload triggered alert() in browser: {confirmed_payload}"
                        validated += 1
                    db.commit()
        finally:
            await browser.close()
        return validated


def poll_forever(interval: float = 3.0):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    log.info("browser-worker started, polling every %.1fs (headless=%s)", interval, HEADLESS)
    while True:
        try:
            n = asyncio.run(validate_pending())
            if n:
                log.info("validated %d finding(s)", n)
        except Exception:
            log.exception("browser worker error")
        time.sleep(interval)
