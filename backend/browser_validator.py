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
from scanner_core import PAYLOADS_BY_CONTEXT, in_scope
from auth_http import build_auth

log = logging.getLogger("browser-worker")

BROWSER_TIMEOUT = int(os.environ.get("BROWSER_TIMEOUT", "15000"))
HEADLESS = os.environ.get("BROWSER_HEADLESS", "true").lower() == "true"


def _inject_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


async def _try_validate(context, finding: Finding) -> Optional[str]:
    payloads = PAYLOADS_BY_CONTEXT.get(finding.context, [])
    for payload in payloads:
        fired = {"hit": False}
        page = await context.new_page()

        async def _on_dialog(dialog):
            fired["hit"] = True
            await dialog.dismiss()

        page.on("dialog", _on_dialog)

        try:
            if finding.method == "GET":
                url = _inject_param(finding.url, finding.param, payload)
                try:
                    await page.goto(url, timeout=BROWSER_TIMEOUT, wait_until="load")
                except Exception:
                    continue
            else:
                form_html = (
                    f"<html><body><form id=f method='POST' action='{finding.url}'>"
                    f"<input name='{finding.param}' value='{payload}'></form>"
                    "<script>document.getElementById('f').submit()</script></body></html>"
                )
                try:
                    await page.set_content(form_html, timeout=BROWSER_TIMEOUT)
                    await page.wait_for_load_state("load", timeout=BROWSER_TIMEOUT)
                except Exception:
                    continue

            await asyncio.sleep(0.4)
            if fired["hit"]:
                return payload
        finally:
            await page.close()
    return None


async def _make_context(pw_browser, profile, allowed_domains):
    """Build a Playwright browser context pre-seeded with the auth profile's material.

    - Cookies go into the storage context, scoped to the target host only.
    - Headers/bearer/basic become extra_http_headers.
    - Scope guard: cookies are attached ONLY when the host is in-scope.
    """
    headers, cookies = build_auth(profile) if profile else ({}, {})
    extra_headers = {k: v for k, v in headers.items()}
    ctx = await pw_browser.new_context(extra_http_headers=extra_headers or None)
    if cookies:
        # Playwright cookie shape needs URL scope; attach one per allowed domain.
        cookie_batch = []
        for domain in allowed_domains or []:
            host = domain.replace("*.", "")
            for name, value in cookies.items():
                cookie_batch.append({
                    "name": name,
                    "value": str(value),
                    "domain": host,
                    "path": "/",
                    "httpOnly": True,
                    "secure": False,
                    "sameSite": "Lax",
                })
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
                ctx = await _make_context(browser, profile, allowed)
                try:
                    with SessionLocal() as db:
                        f = db.query(Finding).filter(Finding.id == fid).first()
                        if not f:
                            continue
                    try:
                        confirmed_payload = await _try_validate(ctx, f)
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
                    await ctx.close()
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
