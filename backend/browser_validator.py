"""Browser-based validation using Playwright. Runs in browser-worker container.

Picks up candidate findings from DB where classification == 'potential',
injects context-appropriate payloads and confirms JS execution via dialog handler
or console error signature. Upgrades finding to 'validated' on success.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Optional
from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl

from db import SessionLocal
from models import Finding
from scanner_core import PAYLOADS_BY_CONTEXT

log = logging.getLogger("browser-worker")

BROWSER_TIMEOUT = int(os.environ.get("BROWSER_TIMEOUT", "15000"))
HEADLESS = os.environ.get("BROWSER_HEADLESS", "true").lower() == "true"


def _inject_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


async def _try_validate(page, finding: Finding) -> Optional[str]:
    payloads = PAYLOADS_BY_CONTEXT.get(finding.context, [])
    for payload in payloads:
        fired = {"hit": False, "text": ""}

        async def _on_dialog(dialog):
            fired["hit"] = True
            fired["text"] = dialog.message
            await dialog.dismiss()

        page.on("dialog", _on_dialog)

        if finding.method == "GET":
            url = _inject_param(finding.url, finding.param, payload)
            try:
                await page.goto(url, timeout=BROWSER_TIMEOUT, wait_until="load")
            except Exception:
                continue
        else:
            # POST via form auto-submit
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
        page.remove_listener("dialog", _on_dialog)
        if fired["hit"]:
            return payload
    return None


async def validate_pending():
    from playwright.async_api import async_playwright

    with SessionLocal() as db:
        pending = db.query(Finding).filter(
            Finding.classification == "potential",
            Finding.validated == False,   # noqa: E712
        ).limit(25).all()
        snapshot = [(f.id, f.url, f.method, f.param, f.context) for f in pending]

    if not snapshot:
        return 0

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=HEADLESS, args=["--no-sandbox"])
        ctx = await browser.new_context()
        page = await ctx.new_page()
        validated = 0
        for fid, url, method, param, context in snapshot:
            with SessionLocal() as db:
                f = db.query(Finding).filter(Finding.id == fid).first()
                if not f:
                    continue
            try:
                confirmed_payload = await _try_validate(page, f)
            except Exception:
                log.exception("validation error")
                continue
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
