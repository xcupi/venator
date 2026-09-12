#!/usr/bin/env python3
"""Browser Login Capture — helper script (runs on the user's machine).

Usage:
    python scripts/capture_login.py --api http://localhost:8001 --token <TOKEN>

The backend issues <TOKEN> via POST /api/auth-profiles/{id}/capture-token.
This script:
  1. Decodes the token locally to learn the login URL and optional success hint.
  2. Launches a REAL headed Chromium via Playwright.
  3. Opens the login URL. The user completes login manually.
  4. Detects login completion:
       - If --success-url-contains was provided in the token, waits for the URL
         to contain that substring.
       - Otherwise waits for the user to click the [I'm signed in] button
         injected as a floating overlay in the page.
  5. Extracts cookies from the browser context.
  6. POSTs them to /api/auth-profiles/import-session using the capture token.

Requirements (on the user's machine):
    pip install playwright requests
    playwright install chromium
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from typing import Optional


INJECTED_DONE_BUTTON = r"""
() => {
  if (document.getElementById('__xh_done_btn__')) return;
  const btn = document.createElement('button');
  btn.id = '__xh_done_btn__';
  btn.textContent = "✓ I'm signed in — capture session";
  Object.assign(btn.style, {
    position: 'fixed', bottom: '20px', right: '20px', zIndex: 2147483647,
    padding: '12px 16px', background: '#10b981', color: '#0a0a0a',
    fontFamily: 'ui-monospace, monospace', fontSize: '13px', fontWeight: '700',
    border: '1px solid #059669', borderRadius: '8px', cursor: 'pointer',
    boxShadow: '0 6px 24px rgba(16,185,129,0.4)',
  });
  btn.onclick = () => { window.__XH_DONE__ = true; btn.textContent = 'Captured, closing…'; };
  document.body.appendChild(btn);
}
"""


def _decode_token_unverified(token: str) -> dict:
    """Read the token payload WITHOUT verifying signature (we don't have the
    secret on the user's machine — verification happens server-side on import).
    """
    try:
        _, payload, _ = token.split(".")
        # base64url decode with padding
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode()).decode())
    except Exception as e:
        print(f"error: could not decode token: {e}", file=sys.stderr)
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(description="reflected-xss-hunter browser login capture")
    parser.add_argument("--api", required=True, help="Backend base URL, e.g. http://localhost:8001")
    parser.add_argument("--token", required=True, help="Capture token from the backend")
    parser.add_argument("--headless", action="store_true", help="Run browser headless (default: visible)")
    parser.add_argument("--timeout", type=int, default=300, help="Max seconds to wait for login (default: 300)")
    args = parser.parse_args()

    try:
        import requests
        from playwright.sync_api import sync_playwright
    except ImportError as e:
        print("Missing dependency:", e, file=sys.stderr)
        print("Install:  pip install playwright requests && playwright install chromium", file=sys.stderr)
        sys.exit(3)

    claims = _decode_token_unverified(args.token)
    login_url = claims.get("login_url")
    success_hint = (claims.get("success_url_contains") or "").strip()
    if not login_url:
        print("error: token has no login_url", file=sys.stderr)
        sys.exit(2)

    print(f"[capture] opening {login_url}")
    if success_hint:
        print(f"[capture] will auto-detect completion when URL contains: {success_hint!r}")
    else:
        print("[capture] click the green 'I'm signed in' button once you've logged in")

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=args.headless, args=["--no-sandbox"])
        ctx = browser.new_context()
        page = ctx.new_page()
        page.goto(login_url, wait_until="load")
        page.evaluate(INJECTED_DONE_BUTTON)

        # Re-inject on every navigation
        page.on("load", lambda: _safe_inject(page))

        deadline = time.time() + args.timeout
        while time.time() < deadline:
            try:
                if success_hint and success_hint in page.url:
                    print(f"[capture] success URL detected: {page.url}")
                    break
                done = page.evaluate("() => window.__XH_DONE__ === true")
                if done:
                    print(f"[capture] user confirmed. final URL: {page.url}")
                    break
            except Exception:
                pass
            time.sleep(0.5)
        else:
            print("error: capture timed out", file=sys.stderr)
            browser.close()
            sys.exit(4)

        cookies = ctx.cookies()
        final_url = page.url
        ua = page.evaluate("() => navigator.userAgent") or ""
        browser.close()

    payload = {
        "token": args.token,
        "cookies": [{"name": c["name"], "value": c["value"], "domain": c.get("domain", ""), "url": None} for c in cookies],
        "final_url": final_url,
        "user_agent": ua,
    }
    print(f"[capture] uploading {len(cookies)} cookie(s) to {args.api}/api/auth-profiles/import-session")
    r = requests.post(f"{args.api}/api/auth-profiles/import-session", json=payload, timeout=15)
    if r.status_code != 200:
        print(f"[capture] server rejected import: HTTP {r.status_code} {r.text}", file=sys.stderr)
        sys.exit(5)
    data = r.json()
    print(f"[capture] ✓ imported {data['imported']} in-scope cookie(s). dropped: {data['dropped_out_of_scope']}")


def _safe_inject(page):
    try:
        page.evaluate(INJECTED_DONE_BUTTON)
    except Exception:
        pass


if __name__ == "__main__":
    main()
