"""Auth-profile aware HTTP helpers used by scanner + test-auth endpoint.

The single source of truth for how an authentication profile is applied to
outbound requests. Scope checks MUST happen before this attaches any auth
material so cookies/tokens never leak to out-of-scope hosts.
"""
from __future__ import annotations
import base64
from typing import Iterable, Tuple
from urllib.parse import urlparse

import aiohttp

from scanner_core import in_scope


AUTH_LOSS_STATUS = {401, 403}


def build_auth(profile) -> Tuple[dict, dict]:
    """Return (headers_dict, cookies_dict) to attach for this profile.

    profile may be None (unauth), or a SQLAlchemy AuthProfile row-like object
    with `.type` and `.config`.
    """
    headers: dict = {}
    cookies: dict = {}
    if profile is None or not getattr(profile, "enabled", True):
        return headers, cookies
    cfg = dict(profile.config or {})
    ptype = profile.type
    if ptype == "cookie":
        for c in cfg.get("cookies", []) or []:
            name = str(c.get("name", "")).strip()
            value = str(c.get("value", ""))
            if name:
                cookies[name] = value
    elif ptype == "header":
        for h in cfg.get("headers", []) or []:
            name = str(h.get("name", "")).strip()
            value = str(h.get("value", ""))
            if name:
                headers[name] = value
    elif ptype == "bearer":
        header_name = str(cfg.get("header_name") or "Authorization").strip() or "Authorization"
        token = str(cfg.get("token", ""))
        if token:
            headers[header_name] = token if token.lower().startswith(("bearer ", "token ")) else f"Bearer {token}"
    elif ptype == "basic":
        u = str(cfg.get("username", ""))
        p = str(cfg.get("password", ""))
        if u:
            encoded = base64.b64encode(f"{u}:{p}".encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"
    return headers, cookies


def should_attach_auth(url: str, allowed_domains: Iterable[str]) -> bool:
    """Scope guard: only attach auth material to URLs inside the allowed scope."""
    return in_scope(url, allowed_domains, [])


def looks_like_auth_loss(status: int, body: str, login_indicators: Iterable[str]) -> bool:
    """Best-effort authentication-loss detection."""
    if status in AUTH_LOSS_STATUS:
        return True
    body = body or ""
    for tag in login_indicators or []:
        if tag and tag.lower() in body.lower():
            return True
    return False


def looks_authenticated(status: int, body: str, authed_indicators: Iterable[str], login_indicators: Iterable[str]) -> bool:
    """Positive heuristic for the Test Authentication endpoint."""
    if status in AUTH_LOSS_STATUS:
        return False
    body = body or ""
    for tag in login_indicators or []:
        if tag and tag.lower() in body.lower():
            return False
    if authed_indicators:
        for tag in authed_indicators:
            if tag and tag.lower() in body.lower():
                return True
        return False
    # Absence of login page and 2xx/3xx status => assume authenticated (best effort)
    return 200 <= status < 400
