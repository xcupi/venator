"""Redaction utilities. Never let raw auth material leak to the UI, logs, or evidence."""
from __future__ import annotations
import re
from typing import Any

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "proxy-authorization",
    "authentication",
}


def mask_value(v: str, keep: int = 2) -> str:
    """Return a masked representation of a secret value.
    Preserves length hint by using 16 stars regardless of input length.
    """
    if v is None:
        return ""
    s = str(v)
    if len(s) <= keep * 2:
        return "*" * 16
    return f"{s[:keep]}{'*' * 12}{s[-keep:]}"


def mask_cookie_header(cookie_str: str) -> str:
    """Mask `k=v; k2=v2` cookie strings preserving names."""
    if not cookie_str:
        return ""
    parts = []
    for chunk in cookie_str.split(";"):
        if "=" in chunk:
            k, _, v = chunk.partition("=")
            parts.append(f"{k.strip()}={mask_value(v.strip())}")
        else:
            parts.append(chunk.strip())
    return "; ".join(parts)


def redact_headers(headers: dict) -> dict:
    """Return a copy of `headers` with sensitive values masked."""
    out = {}
    for k, v in (headers or {}).items():
        if k.lower() in SENSITIVE_HEADER_NAMES:
            if k.lower() == "cookie":
                out[k] = mask_cookie_header(v)
            else:
                out[k] = mask_value(v)
        else:
            out[k] = v
    return out


def public_auth_profile(profile: Any) -> dict:
    """Serialize an AuthProfile SQLAlchemy row for API/UI. Secrets ALWAYS masked."""
    cfg = dict(profile.config or {})
    masked = {}
    ptype = profile.type

    # Common fields (non-sensitive)
    for k in ("check_url", "login_indicators", "authed_indicators", "header_name"):
        if k in cfg:
            masked[k] = cfg[k]

    if ptype == "cookie":
        masked["cookies"] = [
            {"name": c.get("name", ""), "value": mask_value(c.get("value", ""))}
            for c in cfg.get("cookies", [])
        ]
    elif ptype == "header":
        masked["headers"] = [
            {
                "name": h.get("name", ""),
                "value": mask_value(h.get("value", "")) if h.get("sensitive", True) else h.get("value", ""),
                "sensitive": bool(h.get("sensitive", True)),
            }
            for h in cfg.get("headers", [])
        ]
    elif ptype == "bearer":
        if cfg.get("token"):
            masked["token"] = mask_value(cfg["token"])
    elif ptype == "basic":
        if cfg.get("username"):
            masked["username"] = cfg["username"]
        if cfg.get("password"):
            masked["password"] = mask_value(cfg["password"])

    return {
        "id": profile.id,
        "project_id": profile.project_id,
        "name": profile.name,
        "type": profile.type,
        "enabled": profile.enabled,
        "config": masked,
        "created_at": profile.created_at,
    }


_COOKIE_LINE = re.compile(r"(?im)^(cookie|set-cookie):\s*(.+)$")
_AUTH_LINE = re.compile(r"(?im)^(authorization):\s*(.+)$")


def redact_text_evidence(text: str) -> str:
    """Mask sensitive header lines inside multi-line request/response evidence."""
    if not text:
        return ""
    def _cookie(m):
        return f"{m.group(1)}: {mask_cookie_header(m.group(2))}"
    def _auth(m):
        return f"{m.group(1)}: {mask_value(m.group(2))}"
    text = _COOKIE_LINE.sub(_cookie, text)
    text = _AUTH_LINE.sub(_auth, text)
    return text
