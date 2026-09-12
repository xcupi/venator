"""Redaction & auth-http helpers unit tests."""
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from redact import (  # noqa: E402
    mask_value,
    mask_cookie_header,
    redact_headers,
    redact_text_evidence,
    public_auth_profile,
)
from auth_http import (  # noqa: E402
    build_auth,
    should_attach_auth,
    looks_like_auth_loss,
    looks_authenticated,
)


# ---------- mask_value ----------
def test_mask_short_value():
    assert mask_value("abc") == "*" * 16


def test_mask_long_value_keeps_head_tail():
    v = "supersecretsessioncookie1234"
    m = mask_value(v)
    assert m.startswith("su")
    assert m.endswith("34")
    assert "*" in m
    assert "sessioncookie" not in m


def test_mask_none():
    assert mask_value(None) == ""


# ---------- mask_cookie_header ----------
def test_mask_cookie_header_multi():
    out = mask_cookie_header("session=abcdef123456; csrf=xyz789")
    assert "session=" in out
    assert "abcdef123456" not in out
    assert "csrf=" in out


# ---------- redact_headers ----------
def test_redact_headers_masks_authorization():
    r = redact_headers({"Authorization": "Bearer topsecrettoken", "X-Trace": "abc"})
    assert "topsecrettoken" not in r["Authorization"]
    assert r["X-Trace"] == "abc"


def test_redact_headers_masks_cookie():
    r = redact_headers({"Cookie": "session=abcdef123456"})
    assert "abcdef123456" not in r["Cookie"]
    assert "session=" in r["Cookie"]


# ---------- redact_text_evidence ----------
def test_evidence_redaction_masks_cookie_and_auth_lines():
    txt = (
        "GET /x HTTP/1.1\n"
        "Cookie: session=abcdef123456\n"
        "Authorization: Bearer topsecrettoken\n"
        "X-Trace: keepme\n"
    )
    out = redact_text_evidence(txt)
    assert "abcdef123456" not in out
    assert "topsecrettoken" not in out
    assert "keepme" in out


# ---------- public_auth_profile ----------
def _profile(ptype, config):
    return SimpleNamespace(
        id="p1", project_id="proj", name="n", type=ptype,
        enabled=True, config=config, created_at=None,
    )


def test_public_auth_profile_cookie_masked():
    p = _profile("cookie", {"cookies": [{"name": "session", "value": "topsecret"}]})
    out = public_auth_profile(p)
    assert out["config"]["cookies"][0]["name"] == "session"
    assert "topsecret" not in str(out)


def test_public_auth_profile_bearer_masked():
    p = _profile("bearer", {"token": "topsecrettoken"})
    out = public_auth_profile(p)
    assert "topsecrettoken" not in str(out)


def test_public_auth_profile_header_sensitive_flag():
    p = _profile("header", {"headers": [
        {"name": "X-Api-Key", "value": "SECRET123", "sensitive": True},
        {"name": "X-Tenant", "value": "acme", "sensitive": False},
    ]})
    out = public_auth_profile(p)
    hdrs = {h["name"]: h["value"] for h in out["config"]["headers"]}
    assert "SECRET123" not in hdrs["X-Api-Key"]
    assert hdrs["X-Tenant"] == "acme"


def test_public_auth_profile_basic_password_masked():
    p = _profile("basic", {"username": "alice", "password": "topsecretpw"})
    out = public_auth_profile(p)
    assert out["config"]["username"] == "alice"
    assert "topsecretpw" not in str(out)


# ---------- build_auth ----------
def test_build_auth_cookie():
    p = _profile("cookie", {"cookies": [{"name": "s", "value": "v"}]})
    headers, cookies = build_auth(p)
    assert cookies == {"s": "v"}
    assert headers == {}


def test_build_auth_bearer_adds_prefix():
    p = _profile("bearer", {"token": "topsecrettoken"})
    headers, _ = build_auth(p)
    assert headers["Authorization"].startswith("Bearer topsecret")


def test_build_auth_bearer_preserves_existing_prefix():
    p = _profile("bearer", {"token": "Token abc123", "header_name": "X-Auth"})
    headers, _ = build_auth(p)
    assert headers["X-Auth"] == "Token abc123"


def test_build_auth_basic():
    p = _profile("basic", {"username": "u", "password": "p"})
    headers, _ = build_auth(p)
    assert headers["Authorization"].startswith("Basic ")


def test_build_auth_disabled():
    p = _profile("cookie", {"cookies": [{"name": "s", "value": "v"}]})
    p.enabled = False
    headers, cookies = build_auth(p)
    assert headers == {} and cookies == {}


def test_build_auth_none():
    headers, cookies = build_auth(None)
    assert headers == {} and cookies == {}


# ---------- scope guard ----------
def test_should_attach_auth_in_scope():
    assert should_attach_auth("http://example.com/x", ["example.com"])


def test_should_attach_auth_out_of_scope():
    assert not should_attach_auth("http://evil.com/x", ["example.com"])


# ---------- auth-loss detection ----------
def test_auth_loss_401():
    assert looks_like_auth_loss(401, "", [])


def test_auth_loss_403():
    assert looks_like_auth_loss(403, "", [])


def test_auth_loss_login_indicator():
    assert looks_like_auth_loss(200, "Please Sign in to continue", ["Sign in"])


def test_no_auth_loss_normal_response():
    assert not looks_like_auth_loss(200, "<h1>Dashboard</h1>", ["Sign in"])


def test_looks_authenticated_positive():
    assert looks_authenticated(200, "<h1>Dashboard</h1> Sign out", ["Sign out"], ["Sign in"])


def test_looks_authenticated_negative_on_login_page():
    assert not looks_authenticated(200, "Please Sign in", ["Sign out"], ["Sign in"])
