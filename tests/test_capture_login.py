"""End-to-end tests for Browser Login Capture (token issuance + import-session)."""
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

# Isolated DB per test module
os.environ["DATABASE_URL"] = "sqlite:///./data/xsshunter_cap_test.db"
os.environ["RUN_EMBEDDED_WORKER"] = "false"

for p in ("./data/xsshunter_cap_test.db", "./data/xsshunter_cap_test.db-journal"):
    try:
        os.remove(p)
    except FileNotFoundError:
        pass

import server as srv  # noqa: E402


@pytest.fixture
def client():
    with TestClient(srv.app) as c:
        yield c


def _login(client):
    r = client.post("/api/auth/login-json", json={"email": "admin@local.dev", "password": "admin123"})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _make_project(client, headers, name="cap-e2e", allowed=("localhost",)):
    r = client.post("/api/projects", headers=headers,
                    json={"name": name, "allowed_domains": list(allowed)})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _make_profile(client, headers, project_id, name="prof", cfg=None):
    r = client.post("/api/auth-profiles", headers=headers, json={
        "project_id": project_id, "name": name, "type": "cookie",
        "config": cfg or {"cookies": [], "check_url": "http://localhost:5000/dashboard"},
    })
    assert r.status_code == 200, r.text
    return r.json()["id"]


# ---------------- capture-token ----------------
def test_capture_token_rejects_out_of_scope_login_url(client):
    h = _login(client)
    pid = _make_project(client, h)
    prof_id = _make_profile(client, h, pid)
    r = client.post(f"/api/auth-profiles/{prof_id}/capture-token", headers=h,
                    json={"login_url": "http://evil.example.com/login"})
    assert r.status_code == 400
    assert "outside project scope" in r.json()["detail"]


def test_capture_token_returns_helper_command(client):
    h = _login(client)
    pid = _make_project(client, h)
    prof_id = _make_profile(client, h, pid)
    r = client.post(f"/api/auth-profiles/{prof_id}/capture-token", headers=h,
                    json={"login_url": "http://localhost:5000/login",
                          "success_url_contains": "/dashboard"})
    assert r.status_code == 200
    body = r.json()
    assert body["profile_id"] == prof_id
    assert body["login_url"] == "http://localhost:5000/login"
    assert body["token"]
    assert "scripts/capture_login.py" in body["helper_command"]
    assert body["expires_in"] > 0


# ---------------- import-session ----------------
def _capture_token(client, headers, prof_id, login_url="http://localhost:5000/login"):
    r = client.post(f"/api/auth-profiles/{prof_id}/capture-token", headers=headers,
                    json={"login_url": login_url})
    assert r.status_code == 200
    return r.json()["token"]


def test_import_session_stores_in_scope_cookie_masked(client):
    h = _login(client)
    pid = _make_project(client, h)
    prof_id = _make_profile(client, h, pid)
    tok = _capture_token(client, h, prof_id)
    r = client.post("/api/auth-profiles/import-session", json={
        "token": tok,
        "cookies": [{"name": "session", "value": "topsecretsessionvalue", "domain": "localhost"}],
        "final_url": "http://localhost:5000/dashboard",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["imported"] == 1
    assert body["dropped_out_of_scope"] == []
    # returned profile has cookie masked
    cookies = body["profile"]["config"]["cookies"]
    assert cookies[0]["name"] == "session"
    assert "topsecret" not in str(cookies)


def test_import_session_drops_out_of_scope_cookies(client):
    h = _login(client)
    pid = _make_project(client, h, allowed=("localhost",))
    prof_id = _make_profile(client, h, pid)
    tok = _capture_token(client, h, prof_id)
    r = client.post("/api/auth-profiles/import-session", json={
        "token": tok,
        "cookies": [
            {"name": "session", "value": "goodval", "domain": "localhost"},
            {"name": "tracker", "value": "leaked", "domain": "evil.example.com"},
        ],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["imported"] == 1
    assert body["dropped_out_of_scope"] == ["tracker"]


def test_import_session_rejects_unknown_token(client):
    r = client.post("/api/auth-profiles/import-session",
                    json={"token": "not.a.jwt", "cookies": [{"name": "x", "value": "y", "domain": "localhost"}]})
    assert r.status_code == 401


def test_import_session_rejects_user_jwt_wrong_purpose(client):
    h = _login(client)
    user_token = h["Authorization"].split(" ", 1)[1]
    r = client.post("/api/auth-profiles/import-session",
                    json={"token": user_token, "cookies": [{"name": "x", "value": "y", "domain": "localhost"}]})
    assert r.status_code == 401
    assert "purpose" in r.json()["detail"]


def test_import_session_empty_in_scope_rejected(client):
    h = _login(client)
    pid = _make_project(client, h, allowed=("localhost",))
    prof_id = _make_profile(client, h, pid)
    tok = _capture_token(client, h, prof_id)
    r = client.post("/api/auth-profiles/import-session", json={
        "token": tok,
        "cookies": [{"name": "tracker", "value": "x", "domain": "evil.example.com"}],
    })
    assert r.status_code == 400
    assert "No in-scope cookies" in r.json()["detail"]


def test_captured_at_recorded_and_profile_type_normalized(client):
    h = _login(client)
    pid = _make_project(client, h)
    prof_id = _make_profile(client, h, pid, cfg={"cookies": []})
    tok = _capture_token(client, h, prof_id)
    r = client.post("/api/auth-profiles/import-session", json={
        "token": tok,
        "cookies": [{"name": "s", "value": "v", "domain": "localhost"}],
    })
    assert r.status_code == 200
    cfg = r.json()["profile"]["config"]
    assert "captured_at" in cfg
    assert r.json()["profile"]["type"] == "cookie"
