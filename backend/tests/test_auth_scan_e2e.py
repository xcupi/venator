"""E2E API tests for AUTHENTICATED SCANNING feature."""
import os
import time
import requests
import pytest

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL").rstrip("/")
API = f"{BASE_URL}/api"

ADMIN_EMAIL = "admin@local.dev"
ADMIN_PASSWORD = "admin123"

VALID_COOKIE = "authed-session-token-abc123"
INVALID_COOKIE = "nope-invalid-cookie"

DASH_URL = "http://localhost:5000/dashboard"
OUT_OF_SCOPE_URL = "http://example.com/dashboard"


@pytest.fixture(scope="module")
def auth():
    r = requests.post(f"{API}/auth/login-json",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=15)
    assert r.status_code == 200, r.text
    t = r.json().get("access_token") or r.json().get("token")
    return {"Authorization": f"Bearer {t}"}


@pytest.fixture(scope="module")
def project_id(auth):
    name = f"TEST_authproj_{int(time.time())}"
    r = requests.post(f"{API}/projects",
                      json={"name": name, "allowed_domains": ["localhost"]},
                      headers=auth, timeout=10)
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]


def _create_profile(auth, project_id, cookie_value, check_url=DASH_URL, name_suffix=""):
    payload = {
        "project_id": project_id,
        "name": f"TEST_profile_{int(time.time()*1000)}{name_suffix}",
        "type": "cookie",
        "config": {
            "cookies": [{"name": "session", "value": cookie_value}],
            "check_url": check_url,
            "login_indicators": ["Sign in", "Login"],
        },
    }
    r = requests.post(f"{API}/auth-profiles", json=payload, headers=auth, timeout=10)
    return r


# 1. Create profile & assert secret is masked in response
def test_create_profile_masks_cookie_value(auth, project_id):
    r = _create_profile(auth, project_id, VALID_COOKIE)
    assert r.status_code in (200, 201), r.text
    body = r.json()
    text = str(body)
    assert VALID_COOKIE not in text, f"Raw cookie leaked in response: {text}"
    # should contain masking chars
    assert "*" in text or "cookie_names" in text or "cookies" in text


# 2. Test VALID cookie
def test_profile_test_valid(auth, project_id):
    r = _create_profile(auth, project_id, VALID_COOKIE, name_suffix="_valid")
    assert r.status_code in (200, 201)
    pid = r.json()["id"]
    rt = requests.post(f"{API}/auth-profiles/{pid}/test", json={}, headers=auth, timeout=15)
    assert rt.status_code == 200, rt.text
    data = rt.json()
    assert data.get("status") == "VALID", data


# 3. Test INVALID cookie -> redirected to /login
def test_profile_test_invalid(auth, project_id):
    r = _create_profile(auth, project_id, INVALID_COOKIE, name_suffix="_inv")
    pid = r.json()["id"]
    rt = requests.post(f"{API}/auth-profiles/{pid}/test", json={}, headers=auth, timeout=15)
    assert rt.status_code == 200, rt.text
    data = rt.json()
    assert data.get("status") == "INVALID", data
    final_url = data.get("final_url", "")
    assert "/login" in final_url, data


# 4. check_url outside scope -> INVALID with note
def test_profile_test_out_of_scope(auth, project_id):
    r = _create_profile(auth, project_id, VALID_COOKIE, check_url=OUT_OF_SCOPE_URL, name_suffix="_oos")
    pid = r.json()["id"]
    rt = requests.post(f"{API}/auth-profiles/{pid}/test", json={}, headers=auth, timeout=15)
    assert rt.status_code == 200, rt.text
    data = rt.json()
    assert data.get("status") == "INVALID"
    notes = (data.get("notes") or "") + " " + (data.get("note") or "")
    assert "scope" in notes.lower(), data


# 5. Authenticated scan reaches /dashboard/search & /dashboard/profile
def _run_scan(auth, project_id, target, auth_profile_id=None, wait=30):
    payload = {"project_id": project_id, "target_url": target, "max_urls": 25}
    if auth_profile_id:
        payload["auth_profile_id"] = auth_profile_id
    r = requests.post(f"{API}/scans", json=payload, headers=auth, timeout=15)
    assert r.status_code in (200, 201), r.text
    sid = r.json()["id"]
    final = None
    for _ in range(wait):
        time.sleep(1)
        rr = requests.get(f"{API}/scans/{sid}", headers=auth, timeout=10)
        assert rr.status_code == 200
        final = rr.json()
        if final.get("status") in ("COMPLETED", "FAILED", "STOPPED", "AUTHENTICATION_REQUIRED"):
            break
    return sid, final


def test_authenticated_scan_reaches_dashboard(auth, project_id):
    r = _create_profile(auth, project_id, VALID_COOKIE, name_suffix="_scan")
    pid = r.json()["id"]
    sid, final = _run_scan(auth, project_id, DASH_URL, auth_profile_id=pid, wait=30)
    assert final.get("status") == "COMPLETED", final
    rf = requests.get(f"{API}/findings", params={"scan_id": sid}, headers=auth, timeout=10)
    assert rf.status_code == 200
    findings = rf.json()
    urls = " ".join(f.get("url", "") for f in findings)
    assert ("/dashboard/search" in urls) or ("/dashboard/profile" in urls), f"No auth-endpoint findings: {urls[:500]}"


# 6. Invalid profile -> AUTHENTICATION_REQUIRED
def test_invalid_profile_scan_marks_auth_required(auth, project_id):
    r = _create_profile(auth, project_id, INVALID_COOKIE, name_suffix="_authreq")
    pid = r.json()["id"]
    sid, final = _run_scan(auth, project_id, DASH_URL, auth_profile_id=pid, wait=20)
    assert final.get("status") == "AUTHENTICATION_REQUIRED", final


# 7. Findings evidence must not leak raw cookie
def test_findings_evidence_redacted(auth, project_id):
    r = _create_profile(auth, project_id, VALID_COOKIE, name_suffix="_redact")
    pid = r.json()["id"]
    sid, final = _run_scan(auth, project_id, DASH_URL, auth_profile_id=pid, wait=30)
    assert final.get("status") == "COMPLETED", final
    rf = requests.get(f"{API}/findings", params={"scan_id": sid}, headers=auth, timeout=10)
    assert rf.status_code == 200
    for fnd in rf.json():
        blob = (fnd.get("request_dump") or "") + " " + (fnd.get("response_snippet") or "") + " " + str(fnd.get("evidence") or "")
        assert VALID_COOKIE not in blob, f"Raw cookie leaked in finding: {fnd.get('id')}"


# 8. /logout not in discovered URLs
def test_logout_not_crawled(auth, project_id):
    r = _create_profile(auth, project_id, VALID_COOKIE, name_suffix="_nologout")
    pid = r.json()["id"]
    sid, final = _run_scan(auth, project_id, DASH_URL, auth_profile_id=pid, wait=30)
    assert final.get("status") == "COMPLETED"
    rr = requests.get(f"{API}/scans/{sid}", headers=auth, timeout=10)
    scan_data = rr.json()
    discovered = str(scan_data)
    # crude: no /logout endpoint should have been crawled
    rf = requests.get(f"{API}/findings", params={"scan_id": sid}, headers=auth, timeout=10)
    for fnd in rf.json():
        assert "/logout" not in (fnd.get("url") or ""), fnd


# 9. scan detail has stats.auth_status
def test_scan_stats_auth_status(auth, project_id):
    r = _create_profile(auth, project_id, VALID_COOKIE, name_suffix="_stats")
    pid = r.json()["id"]
    sid, final = _run_scan(auth, project_id, DASH_URL, auth_profile_id=pid, wait=30)
    stats = final.get("stats") or {}
    assert "auth_status" in stats, final
    assert stats["auth_status"] in ("VALID", "INVALID", "n/a")
