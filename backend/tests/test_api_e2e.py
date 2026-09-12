"""End-to-end API tests for reflected-xss-hunter."""
import os
import time
import requests
import pytest

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://xss-hunter-local.preview.emergentagent.com").rstrip("/")
API = f"{BASE_URL}/api"

ADMIN_EMAIL = "admin@local.dev"
ADMIN_PASSWORD = "admin123"

# Target for scanner: use internal Flask test target
TARGET_URL = "http://localhost:5000/"


@pytest.fixture(scope="session")
def token():
    r = requests.post(f"{API}/auth/login-json", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=15)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    data = r.json()
    assert "access_token" in data or "token" in data, data
    return data.get("access_token") or data.get("token")


@pytest.fixture(scope="session")
def auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_health():
    r = requests.get(f"{API}/health", timeout=10)
    assert r.status_code == 200
    assert r.json().get("status") == "ok"


def test_auth_me(auth):
    r = requests.get(f"{API}/auth/me", headers=auth, timeout=10)
    assert r.status_code == 200
    data = r.json()
    assert data.get("email") == ADMIN_EMAIL


def test_project_crud(auth):
    name = f"TEST_proj_{int(time.time())}"
    r = requests.post(f"{API}/projects", json={"name": name, "allowed_domains": ["localhost"]}, headers=auth, timeout=10)
    assert r.status_code in (200, 201), r.text
    proj = r.json()
    pid = proj["id"]

    r2 = requests.get(f"{API}/projects", headers=auth, timeout=10)
    assert r2.status_code == 200
    ids = [p["id"] for p in r2.json()]
    assert pid in ids


@pytest.fixture(scope="session")
def project_id(auth):
    name = f"TEST_scanproj_{int(time.time())}"
    r = requests.post(f"{API}/projects", json={"name": name, "allowed_domains": ["localhost"]}, headers=auth, timeout=10)
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]


def test_scan_full_flow(auth, project_id):
    payload = {"project_id": project_id, "target_url": TARGET_URL, "max_urls": 20}
    r = requests.post(f"{API}/scans", json=payload, headers=auth, timeout=15)
    assert r.status_code in (200, 201), r.text
    scan = r.json()
    sid = scan["id"]

    # Poll for completion
    final_status = None
    for _ in range(40):
        time.sleep(1)
        r2 = requests.get(f"{API}/scans/{sid}", headers=auth, timeout=10)
        assert r2.status_code == 200
        st = r2.json().get("status")
        final_status = st
        if st in ("COMPLETED", "FAILED", "STOPPED"):
            break
    assert final_status == "COMPLETED", f"Scan status: {final_status}"

    # Findings
    r3 = requests.get(f"{API}/findings", params={"scan_id": sid}, headers=auth, timeout=10)
    assert r3.status_code == 200
    findings = r3.json()
    assert isinstance(findings, list)
    assert len(findings) >= 4, f"expected >=4 findings, got {len(findings)}"
    contexts = {f.get("context") for f in findings}
    print("Contexts:", contexts, "count:", len(findings))

    # Exports
    for fmt, ct_frag in [("json", "json"), ("csv", "csv"), ("md", "markdown")]:
        rex = requests.get(f"{API}/scans/{sid}/export", params={"format": fmt}, headers=auth, timeout=15)
        assert rex.status_code == 200, f"{fmt}: {rex.status_code} {rex.text[:200]}"
        assert len(rex.content) > 0
        assert ct_frag in rex.headers.get("content-type", "").lower() or fmt in rex.headers.get("content-type", "").lower()


def test_scan_stop_action(auth, project_id):
    payload = {"project_id": project_id, "target_url": TARGET_URL, "max_urls": 20}
    r = requests.post(f"{API}/scans", json=payload, headers=auth, timeout=15)
    assert r.status_code in (200, 201)
    sid = r.json()["id"]
    # Try to stop while running (may already be complete for fast targets)
    time.sleep(0.5)
    rs = requests.post(f"{API}/scans/{sid}/action", params={"action": "stop"}, headers=auth, timeout=10)
    # Accept 200 (worked) or 400 (already finished)
    assert rs.status_code in (200, 400, 409), f"{rs.status_code} {rs.text}"


def test_dashboard_summary(auth):
    r = requests.get(f"{API}/dashboard/summary", headers=auth, timeout=10)
    assert r.status_code == 200
    data = r.json()
    # numeric counts
    assert any(isinstance(v, int) for v in data.values()), data
