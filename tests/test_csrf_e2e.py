"""E2E test: verify csrf_token_required finding is created when CSRF cannot be refreshed."""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

os.environ["DATABASE_URL"] = "sqlite:///./data/xsshunter_csrf_test.db"
os.environ["RUN_EMBEDDED_WORKER"] = "false"
for p in ("./data/xsshunter_csrf_test.db", "./data/xsshunter_csrf_test.db-journal"):
    try:
        os.remove(p)
    except FileNotFoundError:
        pass

import asyncio  # noqa: E402
from db import SessionLocal  # noqa: E402
from models import Project, Scan, DiscoveredURL, Finding  # noqa: E402
import server as srv  # noqa: F401,E402  triggers table create + admin
from scanner_engine import run_scan  # noqa: E402


@pytest.fixture(autouse=True)
def _init(monkeypatch):
    from db import init_db
    init_db()


def test_csrf_token_required_when_refresh_impossible():
    """If a POST form declared CSRF fields but the origin URL is unreachable
    (returns empty body / connection refused), we should record
    classification=csrf_token_required rather than blindly submit and fail."""
    with SessionLocal() as db:
        proj = Project(name="csrf-blocked", allowed_domains=["localhost"], excluded_paths=[])
        db.add(proj); db.commit(); db.refresh(proj)
        # Craft the scan and DiscoveredURL manually so we don't need a live server that
        # serves the CSRF form. origin_url points to a black hole -> no CSRF value.
        scan = Scan(project_id=proj.id, target_url="http://localhost:65531/",
                    status="RUNNING", config={"max_urls": 5, "max_depth": 1},
                    stats={"urls_crawled": 0, "params_tested": 0, "candidates": 0})
        db.add(scan); db.commit(); db.refresh(scan)
        # Pre-seed a POST discovered URL with a CSRF field whose refresh will fail
        db.add(DiscoveredURL(
            scan_id=scan.id,
            url="http://localhost:65531/form",
            method="POST",
            params=["comment"],
            depth=0,
            origin_url="http://localhost:65531/form",   # unreachable
            csrf_fields=["csrf_token"],
            hidden_fields={"csrf_token": ""},
        ))
        db.commit()
        scan_id = scan.id

    asyncio.run(run_scan(scan_id))

    with SessionLocal() as db:
        # The scan may go COMPLETED or FAILED, but the CSRF finding must exist
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        csrf_reqs = [f for f in findings if f.classification == "csrf_token_required"]
        assert len(csrf_reqs) == 1, f"expected 1 csrf_token_required, got {[f.classification for f in findings]}"
        f = csrf_reqs[0]
        assert f.context == "csrf_required"
        assert "csrf_token" in f.evidence
        assert f.param == "comment"
