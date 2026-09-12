"""Finding deduplication tests (Phase 1, item 1).

Verifies that the same reflecting endpoint discovered via multiple
DiscoveredURL rows produces exactly one Finding, and that dedup is
scoped per-scan (distinct scans still record independent findings).
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

# Use a dedicated sqlite file so this test never touches other tests' state.
os.environ["DATABASE_URL"] = "sqlite:///./data/xsshunter_dedup_test.db"
os.environ["RUN_EMBEDDED_WORKER"] = "false"
for _p in ("./data/xsshunter_dedup_test.db", "./data/xsshunter_dedup_test.db-journal"):
    try:
        os.remove(_p)
    except FileNotFoundError:
        pass

from db import SessionLocal, init_db  # noqa: E402
from models import Project, Scan, DiscoveredURL, Finding  # noqa: E402
import server as _srv  # noqa: F401,E402  triggers table create + admin bootstrap
import scanner_engine  # noqa: E402


@pytest.fixture(autouse=True)
def _init():
    init_db()


def _install_reflecting_fetch(monkeypatch):
    """Replace scanner_engine._fetch with a stub that echoes every injected
    value inside a plain HTML body (so classify_context returns 'html' as
    long as any query/form value contains the marker)."""

    async def fake_fetch(session, method, url, params=None, data=None, timeout=15,
                        auth_headers=None, auth_cookies=None, allowed_domains=None,
                        limiter=None):
        parts = []
        if params:
            parts.extend(str(v) for v in params.values())
        if data:
            parts.extend(str(v) for v in data.values())
        body = f"<html><body>Hello {' '.join(parts)} world</body></html>"
        return 200, body, url, False

    monkeypatch.setattr(scanner_engine, "_fetch", fake_fetch)


def test_same_reflecting_endpoint_via_multiple_paths_produces_one_finding(monkeypatch):
    """Three DiscoveredURL rows for the same URL/param must produce exactly
    one Finding for (scan_id, url, method, param, context)."""
    _install_reflecting_fetch(monkeypatch)

    with SessionLocal() as db:
        proj = Project(name="dedup-multi-path", allowed_domains=["localhost"], excluded_paths=[])
        db.add(proj); db.commit(); db.refresh(proj)
        scan = Scan(
            project_id=proj.id, target_url="http://localhost/",
            status="RUNNING", config={"max_urls": 5, "max_depth": 1, "request_timeout": 5},
            stats={"urls_crawled": 0, "params_tested": 0, "candidates": 0},
        )
        db.add(scan); db.commit(); db.refresh(scan)
        # Three DiscoveredURL rows for the same GET endpoint — simulates the
        # same reflecting page being reached via three internal crawl paths.
        for _ in range(3):
            db.add(DiscoveredURL(
                scan_id=scan.id, url="http://localhost/search?q=x",
                method="GET", params=["q"], depth=0,
            ))
        db.commit()
        scan_id = scan.id

    asyncio.run(scanner_engine._test_reflection(
        scan_id, cfg={"request_timeout": 5}, allowed=["localhost"],
        auth_headers={}, auth_cookies={}, login_indicators=[],
    ))

    with SessionLocal() as db:
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(findings) == 1, (
            f"expected exactly 1 finding after dedup, got {len(findings)}: "
            f"{[(f.url, f.param, f.context) for f in findings]}"
        )
        f = findings[0]
        assert f.url == "http://localhost/search?q=x"
        assert f.param == "q"
        assert f.method == "GET"
        assert f.context == "html"
        # classification behavior must be unchanged
        assert f.classification == "potential"
        # `candidates` stat should be incremented exactly once, not three times
        s = db.query(Scan).filter(Scan.id == scan_id).first()
        assert (s.stats or {}).get("candidates", 0) == 1


def test_dedup_does_not_suppress_findings_across_scans(monkeypatch):
    """Two separate scans against the same URL must still each get a finding."""
    _install_reflecting_fetch(monkeypatch)

    with SessionLocal() as db:
        proj = Project(name="dedup-scope-per-scan", allowed_domains=["localhost"], excluded_paths=[])
        db.add(proj); db.commit(); db.refresh(proj)
        scan_ids = []
        for _ in range(2):
            s = Scan(
                project_id=proj.id, target_url="http://localhost/",
                status="RUNNING", config={"max_urls": 5, "max_depth": 1, "request_timeout": 5},
                stats={"urls_crawled": 0, "params_tested": 0, "candidates": 0},
            )
            db.add(s); db.commit(); db.refresh(s)
            db.add(DiscoveredURL(
                scan_id=s.id, url="http://localhost/search?q=x",
                method="GET", params=["q"], depth=0,
            ))
            db.commit()
            scan_ids.append(s.id)

    for sid in scan_ids:
        asyncio.run(scanner_engine._test_reflection(
            sid, cfg={"request_timeout": 5}, allowed=["localhost"],
            auth_headers={}, auth_cookies={}, login_indicators=[],
        ))

    with SessionLocal() as db:
        for sid in scan_ids:
            findings = db.query(Finding).filter(Finding.scan_id == sid).all()
            assert len(findings) == 1, (
                f"scan {sid} got {len(findings)} findings — dedup must be per-scan"
            )


def test_dedup_distinguishes_different_params_on_same_url(monkeypatch):
    """Dedup key includes `param` — reflecting on two different params on the
    same URL must yield two findings, not one."""
    _install_reflecting_fetch(monkeypatch)

    with SessionLocal() as db:
        proj = Project(name="dedup-per-param", allowed_domains=["localhost"], excluded_paths=[])
        db.add(proj); db.commit(); db.refresh(proj)
        scan = Scan(
            project_id=proj.id, target_url="http://localhost/",
            status="RUNNING", config={"max_urls": 5, "max_depth": 1, "request_timeout": 5},
            stats={"urls_crawled": 0, "params_tested": 0, "candidates": 0},
        )
        db.add(scan); db.commit(); db.refresh(scan)
        # Same URL, two distinct params, each seen twice
        db.add(DiscoveredURL(scan_id=scan.id, url="http://localhost/p?q=x&r=y",
                             method="GET", params=["q", "r"], depth=0))
        db.add(DiscoveredURL(scan_id=scan.id, url="http://localhost/p?q=x&r=y",
                             method="GET", params=["q", "r"], depth=0))
        db.commit()
        scan_id = scan.id

    asyncio.run(scanner_engine._test_reflection(
        scan_id, cfg={"request_timeout": 5}, allowed=["localhost"],
        auth_headers={}, auth_cookies={}, login_indicators=[],
    ))

    with SessionLocal() as db:
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        params_seen = sorted({f.param for f in findings})
        assert params_seen == ["q", "r"], f"expected findings for both params, got {params_seen}"
        assert len(findings) == 2, (
            f"expected 2 findings (one per param) after dedup, got {len(findings)}"
        )
