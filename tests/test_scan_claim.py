"""Atomic QUEUED -> RUNNING scan-claiming tests (Phase 1, item 3).

Proves:
- Two racing workers: exactly one wins the claim and "proceeds"; the other does not.
- Claiming an already-RUNNING scan fails and never executes it.
- Claiming a non-existent scan id fails cleanly.
- Multiple queued scans are each claimed exactly once by competing workers.
- Both worker loops (standalone + embedded) route through the shared atomic
  claim helper and only call run_scan() after a successful claim.
"""
import asyncio
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

# Dedicated sqlite file so this test never touches other tests' state.
os.environ["DATABASE_URL"] = "sqlite:///./data/xsshunter_claim_test.db"
os.environ["RUN_EMBEDDED_WORKER"] = "false"
for _p in ("./data/xsshunter_claim_test.db", "./data/xsshunter_claim_test.db-journal"):
    try:
        os.remove(_p)
    except FileNotFoundError:
        pass

from db import SessionLocal, init_db  # noqa: E402
from models import Project, Scan  # noqa: E402
import server as srv  # noqa: F401,E402  embedded worker loop lives here
import scanner_engine  # noqa: E402


@pytest.fixture(autouse=True)
def _init():
    init_db()


def _seed_scan(status="QUEUED"):
    with SessionLocal() as db:
        proj = Project(name="claim-test", allowed_domains=["localhost"], excluded_paths=[])
        db.add(proj); db.commit(); db.refresh(proj)
        scan = Scan(
            project_id=proj.id, target_url="http://localhost/", status=status,
            config={}, stats={},
        )
        db.add(scan); db.commit(); db.refresh(scan)
        return scan.id


def _get_scan(scan_id):
    with SessionLocal() as db:
        s = db.query(Scan).filter(Scan.id == scan_id).first()
        return (s.status, s.started_at) if s else (None, None)


# ---------------------------------------------------------------------------
# Test 1 — two workers race for one scan
# ---------------------------------------------------------------------------

def test_two_workers_race_for_one_scan():
    sid = _seed_scan("QUEUED")
    barrier = threading.Barrier(2)
    results = []
    proceeded = []

    def worker():
        barrier.wait()
        won = scanner_engine.try_claim_scan(sid)
        results.append(won)
        if won:
            proceeded.append(sid)  # mirrors the worker loop: only run if claim won

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert sorted(results) == [False, True], f"exactly one worker may win, got {results}"
    assert proceeded == [sid], "exactly one worker may proceed to run_scan"
    status, started_at = _get_scan(sid)
    assert status == "RUNNING"
    assert started_at is not None


# ---------------------------------------------------------------------------
# Test 2 — already-RUNNING scan cannot be claimed
# ---------------------------------------------------------------------------

def test_claim_fails_for_already_running_scan():
    sid = _seed_scan("RUNNING")
    assert scanner_engine.try_claim_scan(sid) is False
    assert scanner_engine.claim_next_queued_scan() is None
    status, started_at = _get_scan(sid)
    assert status == "RUNNING"
    assert started_at is None  # untouched by the failed claim


def test_claim_fails_for_completed_scan():
    sid = _seed_scan("COMPLETED")
    assert scanner_engine.try_claim_scan(sid) is False
    status, _ = _get_scan(sid)
    assert status == "COMPLETED"


# ---------------------------------------------------------------------------
# Test 3 — non-existent scan id fails cleanly
# ---------------------------------------------------------------------------

def test_claim_nonexistent_scan_fails_cleanly():
    assert scanner_engine.try_claim_scan("does-not-exist") is False
    # Empty queue: the loop-facing helper returns None without raising.
    assert scanner_engine.claim_next_queued_scan() is None


# ---------------------------------------------------------------------------
# Test 4 — multiple queued scans, each claimed exactly once
# ---------------------------------------------------------------------------

def test_multiple_queued_scans_each_claimed_exactly_once():
    scan_ids = [_seed_scan("QUEUED") for _ in range(5)]
    claimed = []
    lock = threading.Lock()
    barrier = threading.Barrier(2)

    def worker():
        barrier.wait()
        while True:
            sid = scanner_engine.claim_next_queued_scan()
            if sid is None:
                return
            with lock:
                claimed.append(sid)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert sorted(claimed) == sorted(scan_ids), (
        f"every queued scan must be claimed exactly once; claimed={sorted(claimed)}"
    )
    for sid in scan_ids:
        status, _ = _get_scan(sid)
        assert status == "RUNNING"


def test_claim_picks_oldest_queued_first():
    sid1 = _seed_scan("QUEUED")
    time.sleep(0.01)
    sid2 = _seed_scan("QUEUED")
    # Force distinct created_at ordering regardless of clock resolution
    with SessionLocal() as db:
        from datetime import datetime, timedelta, timezone
        db.query(Scan).filter(Scan.id == sid1).update(
            {"created_at": datetime.now(timezone.utc) - timedelta(minutes=5)}
        )
        db.commit()
    first = scanner_engine.claim_next_queued_scan()
    assert first == sid1, f"oldest QUEUED scan should be claimed first, got {first}"
    second = scanner_engine.claim_next_queued_scan()
    assert second == sid2


# ---------------------------------------------------------------------------
# Test 5 — both worker loops use the shared atomic claim
# ---------------------------------------------------------------------------

class _StopLoop(BaseException):
    """Sentinel that escapes the worker loops' `except Exception` handlers."""


def test_standalone_worker_routes_through_shared_claim_and_executes_winner(monkeypatch):
    calls = {"claim": 0, "run": []}

    def fake_claim():
        calls["claim"] += 1
        if calls["claim"] == 1:
            return "scan-1"
        raise _StopLoop()

    async def fake_run(scan_id):
        calls["run"].append(scan_id)

    monkeypatch.setattr(scanner_engine, "claim_next_queued_scan", fake_claim)
    monkeypatch.setattr(scanner_engine, "run_scan", fake_run)

    with pytest.raises(_StopLoop):
        scanner_engine.poll_and_run_forever(poll_interval=0.01)

    assert calls["claim"] == 2
    assert calls["run"] == ["scan-1"], "run_scan must be called exactly once, for the claimed scan"


def test_standalone_worker_does_not_execute_when_claim_lost(monkeypatch):
    calls = {"claim": 0, "run": []}

    def fake_claim():
        calls["claim"] += 1
        if calls["claim"] == 1:
            return None  # lost the race / nothing to claim
        raise _StopLoop()

    async def fake_run(scan_id):
        calls["run"].append(scan_id)

    monkeypatch.setattr(scanner_engine, "claim_next_queued_scan", fake_claim)
    monkeypatch.setattr(scanner_engine, "run_scan", fake_run)

    with pytest.raises(_StopLoop):
        scanner_engine.poll_and_run_forever(poll_interval=0.01)

    assert calls["run"] == [], "a worker that loses the claim must NOT call run_scan"


def test_embedded_worker_routes_through_shared_claim_and_executes_winner(monkeypatch):
    calls = {"claim": 0, "run": []}

    def fake_claim():
        calls["claim"] += 1
        if calls["claim"] == 1:
            return "scan-1"
        raise _StopLoop()

    async def fake_run(scan_id):
        calls["run"].append(scan_id)

    monkeypatch.setattr(srv, "claim_next_queued_scan", fake_claim)
    monkeypatch.setattr(srv, "run_scan", fake_run)

    with pytest.raises(_StopLoop):
        asyncio.run(srv._embedded_worker_loop())

    assert calls["claim"] == 2
    assert calls["run"] == ["scan-1"], "embedded worker must run_scan exactly once, for the claimed scan"


def test_embedded_worker_does_not_execute_when_claim_lost(monkeypatch):
    calls = {"claim": 0, "run": []}

    def fake_claim():
        calls["claim"] += 1
        if calls["claim"] == 1:
            return None
        raise _StopLoop()

    async def fake_run(scan_id):
        calls["run"].append(scan_id)

    monkeypatch.setattr(srv, "claim_next_queued_scan", fake_claim)
    monkeypatch.setattr(srv, "run_scan", fake_run)

    with pytest.raises(_StopLoop):
        asyncio.run(srv._embedded_worker_loop())

    assert calls["run"] == [], "embedded worker that loses the claim must NOT call run_scan"
