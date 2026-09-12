# Reflected XSS Hunter — PRD

## Problem
Deliver a local-first, portable reflected-XSS scanner. Zero dependence on
Emergent infrastructure. Runs entirely with `docker compose up`.

## Architecture (chosen)
- FastAPI + SQLAlchemy (Postgres in Docker, SQLite fallback for tests/dev)
- React SPA with craco (existing template) + nginx for prod build
- Standalone scanner worker (aiohttp + BeautifulSoup) polling Postgres for QUEUED scans
- Standalone Playwright browser worker for XSS validation
- Intentionally vulnerable Flask test target with 6 reflection variants
- Single-user JWT auth with env-configurable admin bootstrap

## User personas
- Local security researcher / bug bounty hunter running against approved targets

## Core requirements implemented (2026-02)
- CRUD projects with `allowed_domains` + `excluded_paths` scope
- Scan lifecycle (QUEUED / RUNNING / PAUSED / STOPPING / STOPPED / COMPLETED / FAILED)
- Crawler with URL normalization, dedup, depth+URL limits, scope enforcement
- GET + form (POST) parameter discovery
- Reflection detection with context classification (html/attribute/javascript/encoded/none)
- Finding classification (reflection_only / safely_encoded / potential / validated / false_positive)
- Playwright browser validation upgrades findings to `validated`
- Dashboard, scan detail w/ evidence inspector, findings table
- Exports: JSON / CSV / Markdown
- Docker Compose one-command dev environment
- pytest suite (scope, URL processing, param discovery, reflection, classification)

## Backlog / P1
- Auth-aware crawling (login sequence)
- Custom headers and cookies per project
- Rate limit + per-host concurrency knobs surfaced in UI
- Alembic migrations
- Optional Redis + RQ if concurrency needs grow
- Scheduled scans + notifications (Slack / email via Resend)
- Multi-user with roles

## Non-goals
- Public deployment; SaaS billing; anything Emergent-specific in runtime path
