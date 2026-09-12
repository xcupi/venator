# Reflected XSS Hunter — local, portable, Docker-first

A self-contained platform for discovering reflected XSS. Everything — frontend, backend,
scanner worker, browser validation worker, database, and an intentionally vulnerable
test target — runs locally through Docker Compose. **No Emergent services are required.**

## Architecture

```
Frontend (React + nginx)      http://localhost:3000
        │
        ▼
Backend API (FastAPI)         http://localhost:8001/api
        │
        ▼
PostgreSQL   ◄──────── Scanner Worker (aiohttp crawler + reflection engine)
     │
     └──────────────── Browser Worker (Playwright / headless Chromium)

Test target (Flask, intentionally vulnerable)  http://localhost:5001
```

State — including scan progress, queued/running scans, findings and evidence — lives in
Postgres, so long-running scans **survive browser close and container restarts**.

## Quick start

```bash
git clone <your-fork>
cd reflected-xss-hunter          # this repo

cp .env.example .env
docker compose up --build
```

Then open:

- Web UI:     http://localhost:3000
- API docs:   http://localhost:8001/docs
- Test target http://localhost:5001

Login with the bootstrap admin defined in `.env`:

```
admin@local.dev / admin123
```

Change these before use in any shared network.

### Everyday commands

```bash
# tail all logs
docker compose logs -f

# stop everything
docker compose down

# nuke DB volume for a clean slate
docker compose down -v

# rebuild after code change
docker compose up --build
```

## First scan — end-to-end

1. Log in to the web UI.
2. Create a **Project**, e.g.:
   - Name: `local-demo`
   - Allowed domains: `test-target`
3. On **Scans** page, queue a scan against `http://test-target:5000/`.
4. Watch it move through `QUEUED → RUNNING → COMPLETED`.
5. Open the scan to inspect findings. Six reflection endpoints on the test target
   demonstrate HTML / attribute / JavaScript / encoded / non-reflection / POST-form
   contexts.
6. Browser worker upgrades `potential` → `validated` when a payload triggers `alert()`.
7. Export from the scan detail: **JSON / CSV / Markdown**.

## Directory layout

```
reflected-xss-hunter/
├── frontend/          # React SPA (craco / CRA)
├── backend/           # FastAPI + SQLAlchemy
├── scanner/           # Standalone scanner worker entry
├── browser-worker/    # Playwright validation worker entry
├── test-target/       # Deliberately vulnerable Flask app
├── tests/             # pytest suite (no network required)
├── docker-compose.yml
├── .env.example
└── README.md
```

## Configuration

Everything is driven by `.env` (see `.env.example`). Highlights:

| Var                       | Purpose                                             |
|---------------------------|-----------------------------------------------------|
| `DATABASE_URL`            | SQLAlchemy URL (Postgres in compose, SQLite in dev) |
| `SECRET_KEY`              | JWT signing key                                     |
| `ADMIN_EMAIL/ADMIN_PASSWORD` | Bootstrap admin created on first run             |
| `SCANNER_MAX_URLS/DEPTH`  | Crawler bounds                                      |
| `BROWSER_HEADLESS`        | Toggle Playwright headless mode                     |
| `REACT_APP_BACKEND_URL`   | Backend URL baked into the frontend build           |

**Never commit `.env` — only `.env.example`.**

## Data & artifacts

The `./data/` directory (bind-mounted into the backend container) holds scan
artifacts. Findings and scans are also stored in Postgres; export them any time:

```
GET /api/scans/{id}/export?format=json
GET /api/scans/{id}/export?format=csv
GET /api/scans/{id}/export?format=md
```

## Development

You can run backend + tests without Docker:

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.docker.txt
uvicorn server:app --reload
```

Run the test suite:

```bash
cd tests
PYTHONPATH=../backend pytest -q
```

## Security notes

- The included `test-target` is deliberately vulnerable — **never expose it publicly**.
- Scanner respects `allowed_domains` and `excluded_paths` on every request.
- Change the admin password before use.

## Browser Login Capture (authenticated sessions)

For apps behind a real login you don't want to hand-copy cookies for, use the
browser-based capture helper:

1. In the web UI, create (or open) an Auth Profile and click **Capture Login**.
2. Enter the login URL (must be inside the project's `allowed_domains`) and
   optionally a URL substring that signals successful login (e.g. `/dashboard`).
3. Copy the shown command and run it on **your own machine**:

   ```bash
   pip install playwright requests
   playwright install chromium
   python scripts/capture_login.py --api http://localhost:8001 --token <TOKEN>
   ```

4. A real Chromium window opens at the login URL. Complete sign-in there. When
   the URL matches the success hint (or you click the floating **"I'm signed in"**
   button), cookies are extracted and uploaded back to the backend.
5. The backend **drops any cookie not belonging to an in-scope host**, masks
   the remaining values in the UI, and marks the profile ready for scans.

The capture token expires after 10 minutes and only authorizes cookie import
for the specific profile it was minted for.

## CSRF token preservation

Many authenticated apps require a fresh CSRF token on every POST. The scanner
detects hidden CSRF fields on form discovery (matches `csrf_token`, `_csrf`,
`authenticity_token`, `csrfmiddlewaretoken`, `xsrf`, `__RequestVerificationToken`
and common variants). At test time, it:

1. Refetches the form's origin URL inside a dedicated cookie jar so any
   framework session cookie (Flask, Django, Rails) is replayed on the follow-up POST.
2. Extracts the current CSRF value(s) from the refetched HTML.
3. Submits the fuzz payload with the fresh token(s) + all preserved hidden fields.

If a required CSRF token cannot be obtained or refreshed (e.g. the origin
returned without the field), a finding with classification
`csrf_token_required` is recorded instead of blindly firing the request. The
scanner never attempts to bypass CSRF protections.

## Production portability

The application is architecturally identical whether you run it on a laptop, a VPS,
a private cloud, or another container platform — all configuration comes from
environment variables. No Emergent-only services are used at runtime.
