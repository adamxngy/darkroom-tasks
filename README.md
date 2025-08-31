# DarkRoom – Testable Flask App

A sleek, dark-themed Flask app built for UI and API automation practice. Includes:
- User auth (register, login, logout) with CSRF
- Projects and tasks (CRUD) with AJAX endpoints
- JSON API endpoints (`/api/*`)
- Unique, stable `id` attributes across all interactive elements
- Seed script (built-in) to create a default user and demo data

**Default user:** `testuser@example.com` / `Password123!`

## Local setup

```bash
python -m venv .venv && source .venv/bin/activate  # on Windows: .venv\Scripts\activate
pip install -r requirements.txt
export FLASK_APP=app.py
python app.py  # first run seeds the DB
```

Visit http://127.0.0.1:5000

## Environment variables

- `SECRET_KEY` – Flask secret (set in production)
- `DATABASE_URL` – Optional (PostgreSQL URL). When not set, SQLite is used.
- `SEED_EMAIL`, `SEED_PASSWORD`, `SEED_NAME` – Optional seed overrides

## Deploy on Render.com

1. **New > Web Service** → **Build & deploy from a Git repository.**
2. Connect your repo containing this project.
3. **Environment**: `Python 3`
4. **Build Command**: `pip install -r requirements.txt`
5. **Start Command**: `gunicorn app:app`
6. **Environment Variables** (recommended):
   - `SECRET_KEY` = a strong random string
   - (Optional) **PostgreSQL**: create a Render PostgreSQL instance and add its `DATABASE_URL`. If it starts with `postgres://`, the app automatically adapts to `postgresql://`.
7. **SQLite vs PostgreSQL**:
   - SQLite works for demos but will reset on deploys because Render’s root filesystem is ephemeral.
   - Prefer PostgreSQL for persistence.
8. First boot auto-creates tables. To load default data, run once locally or add a one-off job that executes:
   - `python -c "import app; from app import seed, app as flask_app; 
from flask import current_app; 
from app import db; 
import contextlib; 
with flask_app.app_context(): seed()"`

## Test Targets (ideas)
- Auth flow: register, login, logout (form IDs like `login-email`, `btn-login-submit`).
- Dashboard filters: search & status dropdown.
- Project CRUD: create/edit/delete; confirm dialog on delete.
- Task actions: add/toggle/delete via AJAX with JSON responses.
- API health: `/api/health`
- Auth-required APIs returning 401 redirect when not logged in.
