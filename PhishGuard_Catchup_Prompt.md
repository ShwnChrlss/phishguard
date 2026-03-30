# PhishGuard AI - Refreshed Project Catch-Up Prompt

Use this document to bring any AI assistant or collaborator up to speed on the
PhishGuard project. It captures three things in one place:

1. What the product was originally meant to be
2. What the repository actually is right now
3. What direction development should continue next

This version is grounded in the current codebase in
`/home/shwn/Desktop/Active_projects/phishguard` as inspected on March 29, 2026.

---

## What PhishGuard Is Trying To Become

PhishGuard AI is a learning-focused cybersecurity web application that detects
phishing emails and helps users understand why something looks suspicious.

The long-term product ambition is still strong:

- A production-grade phishing defense SaaS
- Initially relevant to Kenya and East Africa
- Eventually suitable for team and enterprise use
- A codebase that teaches secure engineering while the product is being built

The developer is learning through building, so explanations should remain
patient, practical, and educational. Start from understanding, then move to
implementation.

---

## How To Help On This Project

When assisting on PhishGuard:

- Prefer the actual code over older docs when they disagree
- Explain changes in plain language before or alongside implementation
- Keep security, maintainability, and learning value visible
- Treat this as a real app, not only a tutorial project
- Build from the current repo state, not from assumptions in older prompts

---

## Verified Current Tech Stack

| Layer | Current Reality |
|---|---|
| Backend | Python, Flask app factory, Gunicorn in container entrypoint |
| ORM / DB | SQLAlchemy + Flask-Migrate |
| Local DB default | SQLite in `backend/instance/phishguard.db` |
| Container / production DB path | PostgreSQL via `DATABASE_URL` |
| Cache / rate limiting | Flask-Limiter, Redis when configured, memory fallback otherwise |
| ML | scikit-learn model pipeline with TF-IDF + engineered features |
| Frontend | Vanilla HTML, CSS, and JavaScript |
| Auth | JWT bearer tokens + bcrypt password hashing |
| Email | Flask-Mail with Mailtrap-style dev defaults, production SMTP via env vars |
| Threat intel | VirusTotal integration when `VIRUSTOTAL_API_KEY` is present |
| Infra | Docker, docker-compose, nginx reverse proxy |
| Testing | Pytest-based backend tests exist in `backend/tests/` |

Important nuance:

- Local Python runs default to SQLite now
- Docker Compose uses PostgreSQL + Redis + nginx
- The frontend is currently served by Flask routes and by nginx in Docker

---

## Project Shape Right Now

```text
phishguard/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── extensions.py
│   │   ├── frontend_routes.py
│   │   ├── models/
│   │   │   ├── user.py
│   │   │   ├── email_scan.py
│   │   │   ├── alert.py
│   │   │   └── training_record.py
│   │   ├── routes/
│   │   │   ├── auth.py
│   │   │   ├── detect.py
│   │   │   ├── chat.py
│   │   │   ├── admin.py
│   │   │   ├── reports.py
│   │   │   └── ml_dashboard.py
│   │   ├── services/
│   │   │   ├── detector.py
│   │   │   ├── email_parser.py
│   │   │   ├── virustotal.py
│   │   │   ├── password_reset.py
│   │   │   ├── mailer.py
│   │   │   ├── chatbot.py
│   │   │   ├── notifications.py
│   │   │   └── email_integration.py
│   │   └── utils/
│   ├── ml/
│   │   ├── trainer.py
│   │   ├── evaluator.py
│   │   ├── features.py
│   │   ├── datasets/
│   │   ├── saved_models/
│   │   │   ├── metadata.json
│   │   │   ├── model.pkl
│   │   │   └── vectorizer.pkl
│   │   └── training_history/
│   │       └── runs.json
│   ├── migrations/
│   ├── scripts/
│   │   ├── seed_db.py
│   │   └── prepare_and_train.py
│   └── tests/
├── frontend/
│   ├── pages/
│   │   ├── login.html
│   │   ├── dashboard.html
│   │   ├── analyzer.html
│   │   ├── chatbot.html
│   │   ├── history.html
│   │   ├── admin_alerts.html
│   │   ├── admin_users.html
│   │   ├── quarantine.html
│   │   ├── reports.html
│   │   ├── ml_dashboard.html
│   │   ├── status.html
│   │   ├── forgot-password.html
│   │   └── reset-password.html
│   ├── css/
│   └── js/
├── nginx/
├── docs/
├── scripts/
├── docker-compose.yml
├── Dockerfile
└── entrypoint.sh
```

---

## Where The App Is Right Now

The current repo is no longer just a simple phishing detector. It is already a
multi-surface application with user auth, scan history, admin operations,
reporting, ML operations, and public system health visibility.

### Working product areas visible in the codebase

- User self-registration and login
- JWT-protected session flow with `/api/auth/me`
- Forgot-password and reset-password flow
- Email text scanning through `/api/detect`
- `.eml` upload parsing and scanning through `/api/detect/upload`
- Scan history for the logged-in user
- Rule-based security chatbot with topic suggestions
- Admin and analyst dashboard views
- Alerts workflow with acknowledge and resolve actions
- User administration with create, patch, deactivate, reactivate, and delete
- Reports endpoints for summary, timeline, top senders, and export
- ML dashboard endpoints for model status, history, production stats, and retraining
- SSE training stream for live retraining logs
- Public system status endpoint at `/api/health/status`

### Frontend pages that currently exist

- `/login`
- `/dashboard`
- `/detect`
- `/chat`
- `/history`
- `/alerts`
- `/quarantine`
- `/users`
- `/reports`
- `/ml-dashboard`
- `/status`
- `/forgot-password`
- `/reset-password`

### Current frontend architecture

- Protected pages share a common shell from `frontend/js/core/app-shell.js`
- Navigation is role-aware
- Theme controls are centralized
- API calls are centralized in `frontend/js/api.js`
- The frontend is framework-free on purpose

---

## Verified Current ML State

The local workspace currently contains all three saved model artifacts:

- `backend/ml/saved_models/metadata.json`
- `backend/ml/saved_models/model.pkl`
- `backend/ml/saved_models/vectorizer.pkl`

Current metadata snapshot:

- Model name: `random_forest`
- Trained at: `2026-03-13T05:52:26.858506`
- Accuracy: `0.9838`
- Precision: `0.9988`
- Recall: `0.9687`
- F1 score: `0.9835`
- ROC-AUC: `0.9993`
- TF-IDF features: `5000`
- Total features: `5035`
- Training samples: `7155 train / 1789 test`
- Training time: `7.17s`

Training history currently shows 2 recorded runs in
`backend/ml/training_history/runs.json`.

The feature set includes URL, urgency, impersonation, HTML, attachment, and
brand-pattern signals in addition to TF-IDF.

---

## Current Route Inventory

### Auth

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/auth/logout`
- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`

### Detection

- `POST /api/detect`
- `POST /api/detect/upload`
- `GET /api/scans/history`

### Chat

- `POST /api/chat`
- `GET /api/chat/topics`

### Admin and analyst operations

- `GET /api/admin/dashboard`
- `GET /api/admin/scans`
- `GET /api/admin/scans/<id>`
- `PATCH /api/admin/scans/<id>`
- `GET /api/admin/alerts`
- `POST /api/admin/alerts/<id>/acknowledge`
- `POST /api/admin/alerts/<id>/resolve`
- `GET /api/admin/users`
- `POST /api/admin/users`
- `GET /api/admin/users/<id>`
- `PATCH /api/admin/users/<id>`
- `POST /api/admin/users/<id>/deactivate`
- `POST /api/admin/users/<id>/reactivate`
- `DELETE /api/admin/users/<id>`

### Reports

- `GET /api/reports/summary`
- `GET /api/reports/timeline`
- `GET /api/reports/top-senders`
- `GET /api/reports/export`

### ML operations

- `GET /api/ml/status`
- `GET /api/ml/history`
- `GET /api/ml/production-stats`
- `POST /api/ml/retrain`
- `GET /api/ml/retrain/stream`

### Health

- `GET /api/health`
- `GET /api/health/status`

---

## Blueprint And Routing Notes

This part is important because it is easy for future collaborators to get
confused here.

- `ml_dashboard_bp` is registered with no `url_prefix`
- Its routes already include `/api/...` in the route definitions
- `auth_bp` uses `url_prefix="/api/auth"`
- `detect_bp` uses `url_prefix="/api"`
- `chat_bp` uses `url_prefix="/api/chat"`
- `admin_bp` uses `url_prefix="/api/admin"`
- `reports_bp` uses `url_prefix="/api"`
- `frontend_bp` serves page routes like `/dashboard`, `/reports`, and `/status`

Both Flask and nginx participate in routing depending on the environment:

- Flask can serve the frontend pages directly via `frontend_routes.py`
- Docker/nginx can also serve the page files directly and proxy API requests

---

## Current Environment Model

### Local Python

- Default DB path resolves to SQLite under `backend/instance/`
- `backend/run.py` now includes fail-fast guidance if the wrong Python or a bad
  virtualenv is used
- This is the simplest path for day-to-day feature work

### Local Docker

- Uses `docker-compose.yml`
- Runs app + PostgreSQL + Redis + nginx
- Expects `backend/.env`
- Is the best local approximation of the full stack

### Production-style behavior from config

- PostgreSQL is used whenever `DATABASE_URL` is set
- Redis-backed limiting is used when `REDIS_URL` is set
- Email and VirusTotal integrations depend on env vars
- CORS is open in base config and restricted via `FRONTEND_URL` in production

---

## Current Tests And Docs

### Tests

The backend has a real pytest structure:

- `backend/tests/conftest.py`
- `backend/tests/test_auth.py`
- `backend/tests/test_routes.py`

Notes:

- The current shell session did not have `pytest` installed, so tests were not
  executed during this refresh
- `backend/tests/test_detector.py` and `backend/tests/test_chatbot.py` are
  currently empty placeholders

### Docs

The repo has useful docs under `docs/`, but some top-level documentation still
lags behind the implementation. Treat this catch-up prompt and the source code
as the highest-trust references.

---

## Important Current Gaps Or Inconsistencies

These are the main "do not get misled" items for future work:

1. Version labels are inconsistent across the project.
   - `/api/health` reports version `1.0.0`
   - `/api/health/status` defaults to `v0.7.0`
   - older roadmap text referenced `v0.8.0`

2. Some docs and comments still point to old paths like `~/code/phishguard`
   even though the current repo path is
   `/home/shwn/Desktop/Active_projects/phishguard`.

3. The old assumption that model artifacts were missing is not true for this
   local workspace. The `.pkl` files are present locally right now.

4. The old Cloudflare Pages and `_redirects` framing does not match the current
   repo layout. There is no frontend `_redirects` file in the repo at present.

5. Production readiness still depends on environment configuration:
   Redis, mail delivery, VirusTotal, and deployment-specific model persistence
   are all env-sensitive.

6. README and older catch-up notes understate how much operational UI and admin
   functionality now exists.

---

## Practical Development Direction From Here

If continuing development now, the next highest-value direction is:

1. Keep building on the existing full-stack app, not restarting architecture
2. Sync versioning and stale docs so the repo tells one coherent story
3. Expand test coverage around detection, chatbot, reports, and admin flows
4. Harden environment setup so local Python, Docker, and production are easier
   to move between
5. Continue product features on top of the existing foundations:
   better analyst workflows, richer reports, improved retraining lifecycle,
   and future integrations

Good immediate product areas to extend safely:

- quarantine workflow depth
- alert triage UX
- report exports and analytics
- training data feedback loops
- team and enterprise controls
- external email integrations

---

## Conventions Worth Preserving

- Keep routes thin and push real behavior into services
- Use the existing response helpers from `app.utils.responses`
- Keep auth and role checks on the server even if the UI hides controls
- Prefer educational comments that explain why, not only what
- Preserve the vanilla frontend architecture unless there is a strong reason to
  introduce a framework
- Treat the ML model as one layer in a defense-in-depth system, not the entire
  truth of the app

---

## Refresh Log: What Changed From The Original Catch-Up Prompt

This is the short "what became stale" summary.

- The repo is currently clean. There are no unstaged local changes.
- The app now has more complete frontend coverage than the original prompt
  described, including history, password reset pages, ML dashboard, and public
  status pages.
- Admin functionality is broader than originally documented:
  create user, patch user, deactivate/reactivate, hard delete, and patch scan
  status are all present.
- Reports are broader than originally documented:
  summary, timeline, top senders, and export all exist.
- The current codebase supports SQLite-by-default for local Python runs and
  PostgreSQL in Docker or production-style environments.
- The local workspace currently includes `model.pkl` and `vectorizer.pkl`; the
  old "missing model files locally" note should not be reused blindly.
- The old Cloudflare Pages `_redirects` note is no longer grounded in the repo.
- The app shell has been centralized in `frontend/js/core/app-shell.js`, so
  older page-by-page navigation assumptions are outdated.
- The biggest source of confusion now is not missing features, but stale docs,
  inconsistent version labels, and environment-specific behavior.

---

## Best Starting Point For Any New AI Collaborator

Read in this order:

1. This file
2. `backend/app/__init__.py`
3. `backend/app/config.py`
4. `backend/app/routes/auth.py`
5. `backend/app/routes/detect.py`
6. `backend/app/routes/admin.py`
7. `backend/app/routes/ml_dashboard.py`
8. `backend/app/services/detector.py`
9. `frontend/js/core/app-shell.js`
10. `frontend/js/api.js`

If docs and code disagree, trust the code.
