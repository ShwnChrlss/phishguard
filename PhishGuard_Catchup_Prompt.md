# PhishGuard AI — Project Catch-Up Prompt

Use this document to bring any AI assistant or collaborator up to speed on the
PhishGuard AI project. It covers what has been built, the current state, what
is broken, what is next, and the conventions the project follows.

---

## What PhishGuard Is

PhishGuard AI is a full-stack cybersecurity web application that detects
phishing emails using machine learning. It is being built as a production-grade
SaaS product targeting the Kenyan and East African market, with eventual
positioning toward enterprise clients and ICTA Kenya compliance requirements.

The developer is a self-taught beginner-to-intermediate programmer learning
through building. All explanations should follow Bloom's taxonomy — starting
from understanding concepts before implementing them, with real-world context
and enterprise application in mind.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12, Flask, Gunicorn |
| Database | PostgreSQL (local Docker / Supabase in production) |
| Cache / Rate limiting | Redis (local Docker / Upstash in production) |
| ML Engine | scikit-learn Random Forest, TF-IDF vectorizer, joblib |
| Frontend | Vanilla HTML, CSS, JavaScript (no framework) |
| Auth | JWT tokens, bcrypt password hashing |
| Email | Mailtrap (dev) / Resend (production) |
| Containerisation | Docker, docker-compose, nginx reverse proxy |
| Cloud hosting | Railway (backend), Cloudflare Pages (frontend), Supabase (DB), Upstash (Redis) |
| Version control | Git / GitHub (repo: ShwnChrls/phishguard) |

---

## Project File Structure

```
phishguard/
├── backend/
│   ├── app/
│   │   ├── __init__.py          # Flask app factory (create_app)
│   │   ├── extensions.py        # db, migrate, cors, limiter, mail
│   │   ├── models/              # SQLAlchemy models
│   │   │   ├── user.py
│   │   │   ├── email_scan.py
│   │   │   └── alert.py
│   │   ├── routes/
│   │   │   ├── auth.py          # /api/auth/*
│   │   │   ├── detect.py        # /api/detect, /api/scans/history
│   │   │   ├── chat.py          # /api/chat/*
│   │   │   ├── admin.py         # /api/admin/*
│   │   │   ├── reports.py       # /api/reports/*
│   │   │   └── ml_dashboard.py  # /api/ml/*, /api/health/status
│   │   ├── services/
│   │   │   ├── detector.py      # PhishingDetectorService
│   │   │   └── email_parser.py  # .eml file parser
│   │   ├── utils/
│   │   │   ├── auth_helpers.py  # require_auth, get_current_user
│   │   │   └── responses.py     # success(), error(), created()
│   │   └── frontend_routes.py   # serves HTML pages via Flask
│   ├── ml/
│   │   ├── trainer.py           # PhishingModelTrainer class
│   │   ├── feature_extractor.py # 35-feature engineering pipeline
│   │   ├── saved_models/
│   │   │   ├── model.pkl        # trained Random Forest (GITIGNORED)
│   │   │   ├── vectorizer.pkl   # TF-IDF vectorizer (GITIGNORED)
│   │   │   └── metadata.json    # model metrics (COMMITTED)
│   │   ├── datasets/            # training data (GITIGNORED)
│   │   └── training_history/
│   │       └── runs.json        # history of all training runs
│   ├── scripts/
│   │   ├── prepare_and_train.py # full ML pipeline with SSE streaming
│   │   └── seed_db.py           # seeds admin/analyst/user accounts
│   ├── migrations/              # Alembic database migrations
│   ├── requirements.txt
│   └── run.py                   # Flask entry point (exports `app`)
├── frontend/
│   ├── pages/                   # HTML pages
│   │   ├── login.html
│   │   ├── dashboard.html
│   │   ├── analyzer.html        # email detection UI
│   │   ├── chatbot.html         # security chat
│   │   ├── history.html         # scan history
│   │   ├── admin_alerts.html
│   │   ├── admin_users.html
│   │   ├── quarantine.html
│   │   ├── reports.html
│   │   ├── ml_dashboard.html    # ML monitoring + retrain UI
│   │   └── status.html          # public system status page
│   ├── css/
│   │   ├── variables.css        # design tokens (colours, fonts)
│   │   ├── base.css
│   │   ├── components.css
│   │   ├── layout.css           # topbar, sidebar, main grid
│   │   ├── animations.css
│   │   └── pages.css
│   ├── js/
│   │   ├── auth.js              # Auth object, login/logout
│   │   ├── api.js               # API wrapper
│   │   ├── utils.js             # shared utilities
│   │   └── admin.js             # admin page logic
│   └── _redirects               # Cloudflare Pages API proxy rule
├── nginx/
│   └── nginx.conf               # reverse proxy config
├── Dockerfile                   # builds backend + frontend into one image
├── docker-compose.yml           # local stack: app + db + redis + nginx
├── entrypoint.sh                # wait for DB → migrate → seed → gunicorn
├── pg-git.sh                    # git workflow automation script
└── pg-docker.sh                 # Docker Hub push/pull automation script
```

---

## Design System (Frontend)

The app uses a dark cybersecurity aesthetic with these CSS variables:

```css
--bg:          #0a0c0f      /* page background */
--surface:     #111418      /* card/panel background */
--surface2:    #181c22      /* nested surfaces */
--border:      #1e2530      /* borders */
--text:        #c8d6e8      /* primary text */
--text-dim:    #5a6a80      /* secondary text */
--accent:      #00d4ff      /* cyan — primary accent */
--danger:      #ff3b5c      /* red — phishing/errors */
--warn:        #ffaa00      /* amber — warnings */
--safe:        #00e676      /* green — safe/success */
--font-mono:   'Space Mono', monospace
--font-sans:   'Syne', sans-serif
--topbar-h:    56px
--sidebar-w:   200px
```

Every page loads these six CSS files in order:
`variables.css, base.css, components.css, layout.css, animations.css, pages.css`

---

## Authentication System

- JWT tokens stored in `localStorage` as `pg_token`
- User object stored in `localStorage` as `pg_user` (JSON with `.username` and `.role`)
- Three roles: `admin`, `analyst`, `user`
- Seed credentials: `admin/Admin123!`, `analyst1/Analyst123!`, `sarah/Sarah1234!`
- Auth helpers: `require_auth` decorator, `get_current_user()` in `auth_helpers.py`
- Admin pages check `user.role === 'admin'` in JavaScript and redirect if not admin

---

## ML Model — Current State

- Algorithm: Random Forest classifier
- Training dataset: 8,944 emails (4,472 phishing + 4,472 safe, balanced)
  - SpamAssassin spam folder (500 emails)
  - SpamAssassin easy_ham folder (2,551 emails)
  - fraudulent_emails.txt (3,972 419/advance-fee fraud emails)
- Features: 5,035 total (5,000 TF-IDF + 35 hand-engineered)
- Results: 98.4% accuracy, 99.9% precision, 96.9% recall, 98.4% F1, 0.9993 ROC-AUC
- Training time: 7.5 seconds
- Model files: `model.pkl` (4.3MB), `vectorizer.pkl` (6MB) — gitignored
- Metadata: `metadata.json` — committed to git
- Training script: `backend/scripts/prepare_and_train.py --stream` (supports SSE)
- Key class: `PhishingModelTrainer` in `backend/ml/trainer.py`
  - `trainer.train(emails, labels)` → metrics dict
  - `trainer.predict(email_text)` → prediction dict
  - `trainer.save(directory)` → saves pkl files

---

## API Routes Reference

```
POST /api/auth/login              → JWT login
POST /api/auth/register           → create account
POST /api/auth/forgot-password    → send reset email
POST /api/auth/reset-password     → confirm reset

POST /api/detect                  → scan email text
POST /api/detect/upload           → scan .eml file
GET  /api/scans/history           → user's scan history

POST /api/chat                    → AI security chat

GET  /api/admin/users             → list users (admin)
PUT  /api/admin/users/<id>/role   → change role (admin)
DELETE /api/admin/users/<id>      → delete user (admin)
GET  /api/admin/alerts            → list alerts (admin)
PUT  /api/admin/alerts/<id>       → update alert status (admin)

GET  /api/reports/summary         → report data (admin)

GET  /api/ml/status               → current model metadata + metrics
GET  /api/ml/history              → all training run history
GET  /api/ml/production-stats     → scan stats from DB
POST /api/ml/retrain              → trigger retraining (admin)
GET  /api/ml/retrain/stream       → SSE training log stream
GET  /api/health                  → simple health check (public)
GET  /api/health/status           → full system component health (public)
```

---

## Blueprint Registration (CRITICAL)

`ml_dashboard_bp` is registered WITHOUT a url_prefix because its routes
already include `/api/` internally. All other blueprints have prefixes:

```python
app.register_blueprint(ml_dashboard_bp)                      # no prefix
app.register_blueprint(auth_bp,    url_prefix="/api/auth")
app.register_blueprint(detect_bp,  url_prefix="/api")
app.register_blueprint(chat_bp,    url_prefix="/api/chat")
app.register_blueprint(admin_bp,   url_prefix="/api/admin")
app.register_blueprint(reports_bp, url_prefix="/api")
app.register_blueprint(frontend_bp)                          # no prefix
```

---

## Environment Variables Required

```bash
# Core
FLASK_ENV=production              # or development
SECRET_KEY=<64-char hex>          # signs JWT tokens

# Database
DATABASE_URL=postgresql://user:pass@host:5432/dbname?sslmode=require

# Cache
REDIS_URL=rediss://user:pass@host:port

# Email
MAIL_SERVER=smtp.resend.com       # or smtp.mailtrap.io for dev
MAIL_PORT=587
MAIL_USERNAME=resend
MAIL_PASSWORD=<resend-api-key>

# Integrations
VIRUSTOTAL_API_KEY=<key>

# Railway specific
PORT=5000
```

---

## The Four Environments and Their Relationships

**Local Python** (`python3 backend/run.py`)
- Reads `.env` file from project root
- Uses `.venv` Python packages
- Connects to whatever DATABASE_URL says (usually SQLite or local Postgres)
- Fast iteration, no Docker overhead
- Use for: writing code, debugging logic

**Local Docker** (`docker-compose up --build`)
- Builds from `Dockerfile`, copies files at build time
- Has its own PostgreSQL and Redis containers
- Does NOT auto-reload on file changes (requires rebuild)
- Closest to production environment locally
- Use for: testing infrastructure changes, nginx config, entrypoint changes

**GitHub** (git push)
- Source of truth for all code
- Does NOT run anything
- Triggers Railway auto-deploy on push to `main` branch
- `.env`, `*.pkl` model files, datasets are gitignored

**Railway** (production cloud)
- Builds from GitHub repo automatically on push to `main`
- Reads environment variables from Railway dashboard
- Backend URL: `https://phishguard-production-2290.up.railway.app`
- Database: Supabase PostgreSQL
- HTTPS provided automatically via Let's Encrypt

---

## Current State of the Project (as of March 2026)

### What Works
- Full Flask backend with JWT auth, email scanning, ML detection
- PostgreSQL database with migrations and seed data
- ML model trained and working locally (98.4% accuracy)
- Docker containerisation working locally
- Railway deployment live at `phishguard-production-2290.up.railway.app`
- Supabase PostgreSQL connected to Railway — migrations ran, users seeded
- HTTPS working automatically on Railway
- `/api/health` returns 200 on Railway
- ML retraining pipeline with live SSE log streaming

### What Is Broken / Incomplete
1. **Local environment** — project moved from `~/code/phishguard` to
   `~/Desktop/Active_projects/phishguard`. The `.venv` is broken (activates
   but `which python3` still shows system Python). No `.env` file exists.
   App cannot boot locally.

2. **ML routes on Railway** — `/api/ml/status` and `/api/health/status`
   return `{"error":"not_found"}` because `model.pkl` and `vectorizer.pkl`
   are gitignored and not present in the Railway container. `metadata.json`
   was just committed but the pkl files need a storage solution.

3. **Sidebar collapse** — CSS and JS were added to implement a collapsible
   sidebar but nav item text nodes were not wrapped in `<span>` tags in
   two files (`chatbot.html`, `reports.html`), so those pages do not
   collapse properly.

4. **CORS** — `access-control-allow-origin` is hardcoded to
   `https://yourdomain.com` in the Flask config. Needs to be updated to
   allow Railway URL and future Cloudflare Pages URL.

5. **Cloudflare Pages** — not set up yet. Frontend is not deployed to CDN.
   `_redirects` file was created to proxy `/api/*` to Railway.

6. **Upstash Redis** — `REDIS_URL` not set in Railway. Rate limiting
   falls back to in-memory.

7. **Resend email** — mail variables not set in Railway. Password reset
   emails do not send in production.

8. **Model persistence** — no strategy for storing `model.pkl` in production.
   Planned solution: Supabase Storage download on container startup (v0.8.0).

---

## Immediate Priority — Fix Local Environment

Before touching cloud or GitHub, the local environment must be fixed first.
The workflow is always: fix locally → test locally → commit → push → verify
on Railway.

Steps needed:
1. Rebuild the `.venv` properly using the correct Python version
2. Create a `.env` file with development values
3. Verify `python3 backend/run.py` boots cleanly
4. Verify Docker boots cleanly with `docker-compose up --build`
5. Then commit any unstaged changes and push to Railway

Current unstaged changes (not yet committed):
- `backend/app/__init__.py`
- `frontend/css/layout.css`
- All HTML pages in `frontend/pages/`
- `nginx/nginx.conf`
- `scripts/train_model.py`
- New files: `ml_dashboard.py`, `prepare_and_train.py`, `ml_dashboard.html`,
  `status.html`, `pg-docker.sh`

---

## Version Roadmap

```
v0.7.0  ✅ Docker + PostgreSQL + Redis + Nginx + ML dashboard
v0.8.0  🔨 Pre-Production Hardening  ← CURRENT VERSION
            - Fix local environment (IN PROGRESS)
            - Cloudflare Pages frontend deployment
            - Upstash Redis connection
            - Resend email for production
            - CORS configuration fix
            - ML model persistence (Supabase Storage)
            - Sentry error monitoring
            - Structured JSON logging
            - Health check wired to Railway restart policy
v0.9.0  User Self-Registration + Free Tier Enforcement
            - Public signup page
            - Email verification on registration
            - Scan limits per role (free: 10/day, paid: unlimited)
            - Upgrade prompt UI
v0.10.0 Public URL Scanner
            - No-login scanner at /scan (public landing page)
            - Scan a URL for phishing indicators
            - Rate limited by IP
            - Conversion funnel to signup
v0.11.0 Email Header Forensics
            - Parse SPF, DKIM, DMARC headers from .eml files
            - Show pass/fail per authentication check
            - Explain what each check means in plain language
v0.12.0 SMS and WhatsApp Text Analysis
            - Paste SMS text for phishing detection
            - Detect smishing patterns (urgency, fake URLs, prize scams)
            - Adapted ML features for short-form text
v0.13.0 Audit Log and Compliance
            - Every admin action logged with timestamp and user
            - Exportable audit trail (CSV/PDF)
            - Retention policy settings
v0.14.0 MITRE ATT&CK Mapping
            - Tag each detected phishing email with ATT&CK technique IDs
            - Show attack pattern explanations
            - Dashboard showing most common techniques seen
v0.15.0 Threat Intelligence Dashboard + Kenya Phishing Database
            - Aggregate scan data into threat trends
            - Kenya-specific phishing campaign tracking
            - M-Pesa, KRA, Safaricom impersonation detection
            - Public threat feed API
v0.16.0 ML Retraining Pipeline (automated)
            - Scheduled weekly retraining on new confirmed phishing emails
            - Model performance regression detection
            - Automatic rollback if new model performs worse
            - Admin notification on retrain completion
v1.0.0  Browser Extension + Gmail Integration
            - Chrome extension that scans emails in Gmail in real time
            - One-click report to PhishGuard
            - Highlight suspicious links in browser
            - Gmail API integration for batch scanning
```

---

## Key Conventions and Patterns

**Response format** — all API responses use:
```python
from app.utils.responses import success, error, created
return success(data={"key": "value"})   # {"status":"success","data":{...}}
return error("message", 400)             # {"error":"...", "message":"..."}
```

**Auth decorator** — protect routes with:
```python
from app.utils.auth_helpers import require_auth, get_current_user

@bp.route("/endpoint")
@require_auth
def endpoint():
    user = get_current_user()
```

**Frontend API calls** — all pages use:
```javascript
const token = () => localStorage.getItem('pg_token');
const hdrs  = () => ({ 'Authorization': `Bearer ${token()}` });
fetch('/api/endpoint', { headers: hdrs() })
```

**Git commit convention**:
```
feat: add new feature
fix: fix a bug
chore: maintenance, cleanup
docs: documentation
refactor: restructure without behaviour change
```

**Branch strategy**:
- `main` — production, Railway deploys from this
- `dev` — active development
- Always develop on `dev`, merge to `main` when stable

---

## What to Ask the Developer Before Helping

1. Which environment are we working in? (local Python / local Docker / Railway)
2. What is the current error or symptom?
3. Has the app been working at any point recently? When did it break?
4. Are we fixing something existing or building something new?

Always fix local first. Never edit files directly in Docker or on Railway.
Always commit before pushing to Railway. Always test in Docker before committing
infrastructure changes.
