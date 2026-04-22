# 🛡 PhishGuard AI

> **AI-powered phishing detection and security awareness platform**  
> Built with Flask · SQLite · Scikit-learn · VirusTotal API · Mailtrap

---

## Table of Contents

- [Overview](#overview)
- [Learning Guide](#learning-guide)
- [How AI is Used](#how-ai-is-used)
- [Architecture](#architecture)
- [Current Features](#current-features)
- [Roadmap](#roadmap)
- [Improving the AI](#improving-the-ai)
- [Setup & Installation](#setup--installation)
- [API Reference](#api-reference)
- [Contributing](#contributing)

---

## Overview

PhishGuard AI is a full-stack web application that uses machine learning and real-time threat intelligence to detect phishing emails. It is designed for security teams, IT departments, and individuals who want to analyse suspicious emails before acting on them.

The platform combines three layers of analysis:

1. **Machine Learning** — a trained classifier that scores email text against known phishing patterns
2. **VirusTotal Enrichment** — URLs extracted from emails are checked against 70+ security vendor databases in real time
3. **Rule-based Heuristics** — lookalike domain detection, suspicious TLD matching, urgency language patterns, and more

Every scan produces a risk score (0–100%), a phishing/clean label, a human-readable explanation, and optionally triggers a security alert for admin review.

## Learning Guide

This project is intentionally written as a teaching codebase, not just a demo app. Many of the source files now include comments that connect implementation choices to software engineering and cybersecurity theory.

Recommended reading order:

1. `README.md`
2. `docs/00_overview.md`
3. `docs/01_setup.md`
4. `docs/02_architecture.md`
5. `backend/app/__init__.py`
6. `backend/app/config.py`
7. `backend/app/routes/auth.py`
8. `backend/app/routes/detect.py`
9. `backend/app/services/detector.py`
10. `frontend/js/core/app-shell.js`

Companion docs in `docs/`:

- `00_overview.md` — what the project does and what it teaches
- `01_setup.md` — environment setup and common pitfalls
- `02_architecture.md` — layers, tradeoffs, and request flow
- `03_api_reference.md` — main endpoints and contracts
- `03_frontend_ui.md` — where to customize the UI system
- `04_ml_model.md` — model pipeline and ML theory notes
- `05_improvement_guide.md` — safe directions for future improvement

---

## How AI is Used

### The ML Pipeline

PhishGuard's core detection engine is a **supervised machine learning classifier** built with Scikit-learn.

**Training data:** The model is trained on a labelled dataset of phishing and legitimate emails. Each email is converted into a numerical feature vector using TF-IDF (Term Frequency-Inverse Document Frequency) — a technique that weighs words by how distinctive they are across the corpus.

**Model:** A Logistic Regression or Random Forest classifier (configurable) learns the statistical boundary between phishing and legitimate emails. It outputs a probability score — the confidence that an email is phishing.

**Inference flow:**
```
Email text
    │
    ▼
Feature extraction (TF-IDF vectorizer)
    │
    ▼
ML classifier → probability score (0.0 → 1.0)
    │
    ▼
Rule-based heuristics → explanation list
    │
    ▼
VirusTotal URL check → score enrichment
    │
    ▼
Final risk score (0–100) + label + explanation
```

**Prediction safety:** The model uses `predict_safe()` — a wrapper that catches all exceptions and returns a degraded result if the model is unavailable, so scans never crash the application.

### VirusTotal Enrichment

After the ML model scores an email, PhishGuard extracts all URLs from the email body and checks them against the VirusTotal API v3. If any URL is flagged as malicious by 3 or more security vendors, the risk score is boosted significantly.

This matters because:
- A well-written phishing email can fool an ML model trained on text patterns
- But if the email links to a known malicious domain, VirusTotal will catch it
- The combination of ML + VT is significantly stronger than either alone

**Example:** An email with clean, professional text that links to `malware.wicar.org` — ML scores it 20% (clean text), but VT finds 16 engines flag the URL as malicious, boosting the final score to 97% (phishing).

**Caching:** VT results are cached for 24 hours per URL using SHA256 as the cache key. This means 100 users scanning the same URL only triggers 1 API call. URL reputation changes slowly — a malicious URL flagged today will still be flagged tomorrow.

### Security Chat (Rule-based NLP)

The Security Chat assistant uses a multi-layer intent matching engine:

- **Layer 1:** Exact phrase matching with regex
- **Layer 2:** Token overlap scoring (40% threshold) — handles rephrasing and paraphrasing
- **Layer 3:** Smart fallback — scores all 15 topics and suggests the top 2 closest matches

This gives the chatbot human-like flexibility without requiring a large language model, keeping it fast and fully offline.

---

## Architecture

```
phishguard/
├── backend/
│   ├── app/
│   │   ├── __init__.py          # App factory (create_app)
│   │   ├── config.py            # Dev / Test / Production configs
│   │   ├── extensions.py        # SQLAlchemy, Migrate, CORS, Limiter, Mail
│   │   ├── frontend_routes.py   # Serves HTML pages
│   │   ├── models/
│   │   │   ├── user.py          # User model, JWT auth, password reset
│   │   │   ├── email_scan.py    # Scan results
│   │   │   └── alert.py         # Security alerts
│   │   ├── routes/
│   │   │   ├── auth.py          # Login, register, forgot/reset password
│   │   │   ├── detect.py        # Scan + .eml upload + scan history
│   │   │   ├── chat.py          # Security chatbot
│   │   │   └── admin.py         # Admin dashboard, user management
│   │   ├── services/
│   │   │   ├── detector.py      # ML model singleton + predict_safe()
│   │   │   ├── email_parser.py  # MIME .eml parser (headers, body, URLs)
│   │   │   ├── virustotal.py    # VT API v3 + 24hr cache + score enrichment
│   │   │   ├── password_reset.py# Token generation, hashing, validation
│   │   │   ├── mailer.py        # Flask-Mail email sending
│   │   │   └── chatbot.py       # 3-layer intent matching, 15 security topics
│   │   └── utils/
│   │       ├── auth_helpers.py  # JWT create/decode, require_auth decorator
│   │       └── responses.py     # success(), error(), created() helpers
│   └── run.py
├── frontend/
│   ├── pages/                   # HTML pages
│   ├── js/                      # Vanilla JS (api.js, auth.js, utils.js)
│   └── css/                     # CSS variables, base, components, layout
└── pg-git.sh                    # Git workflow automation script
```

**Tech stack:**

| Layer | Technology |
|---|---|
| Backend framework | Flask 3.x |
| Database ORM | SQLAlchemy + Flask-Migrate |
| Authentication | JWT (HS256, 24hr expiry) |
| ML framework | Scikit-learn |
| Threat intelligence | VirusTotal API v3 |
| Email sending | Flask-Mail + Mailtrap |
| Rate limiting | Flask-Limiter (sliding window) |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Frontend | Vanilla HTML/CSS/JS |

Engineering ideas used throughout the codebase:

- App factory pattern for clean environment switching and testability
- Service layer to separate HTTP concerns from domain logic
- ORM models to express persistence as Python objects
- Least privilege for role-based access control
- Defence in depth through ML, heuristics, and threat-intelligence enrichment
- Responsive design tokens so visual changes can be made centrally

---

## Current Features

### v0.1.0 — Security Chatbot
A fully offline security awareness assistant with 15 topics covering phishing basics, 2FA, password hygiene, social engineering, ransomware, VPNs, and more. Uses a 3-layer intent matching engine that handles rephrasing and typos gracefully. Topic chips are dynamically fetched from the backend so adding new topics requires no frontend changes.

### v0.2.0 — .eml File Upload
Users can upload raw `.eml` email files directly exported from their email client. The parser extracts headers (subject, sender, recipients, date), decodes the body (supports quoted-printable and base64 payloads), strips HTML tags, and extracts all URLs. The parsed content is fed through the same ML pipeline as text scans. Drag-and-drop supported.

### v0.3.0 — Rate Limiting
All sensitive endpoints are protected against brute force and denial-of-service attacks using a sliding window algorithm:

| Endpoint | Limit | Reason |
|---|---|---|
| `POST /api/auth/login` | 10 per 15 min per IP | Brute force protection |
| `POST /api/detect` | 100 per hour per IP | DoS / ML model protection |
| `POST /api/detect/upload` | 20 per hour per IP | CPU-intensive file parsing |
| `POST /api/auth/forgot-password` | 5 per hour per IP | Enumeration prevention |

### v0.4.0 — Password Reset
Full secure password reset flow:
- Cryptographically secure tokens via `secrets.token_urlsafe(32)` (256 bits entropy)
- Only the SHA256 hash is stored in the database — raw token lives only in the email
- Reset links expire after 1 hour and are invalidated immediately after use
- User enumeration prevention — identical response whether the email exists or not
- Emails delivered via Mailtrap sandbox (dev) or live SMTP (prod)

### v0.5.0 — URL Reputation Check (VirusTotal)
Every scan extracts URLs from the email body and checks them against VirusTotal's database of 70+ security vendors. Key behaviours:
- Results cached for 24 hours per URL (SHA256 cache key)
- Score enrichment: malicious URL → significant risk score boost
- Graceful degradation: if VT is down or rate-limited, scan continues with ML result only
- Up to 5 URLs checked per scan (free tier protection)

### v0.6.0 — Scan History
A dedicated page showing the user's full scan history:
- Paginated table (15 scans per page)
- Color-coded risk badges: 🔴 critical (80%+) · 🟠 high (60%+) · 🟡 medium (40%+) · 🟢 low
- Filter by phishing/clean label or source (text/eml upload)
- Detail modal: full explanation, confidence, sender, subject, metadata
- Relative timestamps ("5h ago", "2d ago")
- Navigation integrated into the sidebar alongside all other pages

---

## Roadmap

### v1.0.0 — Gmail Integration *(target milestone)*
Connect a Gmail account via OAuth2. PhishGuard will scan incoming emails automatically, flag suspicious ones, and surface them in the dashboard without the user having to paste or upload anything. Suspicious emails will be labelled in Gmail directly.

### v1.1.0 — ML Retraining
An admin interface to review flagged scans and mark them as correct or incorrect (false positives/negatives). Confirmed labels become new training examples. A retraining job will re-fit the model and compare accuracy metrics before promoting the new version to production. This closes the feedback loop — the more the platform is used, the smarter it gets.

### v1.2.0 — Browser Extension
A Chrome/Firefox extension that adds a PhishGuard button to Gmail and Outlook Web. One click sends the current email to the API and displays the risk score inline without leaving the inbox.

### v1.3.0 — Weekly Digest
A scheduled job that emails each user a weekly summary: total scans, phishing caught, top threat senders, false positive rate, and risk trend over time. Delivered every Monday morning.

### v2.0.0 — Multi-tenant / Team Mode
Organisation-level accounts where admins manage a team, see all scans across the organisation, set custom alert thresholds, configure department-level policies, and export reports as CSV or PDF.

---

## Improving the AI

PhishGuard's ML model is only as good as its training data. Here are concrete ways you can improve detection accuracy after cloning this project.

### 1. Expand the training dataset
More labelled examples — especially recent phishing samples — directly improve accuracy. Recommended sources:

- [PhishTank](https://phishtank.org) — community-submitted phishing URLs
- [OpenPhish](https://openphish.com) — real-time phishing intelligence feeds
- [Enron Email Dataset](https://www.cs.cmu.edu/~enron/) — large legitimate email corpus
- Your own organisation's reported phishing emails (strip all PII before using)

### 2. Improve feature engineering
The current model uses TF-IDF on the raw email body. These additional features would significantly improve accuracy:

| Feature category | Examples |
|---|---|
| Header features | Sender domain age, SPF/DKIM pass/fail, reply-to mismatch |
| URL features | Domain entropy, subdomain count, URL length, IP in URL, URL shortener |
| Structural features | HTML-to-text ratio, link count, image count, attachment presence |
| Metadata features | Send hour (off-hours = suspicious), language mismatch, charset |

### 3. Try stronger models
Scikit-learn's Logistic Regression and Random Forest are solid baselines. For higher accuracy:

- **XGBoost / LightGBM** — gradient boosting, consistently outperforms RF on tabular data
- **Fine-tuned DistilBERT** — a pre-trained transformer model fine-tuned on phishing data understands semantic meaning, not just word frequency. Particularly effective against carefully crafted social engineering text
- **Ensemble** — combine multiple model predictions (e.g. average RF + LR + XGBoost probabilities) for a more robust final score

### 4. Upgrade URL intelligence
The current VT integration checks if URLs are known malicious. Additional signals to add:

- **Domain age lookup** — newly registered domains (< 30 days old) are disproportionately used in phishing
- **WHOIS data** — registrar, registration country, privacy shield usage
- **Google Safe Browsing API** — a free second opinion alongside VirusTotal
- **Certificate transparency** — check if the domain has a valid, recently-issued TLS certificate
- **Homograph detection** — URLs that use Unicode lookalike characters (e.g. `pаypal.com` with Cyrillic `а`)

### 5. Active learning loop
The highest-impact improvement: implement the v1.1.0 retraining pipeline. Every time an admin marks a scan as a false positive or false negative, that becomes a labelled training example. After accumulating enough feedback, retrain and deploy the improved model. Track accuracy metrics over versions to measure improvement.

---

## Setup & Installation

### Prerequisites
- Python 3.12+
- Git
- Free [Mailtrap](https://mailtrap.io) account
- Free [VirusTotal](https://virustotal.com) account

### Install

```bash
git clone https://github.com/ShwnChrlss/PhishGuard.git
cd PhishGuard

python3 -m venv .venv
source .venv/bin/activate

pip install -r backend/requirements.txt
```

### Configure

```bash
cp backend/.env.example backend/.env
# Edit backend/.env with your credentials
```

Key variables:

```env
SECRET_KEY=your-secret-key-here
FLASK_ENV=development
MAIL_SERVER=sandbox.smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=your_mailtrap_username
MAIL_PASSWORD=your_mailtrap_password
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

### Run

```bash
python3 backend/run.py
# http://localhost:5000
```

# Default accounts are configured via environment variables. See 'docs/01_setup.md' for set up instructions

---

## API Reference

All endpoints are prefixed with `/api`. Protected endpoints require `Authorization: Bearer <token>`.

### Auth

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/auth/register` | No | Create account |
| POST | `/auth/login` | No | Get JWT token |
| GET | `/auth/me` | Yes | Current user info |
| POST | `/auth/logout` | Yes | Logout |
| POST | `/auth/forgot-password` | No | Request reset link |
| POST | `/auth/reset-password` | No | Set new password with token |

### Detection

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/detect` | Yes | Scan email text |
| POST | `/detect/upload` | Yes | Upload `.eml` file |
| GET | `/scans/history` | Yes | Paginated scan history |

### Chat

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/chat` | Yes | Send message |
| GET | `/chat/topics` | Yes | Get topic chips |

### Admin

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/admin/users` | Admin | List all users |
| GET | `/admin/dashboard` | Admin | Stats and metrics |

---

## Contributing

PhishGuard is a learning project — every file is commented to explain not just *what* the code does but *why* it does it. Contributions, bug reports, and feature suggestions are welcome.

When adding features:

```bash
./pg-git.sh   # Option 5 → start feature branch
              # Option 2 → commit work
              # Option 3 → push
              # Option 6 → merge to dev
              # Option 7 → release
```

Code principles used throughout:
- Every non-trivial function has a docstring explaining **what** and **why**
- Secrets come from `.env` — nothing hardcoded
- External API calls always have a timeout and a graceful failure path
- Database writes use atomic transactions — scan and alert saved together or not at all
- Rate limiting on every public endpoint — assume hostile traffic

---

*PhishGuard AI — a cybersecurity learning project built from first principles.*  
*From ML pipelines to JWT auth to SMTP — every layer explained, nothing magic.*
