# 🛡️ PhishGuard AI

An AI-powered phishing email detection and security awareness platform.

## What it does
- Analyses emails with a trained Random Forest ML model (35 features)
- Gives a risk score 0–100 with plain-English explanations
- Auto-quarantines high-risk emails and raises security alerts
- Security awareness chatbot for employee training
- Full admin dashboard with audit trail and analytics

## Quick Start

```bash
# 1. Clone and enter the project
cd phishguard/backend

# 2. Create virtual environment
python3 -m venv .venv && source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Train the ML model (takes ~30 seconds)
python ../scripts/train_model.py

# 5. Seed demo data (optional but recommended)
python ../scripts/seed_database.py

# 6. Start the server
python run.py
```

Then open `frontend/pages/login.html` in your browser.
Default admin login: **admin / Admin123!**

## Project Structure

```
phishguard/
├── backend/
│   ├── app/
│   │   ├── models/      # Database tables (User, EmailScan, Alert)
│   │   ├── routes/      # API endpoints (auth, detect, admin, chat, reports)
│   │   ├── services/    # Business logic (ML detector, chatbot, notifications)
│   │   └── utils/       # JWT auth, validators, response helpers
│   ├── ml/              # Machine learning pipeline
│   └── tests/           # pytest test suite
├── frontend/
│   ├── pages/           # HTML pages
│   ├── css/             # Stylesheets
│   └── js/              # JavaScript modules
└── scripts/             # train_model, seed_database, evaluate, export
```

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | /api/auth/register | None | Create account |
| POST | /api/auth/login | None | Get JWT token |
| POST | /api/detect | User | Analyse an email |
| GET | /api/scans/history | User | Personal scan history |
| POST | /api/chat | User | Security chatbot |
| GET | /api/admin/dashboard | Admin | Stats overview |
| GET | /api/admin/alerts | Analyst | Security alerts |
| GET | /api/reports/summary | Analyst | Analytics |

## Running Tests

```bash
cd backend
pytest tests/ -v
```

## Docker

```bash
docker-compose up --build
# Backend:  http://localhost:5000
# Frontend: http://localhost:8080
```