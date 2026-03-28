# Setup Guide

## Environment Setup

Create and use the project virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

Why a virtual environment matters:

- It isolates project dependencies from system Python.
- It makes installs reproducible.
- It prevents the classic "works on my machine" dependency drift problem.

## Configuration

Copy the example environment file and edit values:

```bash
cp backend/.env.example backend/.env
```

Important variables:

- `SECRET_KEY`
  Used to sign JWT tokens and other security-sensitive values.
- `FLASK_ENV`
  Chooses the environment profile.
- `DATABASE_URL`
  Chooses the database backend.
- `MAIL_*`
  Needed for password reset email delivery.
- `VIRUSTOTAL_API_KEY`
  Enables URL reputation enrichment.

## Running The App

```bash
.venv/bin/python backend/run.py
```

Open:

- `http://localhost:5000`
- `http://localhost:5000/api/health`

## Seeding Demo Data

```bash
.venv/bin/python scripts/seed_database.py
```

Software engineering concept:

- Seeding creates a predictable starting state for demos and testing.
- Good demo data improves QA because empty interfaces hide real UX issues.

## Running Tests

```bash
.venv/bin/pytest backend/tests -q
```

Testing concept:

- The tests use a dedicated testing config and isolated database.
- This protects development data and makes failures deterministic.

## Common Setup Pitfalls

### "ModuleNotFoundError"

Cause:
- using system Python instead of the virtual environment

Fix:

```bash
source .venv/bin/activate
```

or run commands with:

```bash
.venv/bin/python ...
```

### App works, but seeded logins do not

Cause:
- app and seed script pointing at different database files

Fix:
- run both through the project environment
- confirm the resolved DB path printed at startup

### Phone cannot open the app on your network

Check:

- app is running on `0.0.0.0`
- phone and laptop are on the same network
- local firewall is not blocking port `5000`

## Production Mindset

Even when running locally, this project models several production habits:

- configuration through environment variables
- explicit test configuration
- role-aware security checks
- graceful degradation around external services
- logs instead of ad hoc prints for runtime observability
