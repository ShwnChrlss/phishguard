# Project Overview

PhishGuard is a learning-focused cybersecurity application that combines web engineering, secure coding, and practical phishing detection in one codebase.

At a high level, the system does four jobs:

1. Accept suspicious email content from a user.
2. Analyse that content with a phishing-detection pipeline.
3. Persist the result for history, review, and reporting.
4. Present the result through a browser interface tailored by role.

## What This Project Teaches

This repo is useful because it connects theory to a working system:

- Web backend concepts:
  app factory pattern, blueprints, request lifecycle, error handling
- Database concepts:
  ORM models, foreign keys, transactions, pagination, soft delete
- Security concepts:
  JWT authentication, role-based access control, least privilege, XSS prevention, CORS, secure password reset
- Frontend concepts:
  shared shell architecture, responsive design, stateful UI, theme tokens
- ML concepts:
  supervised learning, feature extraction, model evaluation, graceful degradation when AI is unavailable

## Main User Flows

### 1. Account and login

- A user registers through `POST /api/auth/register`
- The server stores a hashed password, creates a JWT, and returns the session payload
- The browser stores the token and user metadata locally

### 2. Email detection

- The user pastes email text or uploads an `.eml` file
- The backend extracts the text to analyse
- The detector service loads the trained model and predicts phishing risk
- The app optionally enriches the result with VirusTotal URL intelligence
- The result is saved as an `EmailScan`
- If risk is high enough, an `Alert` is created for operations review

### 3. Review and reporting

- Normal users can review their own scan history
- Analysts and admins can review alerts, quarantine, reports, and ML operations
- Admins can manage user accounts and trigger retraining

## Read The Repo In This Order

If you are learning from the code, this reading order works well:

1. `README.md`
2. `backend/app/__init__.py`
3. `backend/app/config.py`
4. `backend/app/routes/auth.py`
5. `backend/app/routes/detect.py`
6. `backend/app/services/detector.py`
7. `backend/app/models/*.py`
8. `frontend/js/core/app-shell.js`
9. `frontend/js/auth.js`
10. `frontend/js/api.js`

## Guiding Design Ideas

- Keep routes thin and services purposeful.
- Keep security checks on the server, even if the client also guards UX.
- Prefer explicit roles and predictable workflows over magic behaviour.
- Keep the UI understandable to both normal users and operational staff.
- Treat the model as one signal in a defence-in-depth system, not the only truth.
