# Architecture

## Layered View

PhishGuard follows a practical layered architecture:

1. Presentation layer
   Flask-served HTML, CSS, and JavaScript in `frontend/`
2. Route layer
   HTTP endpoints in `backend/app/routes/`
3. Service layer
   Detection, chat, email parsing, notifications, integrations
4. Persistence layer
   SQLAlchemy models in `backend/app/models/`
5. Infrastructure layer
   config, extensions, auth helpers, mail, rate limiting

## Why This Structure Works

### App factory pattern

`backend/app/__init__.py` creates the Flask app on demand.

Why it matters:

- allows different configs for dev, test, and prod
- avoids circular-import issues
- makes test isolation easier

### Blueprints

Routes are grouped by domain:

- `auth.py`
- `detect.py`
- `chat.py`
- `admin.py`
- `reports.py`
- `ml_dashboard.py`

Concept:
- Blueprints are modular route bundles.
- They reduce the "one giant app file" problem.

### Services

Services hold domain behaviour that should not live in route functions.

Examples:

- `detector.py`
  wraps the ML model and its lifecycle
- `email_parser.py`
  extracts useful text from `.eml` files
- `virustotal.py`
  adds external threat intelligence
- `password_reset.py`
  encapsulates secure token logic

Concept:
- This is a service-layer pattern.
- It keeps HTTP logic and business logic separate.

## Data Model

### User

Represents an account and role.

Key ideas:

- password hashes, not raw passwords
- role-based access
- soft deactivation with `is_active`

### EmailScan

Represents one analysis event.

Why it matters:

- gives users history
- gives admins visibility
- provides future training data

### Alert

Represents a follow-up operational signal.

Concept:
- not every scan is an incident
- high-risk scans become alerts with their own workflow

### TrainingRecord

Represents quiz or awareness training progress.

Concept:
- security products often mix prevention, detection, and education

## Security Architecture

### Authentication

- user logs in
- backend returns signed JWT
- browser stores token
- protected routes use decorators to validate it

### Authorisation

Roles:

- `user`
- `analyst`
- `admin`

Concept:
- authentication proves identity
- authorisation enforces permissions

### Defence in depth

PhishGuard does not rely on one mechanism alone.

Examples:

- ML model for text scoring
- heuristics for explanations
- VirusTotal for external confirmation
- server-side auth checks even when the UI hides controls
- input validation both client-side and server-side

## Frontend Architecture

The frontend is intentionally framework-free.

Main ideas:

- shared app shell in `frontend/js/core/app-shell.js`
- reusable helpers in `frontend/js/api.js`, `auth.js`, and `utils.js`
- design tokens in `frontend/css/variables.css`
- role-based navigation and a persistent theme model

Concept:
- this is a small example of component thinking without a framework

## Request Flow Example

### Detect an email

1. user submits content from the analyzer page
2. browser calls `POST /api/detect`
3. route validates payload and auth
4. detector service predicts risk
5. VirusTotal optionally enriches score
6. scan is written to DB
7. alert may be created
8. JSON result returns to frontend
9. UI renders score, explanation, and history state

## Architectural Tradeoffs

This project makes several deliberate tradeoffs:

- Vanilla JS instead of React:
  easier for learners to trace directly, but less abstracted
- SQLite by default:
  simple local setup, but not ideal for larger concurrent production workloads
- Rule-based chatbot:
  predictable and offline, but less flexible than an LLM
- JWT stored in browser storage:
  simple for learning, though some production systems may prefer httpOnly cookies depending on threat model
