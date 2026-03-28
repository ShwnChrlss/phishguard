# Improvement Guide

## Purpose

This guide highlights where learners can improve the project while preserving good engineering habits.

## Backend Improvements

### 1. Strengthen validation

Current app:
- validates required fields and basic formats

Good next step:
- centralise schema validation more aggressively
- add stricter input contracts for every route

Theory:
- fail fast
- reject invalid input at trust boundaries

### 2. Expand test coverage

Current tests cover:
- auth
- route wiring
- permission checks

Good next step:
- richer detector tests
- admin workflow tests
- report endpoint tests
- parser edge cases

Theory:
- regression tests protect behaviour during refactors

### 3. Introduce service boundaries more consistently

Some route logic is still fairly feature-heavy.

Good next step:
- move more route-side branching into services where appropriate

Theory:
- lower coupling
- higher cohesion

## Frontend Improvements

### 1. Continue extracting inline styles

The design system is better now, but several pages still contain page-local style blocks.

Good next step:
- migrate repeated patterns into shared CSS modules

Theory:
- duplication in styling becomes maintenance debt just like duplicated logic

### 2. Create reusable page sections

Useful shared UI primitives:

- empty states
- section headers
- filter bars
- data tables
- metric cards

Theory:
- consistent components reduce cognitive load for users and developers

### 3. Improve accessibility

Good next step:

- review contrast in both themes
- add more keyboard interaction support
- improve ARIA labelling where needed

Theory:
- accessibility is part of quality, not an optional add-on

## Security Improvements

### 1. Consider token storage strategy

Current project uses browser storage for simplicity.

Possible future alternative:
- httpOnly secure cookies with CSRF protection

Theory:
- different auth storage models trade off simplicity, XSS exposure, and deployment complexity

### 2. Add audit logging

Valuable events to record:

- failed logins
- role changes
- password resets
- retrain triggers
- quarantine actions

Theory:
- security systems need accountability and traceability

### 3. Add stronger file upload inspection

For `.eml` handling:

- verify MIME type more strictly
- scan attachments metadata if feature expands
- enforce tighter parser limits

Theory:
- file parsing is a classic attack surface

## ML Improvements

### 1. Add drift awareness

Good next step:
- compare current live scans to training distribution

### 2. Improve explainability

Good next step:
- separate model-driven explanations from heuristic explanations more explicitly

### 3. Formalise promotion rules

Good next step:
- define minimum metric thresholds before replacing a model

Theory:
- production ML benefits from release policy just like application code

## Documentation Improvements

Keep docs current when you change:

- routes
- DB schema
- nav structure
- model pipeline
- deployment steps

Theory:
- stale docs are negative value
- good docs lower onboarding cost and reduce accidental misuse
