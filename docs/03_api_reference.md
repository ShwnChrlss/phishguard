# API Reference

All API routes are served under `/api` unless noted otherwise.

## Response Shape

Most endpoints use a consistent envelope:

```json
{
  "status": "success",
  "message": "Optional message",
  "data": {}
}
```

Error responses generally look like:

```json
{
  "status": "error",
  "message": "Human-readable error",
  "code": "optional_machine_code"
}
```

API design concept:

- consistent response envelopes simplify frontend code
- machine-readable status and human-readable messages serve different needs

## Auth

### POST `/api/auth/register`

Creates a normal user account.

Important security rule:
- self-registration always creates role `user`

### POST `/api/auth/login`

Returns:

- JWT token
- user profile payload

### GET `/api/auth/me`

Requires:
- bearer token

Returns:
- current user profile

### POST `/api/auth/logout`

Confirms logout.

Note:
- JWT logout is effectively client-side token removal unless you add token revocation

### POST `/api/auth/forgot-password`

Triggers password reset flow.

Security concept:
- user enumeration prevention uses the same response whether the email exists or not

### POST `/api/auth/reset-password`

Consumes:

- reset token
- new password

## Detection

### POST `/api/detect`

Body:

```json
{
  "email_text": "message body",
  "email_subject": "optional subject",
  "email_sender": "optional sender"
}
```

Returns:

- phishing label
- risk score
- explanation list
- scan id
- whether an alert was created

### POST `/api/detect/upload`

Multipart upload endpoint for `.eml` files.

Concept:
- file uploads use `multipart/form-data`, not JSON

### GET `/api/scans/history`

Returns paginated scan history for the current user.

## Chat

### POST `/api/chat`

Body:

```json
{
  "message": "what is phishing?"
}
```

Returns:
- the chatbot reply

### GET `/api/chat/topics`

Returns:
- prompt suggestions used by the chat UI

## Admin and Operations

### GET `/api/admin/dashboard`

Requires:
- analyst or admin

Returns:
- aggregate stats
- recent scans
- recent alerts

### GET `/api/admin/scans`

Supports filters such as:

- `page`
- `limit`
- `is_phishing`
- `status`
- `user_id`

### GET `/api/admin/alerts`

Supports:
- alert list by status

### POST `/api/admin/alerts/<id>/acknowledge`

Marks an alert as acknowledged.

### POST `/api/admin/alerts/<id>/resolve`

Marks an alert as resolved.

### GET `/api/admin/users`

Admin only.

Returns:
- user listing with roles and status

## Reports

### GET `/api/reports/summary`

Operational summary metrics.

### GET `/api/reports/timeline`

Time-series counts for charts.

### GET `/api/reports/top-senders`

Frequent phishing sender statistics.

### GET `/api/reports/export`

Admin-only data export.

HTTP concept:
- this endpoint uses a download response rather than a normal inline JSON API workflow

## ML Dashboard

### GET `/api/ml/status`

Returns current model metadata and evaluation metrics.

### GET `/api/ml/history`

Returns prior training run history.

### GET `/api/ml/production-stats`

Returns production-oriented scan statistics from the live database.

### POST `/api/ml/retrain`

Admin-only trigger for retraining.

### GET `/api/ml/retrain/stream`

Server-Sent Events stream for training progress.

## Health

### GET `/api/health`

Simple liveness probe.

### GET `/api/health/status`

System status payload used by the status page.
