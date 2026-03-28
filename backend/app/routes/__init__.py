"""
backend/app/routes/__init__.py

This package groups the HTTP-facing layer of the application.

Software design concept:
- Routes are the "delivery mechanism" layer.
- They should focus on HTTP concerns such as parsing input,
  checking auth, choosing status codes, and formatting output.
- Heavy business logic belongs in services so routes stay thin.

Cybersecurity concept:
- Keeping auth, validation, and response shaping close to the
  route makes it easier to audit the app's attack surface.
"""
