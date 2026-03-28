"""
backend/app/utils/__init__.py

Shared helpers that do not belong to a single route or model.

Engineering concept:
- Utility modules reduce duplication, but they should stay
  focused on generic cross-cutting concerns such as auth,
  validation, or response formatting.
- If a helper starts knowing too much about a feature domain,
  that is usually a sign it belongs in a service instead.
"""
