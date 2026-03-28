"""
backend/app/services/__init__.py

The service layer contains reusable business logic.

Architecture concept:
- A service sits between routes and lower-level helpers.
- This helps enforce separation of concerns:
  route = transport logic
  service = domain logic
  model = persistence logic

That separation makes the code easier to test, refactor, and
reason about when you add features such as retraining, email
integration, or richer threat-intelligence flows.
"""
