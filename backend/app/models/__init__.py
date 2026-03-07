# backend/app/models/__init__.py
# Exports all models so they can be imported from one place.
#
# Usage anywhere in the app:
#   from app.models import User, EmailScan, Alert, TrainingRecord
#
# WHY import here?
#   When __init__.py imports the models, SQLAlchemy "sees" them
#   and includes them in db.create_all(). Without this, tables
#   won't be created even if the files exist.

# backend/app/models/__init__.py
from .user            import User
from .email_scan      import EmailScan
from .alert           import Alert
from .training_record import TrainingRecord

__all__ = ["User", "EmailScan", "Alert", "TrainingRecord"]