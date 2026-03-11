# =============================================================
#  scripts/seed_db.py — Database Seeder
#
#  PURPOSE:
#    Populates a fresh database with default users so the app
#    is usable immediately after docker-compose up.
#
#  WHEN TO RUN:
#    Automatically called by entrypoint.sh on first startup.
#    Safe to run multiple times — checks before inserting.
#
#  USAGE:
#    python3 scripts/seed_db.py
# =============================================================
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dotenv import load_dotenv
load_dotenv()

from app import create_app
from app.extensions import db
from app.models.user import User

app = create_app()

with app.app_context():
    seeds = [
        {"username": "admin",    "email": "admin@phishguard.local",
         "password": "Admin123!", "role": "admin"},
        {"username": "analyst1", "email": "analyst1@phishguard.local",
         "password": "Analyst123!", "role": "analyst"},
        {"username": "sarah",    "email": "sarah@phishguard.local",
         "password": "Sarah1234!", "role": "user"},
    ]

    created = 0
    for s in seeds:
        if not User.query.filter_by(username=s["username"]).first():
            u = User(
                username=s["username"],
                email=s["email"],
                role=s["role"],
                is_active=True,
            )
            u.set_password(s["password"])
            db.session.add(u)
            created += 1
            print(f"  Created user: {s['username']} ({s['role']})")
        else:
            print(f"  Skipped: {s['username']} already exists")

    db.session.commit()
    print(f"\nSeeding complete — {created} user(s) created.")
