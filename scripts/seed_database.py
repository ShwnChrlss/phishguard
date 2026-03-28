#!/usr/bin/env python3
# =============================================================
#  scripts/seed_database.py
#  Populates the database with realistic demo data
#
#  CONCEPT: Database seeding
#  Seeding = inserting known, realistic test data into the DB.
#  Useful for:
#    - Demoing the app to stakeholders (data to show)
#    - Development (don't start from a blank slate every time)
#    - Testing the frontend with real-looking data
#
#  RUN:  cd backend && python ../scripts/seed_database.py
#  NOTE: Safe to run multiple times — skips existing records.
# =============================================================

import sys
import os

# Add backend/ to path so we can import Flask app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.email_scan import EmailScan
from app.models.alert import Alert

app = create_app()

# ── DEMO USERS ────────────────────────────────────────────────
USERS = [
    {"username": "admin",    "email": "admin@company.com",    "role": "admin",    "password": "Admin123!",    "department": "IT Security"},
    {"username": "analyst1", "email": "analyst@company.com",  "role": "analyst",  "password": "Analyst123!", "department": "IT Security"},
    {"username": "sarah",    "email": "sarah@company.com",    "role": "user",     "password": "Sarah1234!",  "department": "Finance"},
    {"username": "mike",     "email": "mike@company.com",     "role": "user",     "password": "Mike1234!",   "department": "HR"},
    {"username": "priya",    "email": "priya@company.com",    "role": "user",     "password": "Priya1234!",  "department": "Engineering"},
]

# ── DEMO EMAILS ───────────────────────────────────────────────
SCANS = [
    {
        "email_text":    "URGENT: Your PayPal account has been suspended! Click http://192.168.1.1/paypal to verify your password NOW or your account will be permanently closed.",
        "email_subject": "Account Suspended - Immediate Action Required",
        "email_sender":  "security@paypa1.com",
        "is_phishing":   True,
        "risk_score":    91,
        "status":        "quarantined",
        "explanation":   ["🚨 IP address in URL", "🚨 Lookalike domain (paypa1.com)", "⚠️ 3 urgency words", "⚠️ Threat of account closure"],
    },
    {
        "email_text":    "Hi team, please find attached the Q3 board report. The meeting is scheduled for Thursday at 2pm in Conference Room A. Best regards, Jennifer",
        "email_subject": "Q3 Board Report - Thursday Meeting",
        "email_sender":  "jennifer@company.com",
        "is_phishing":   False,
        "risk_score":    4,
        "status":        "safe",
        "explanation":   ["✅ No suspicious links", "✅ No urgency words", "✅ Legitimate sender domain"],
    },
    {
        "email_text":    "Dear Customer, your Netflix subscription payment failed. Update your billing details immediately at http://netflix-billing.suspicious.tk or lose access.",
        "email_subject": "Netflix Payment Failed",
        "email_sender":  "billing@netflix-support.tk",
        "is_phishing":   True,
        "risk_score":    88,
        "status":        "quarantined",
        "explanation":   ["🚨 Suspicious TLD (.tk)", "🚨 Lookalike domain", "⚠️ Payment urgency", "⚠️ Account threat"],
    },
    {
        "email_text":    "Hi Priya, your leave request for 14-18 March has been approved. Please update your calendar. HR Team",
        "email_subject": "Leave Request Approved",
        "email_sender":  "hr@company.com",
        "is_phishing":   False,
        "risk_score":    2,
        "status":        "safe",
        "explanation":   ["✅ No suspicious indicators"],
    },
    {
        "email_text":    "You have won a $1,000 Amazon gift card! Click here IMMEDIATELY to claim your prize before it expires. Limited time offer!",
        "email_subject": "Congratulations! You've Won!",
        "email_sender":  "prizes@amazon-rewards.ml",
        "is_phishing":   True,
        "risk_score":    79,
        "status":        "quarantined",
        "explanation":   ["🚨 Suspicious TLD (.ml)", "⚠️ Prize/reward language", "⚠️ Urgency words"],
    },
    {
        "email_text":    "Hello Mike, this is a reminder that your mandatory security awareness training is due by end of month. Please complete it at training.company.com",
        "email_subject": "Security Training Reminder",
        "email_sender":  "training@company.com",
        "is_phishing":   False,
        "risk_score":    8,
        "status":        "safe",
        "explanation":   ["✅ Internal sender domain", "✅ No credentials requested"],
    },
]


def seed():
    with app.app_context():
        print("\n🛡️  PhishGuard — Database Seeder")
        print("=" * 50)
        print(f"DB URI: {app.config['SQLALCHEMY_DATABASE_URI']}")

        # ── USERS ─────────────────────────────────────────────
        print("\n👤 Seeding users...")
        created_users = {}

        for u_data in USERS:
            existing = User.query.filter_by(username=u_data["username"]).first()
            if existing:
                print(f"   ⏭  Skipping {u_data['username']} (already exists)")
                created_users[u_data["username"]] = existing
                continue

            user = User(
                username   = u_data["username"],
                email      = u_data["email"],
                role       = u_data["role"],
                department = u_data.get("department"),
            )
            user.set_password(u_data["password"])
            db.session.add(user)
            db.session.flush()  # get user.id without committing
            created_users[u_data["username"]] = user
            print(f"   ✅ Created {u_data['role']:10s} → {u_data['username']} / {u_data['password']}")

        db.session.commit()

        # ── SCANS ─────────────────────────────────────────────
        print("\n📧 Seeding email scans...")
        admin = created_users.get("admin")
        sarah = created_users.get("sarah")
        mike  = created_users.get("mike")

        user_cycle = [admin, sarah, mike, sarah, mike, admin]

        for i, scan_data in enumerate(SCANS):
            scan = EmailScan(
                user_id       = user_cycle[i].id if user_cycle[i] else admin.id,
                email_body    = scan_data["email_text"],
                email_subject = scan_data.get("email_subject"),
                email_sender  = scan_data.get("email_sender"),
                is_phishing   = scan_data["is_phishing"],
                risk_score    = scan_data["risk_score"],
                confidence    = scan_data["risk_score"] / 100,
                status        = scan_data["status"],
                source        = "seed",
            )
            scan.explanation = scan_data["explanation"]
            db.session.add(scan)
            db.session.flush()

            # Create alert for high-risk scans
            if scan_data["is_phishing"] and scan_data["risk_score"] >= 65:
                severity = "critical" if scan_data["risk_score"] >= 90 else "high"
                alert = Alert(
                    scan_id   = scan.id,
                    title     = f"{severity.upper()} — Phishing detected (risk {scan_data['risk_score']}/100)",
                    message   = f"A phishing email from {scan_data.get('email_sender', 'unknown')} was detected.",
                    severity  = severity,
                    risk_score = scan_data["risk_score"],
                    alert_type = "phishing_detected",
                    target_email = scan_data.get("email_sender"),
                    status    = "pending",
                )
                db.session.add(alert)
                print(f"   🚨 Scan #{i+1}: PHISHING (risk={scan_data['risk_score']}) → alert created")
            else:
                print(f"   ✅ Scan #{i+1}: SAFE (risk={scan_data['risk_score']})")

        db.session.commit()

        # ── SUMMARY ───────────────────────────────────────────
        print("\n" + "=" * 50)
        print(f"✅ Done!")
        print(f"   Users:  {User.query.count()}")
        print(f"   Scans:  {EmailScan.query.count()}")
        print(f"   Alerts: {Alert.query.count()}")
        print("\nLogin credentials:")
        for u in USERS:
            print(f"   {u['username']:12s} / {u['password']:15s} ({u['role']})")
        print()


if __name__ == "__main__":
    seed()
