#!/usr/bin/env python3
# =============================================================
#  scripts/train_model.py
#  Run this to train the phishing detection model
# =============================================================
#
#  USAGE (from the project root: phishguard/):
#    python scripts/train_model.py
#
#  WHAT THIS DOES:
#    1. Loads training data (CSV file or built-in demo data)
#    2. Trains the Random Forest classifier
#    3. Evaluates it and prints a full report
#    4. Saves the model to backend/ml/saved_models/
#
#  After this script runs, the Flask server will automatically
#  load the saved model on the next restart.
#
#  ADDING YOUR OWN DATA:
#    Put a CSV file at: backend/ml/datasets/emails.csv
#    Required columns: "text" (email body), "label" (0=safe, 1=phishing)
#
#    Great free datasets to download:
#    - Enron Email Dataset (legitimate emails)
#    - SpamAssassin Public Corpus
#    - CLAIR Phishing Email Collection
#    - Kaggle: "Phishing Email Detection" datasets
# =============================================================

import sys
import os
import logging
from typing import Optional

# ── PATH SETUP ────────────────────────────────────────────────
# Same pattern as seed_database.py — compute absolute paths
# so this script works from any working directory.
THIS_FILE    = os.path.abspath(__file__)
SCRIPTS_DIR  = os.path.dirname(THIS_FILE)
PROJECT_ROOT = os.path.dirname(SCRIPTS_DIR)
BACKEND_DIR  = os.path.join(PROJECT_ROOT, "backend")

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from dotenv import load_dotenv
load_dotenv(os.path.join(BACKEND_DIR, ".env"))

# ── LOGGING ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── IMPORTS ───────────────────────────────────────────────────
from ml.trainer   import PhishingModelTrainer
from ml.evaluator import ModelEvaluator


# =============================================================
#  DEMO TRAINING DATA
#
#  These 40 examples are enough to demonstrate the pipeline.
#  For real-world accuracy (85-90%), you need 5,000-50,000
#  labelled emails. See the dataset suggestions above.
#
#  Label meanings: 0 = safe, 1 = phishing
# =============================================================

DEMO_EMAILS = [
    # ── PHISHING (label = 1) ──────────────────────────────────
    (
        "URGENT: Your PayPal account has been suspended! "
        "Click immediately to verify: http://192.168.1.100/paypal-verify "
        "Enter your password, credit card, and SSN to restore access. "
        "Account will be PERMANENTLY DELETED within 24 hours!!!",
        1
    ),
    (
        "Congratulations! You have been selected as our lucky winner! "
        "Claim your $5,000 Amazon gift card NOW: http://amaz0n-prizes.tk/claim "
        "This offer EXPIRES in 24 hours. Limited time only!",
        1
    ),
    (
        "Dear Customer, unusual sign-in activity detected on your account. "
        "Verify your identity immediately: http://secure-banklogin.xyz "
        "Provide your bank account number, routing number and date of birth.",
        1
    ),
    (
        "FINAL NOTICE: Your Microsoft account will be terminated in 48 hours. "
        "Download and run this tool to fix it: http://bit.ly/ms-fix-urgent "
        "Action required NOW or lose access permanently!!!",
        1
    ),
    (
        "IRS TAX REFUND NOTIFICATION: You are owed $3,847. "
        "To receive your refund, submit your social security number "
        "and bank account details: http://irs-refund.cf/claim",
        1
    ),
    (
        "Apple ID Alert: Someone signed in from Russia. "
        "Your account will be closed unless you verify NOW: "
        "http://app1e-secure.ml/verify — Enter password immediately!",
        1
    ),
    (
        "WINNER ANNOUNCEMENT: You've won our monthly lottery! "
        "Prize: $10,000 cash. Claim here: https://tinyurl.com/xyz123 "
        "You MUST claim within 24 hours or prize will be forfeited.",
        1
    ),
    (
        "NetFlix Billing FAILED. Your subscription expires TONIGHT. "
        "Update credit card now: http://netfl1x-billing.click/update "
        "Failure to act will result in immediate account termination.",
        1
    ),
    (
        "Security ALERT: Your bank account has been compromised. "
        "URGENT ACTION REQUIRED. Reset PIN: http://chase-secure.xyz/reset "
        "Provide account number and social security to verify identity.",
        1
    ),
    (
        "Dear Valued User, FedEx delivery attempt failed. "
        "Pay $2.99 redelivery fee here: http://fedex-delivery.tk/pay "
        "Your package will be returned if not paid within 24hrs.",
        1
    ),
    (
        "CONGRATULATIONS! Your email was randomly selected! "
        "You've won a free iPhone 15! Click to claim: bit.ly/free-iphone "
        "Limited to first 100 winners only. Act immediately!",
        1
    ),
    (
        "LinkedIn: Unusual login from Nigeria detected on your account. "
        "Verify your credentials immediately or account will be suspended: "
        "http://linkedin-verify.xyz/login — Enter username and password.",
        1
    ),
    (
        "Your Dropbox storage is FULL and files will be deleted in 24 hours. "
        "Upgrade immediately at: http://dr0pbox-upgrade.ml/pay "
        "Enter credit card details to prevent data loss.",
        1
    ),
    (
        "DocuSign: Important document requires your signature. "
        "View and sign HERE: http://192.168.0.1/docusign/review "
        "Document expires in 2 hours. Immediate action required.",
        1
    ),
    (
        "Wells Fargo: URGENT — your account shows suspicious transactions. "
        "Verify at: http://wellsfargo-secure.cf/verify "
        "You must provide SSN, card number and PIN to proceed.",
        1
    ),
    (
        "Your Google Account has been compromised! "
        "Hackers have access to your emails. Secure now: "
        "http://g00gle-secure.tk/reset — Enter password to protect account!!!",
        1
    ),
    (
        "FREE iPhone giveaway for loyal customers selected this month! "
        "Download the form, fill it and email back your: name, DOB, "
        "address, national insurance number and bank sort code. Hurry!",
        1
    ),
    (
        "HMRC: You are eligible for a tax refund of £892.40. "
        "Complete the refund request: http://hmrc-refund.click/apply "
        "Provide NI number and bank account. Offer expires 48 hours.",
        1
    ),
    (
        "Your UPS package could not be delivered. Confirm shipping details "
        "and pay £1.49 customs fee: http://ups-confirm.xyz/pay "
        "Parcel will be returned after 72 hours if unclaimed.",
        1
    ),
    (
        "American Express: Your card has been flagged for fraud. "
        "Verify transactions at: http://amex-verify.ml "
        "Enter card number, CVV, expiry and billing zip code immediately.",
        1
    ),

    # ── SAFE (label = 0) ─────────────────────────────────────
    (
        "Hi Sarah, just following up on the project proposal we discussed "
        "in Tuesday's meeting. Could you send over the updated budget "
        "estimates when you get a chance? No rush, end of week is fine.",
        0
    ),
    (
        "Your Amazon order #114-7823691 has shipped. Expected delivery: "
        "Wednesday March 15. Track your package at amazon.com/orders. "
        "Questions? Contact us at amazon.com/help.",
        0
    ),
    (
        "Meeting reminder: All-hands standup tomorrow at 9am in the main "
        "conference room. Agenda: Q1 results, roadmap review, team updates. "
        "Please come prepared with your weekly status.",
        0
    ),
    (
        "Your monthly bank statement is ready to view online. "
        "Log in to your account at bankofamerica.com to view your "
        "statement. As a reminder, we will never ask for your password "
        "by email.",
        0
    ),
    (
        "Newsletter: This month at Acme Corp — new office opens in Austin, "
        "Q3 revenue up 12%, employee of the month award goes to David Chen. "
        "Read the full story on our intranet.",
        0
    ),
    (
        "Hi team, the updated product roadmap for Q2 is now available in "
        "the shared Google Drive folder. Please review slides 14-22 which "
        "cover the new feature priorities. Let me know your feedback.",
        0
    ),
    (
        "Your Spotify Premium subscription has been renewed for another month. "
        "Next billing date: April 3. Amount: £9.99. To manage your "
        "subscription, visit spotify.com/account.",
        0
    ),
    (
        "HR reminder: Annual performance reviews are due by March 31st. "
        "Please complete your self-assessment form in Workday and schedule "
        "your 1:1 with your manager before the deadline.",
        0
    ),
    (
        "The software deployment to production was successful. "
        "Version 2.4.1 is now live. Monitoring dashboards show all "
        "services healthy. Rollback plan is ready if needed.",
        0
    ),
    (
        "Good morning, please find attached the February invoice for "
        "consulting services. Payment terms are net-30 as agreed. "
        "Please don't hesitate to reach out with any questions.",
        0
    ),
    (
        "GitHub: New pull request opened by alex-dev in repository "
        "backend-api. Title: 'Add rate limiting to auth endpoints'. "
        "Review at github.com/yourorg/backend-api/pull/847",
        0
    ),
    (
        "Your flight confirmation: BA0287 London Heathrow to New York JFK "
        "on March 22. Departs 11:35, arrives 14:15. Seat 24A. "
        "Check in online from March 20 at britishairways.com.",
        0
    ),
    (
        "Slack notification: James left a comment on your design file: "
        "'Love the new colour palette — could we try a slightly darker "
        "shade for the primary CTA button? Otherwise looks great!'",
        0
    ),
    (
        "Team lunch this Friday at 12:30pm at The Oak restaurant on "
        "Main Street. We have a reservation for 12 people. "
        "Please let Maria know your dietary requirements by Wednesday.",
        0
    ),
    (
        "Your Docker Hub image push was successful. "
        "Image: mycompany/phishguard:v1.2.3 "
        "Digest: sha256:abc123... pushed to repository at 14:32 UTC.",
        0
    ),
    (
        "Quarterly IT security reminder: Please ensure your laptop's "
        "operating system is updated to the latest version. "
        "Contact the help desk at ext. 4200 if you need assistance.",
        0
    ),
    (
        "Hello, this is a reminder that the library book you borrowed "
        "'Clean Code' is due back on March 20th. You can renew it "
        "online at library.example.com or in person at the front desk.",
        0
    ),
    (
        "Hi, we wanted to confirm your appointment with Dr. Johnson "
        "on Thursday March 16 at 2:30pm. Please call us at 555-1234 "
        "to reschedule if needed. See you then!",
        0
    ),
    (
        "Weekly digest: Your GitHub repositories had 47 commits this week. "
        "Top contributor: you (23 commits). "
        "2 pull requests merged, 1 open issue resolved.",
        0
    ),
    (
        "Congratulations on completing the Python for Data Science course! "
        "Your certificate is ready to download from your learning portal. "
        "Keep up the great work — next recommended course: Machine Learning.",
        0
    ),
]


def load_dataset(csv_path: Optional[str] = None):
    """
    Loads training data from a CSV file if provided,
    otherwise falls back to the built-in demo dataset.

    CSV format required:
        text,label
        "Email body here...",1
        "Another email...",0

    Args:
        csv_path: Path to CSV file. None = use demo data.

    Returns:
        Tuple of (emails list, labels list)
    """
    if csv_path and os.path.exists(csv_path):
        import pandas as pd
        logger.info("Loading dataset from: %s", csv_path)
        df = pd.read_csv(csv_path)

        # Validate expected columns exist
        if "text" not in df.columns or "label" not in df.columns:
            raise ValueError(
                "CSV must have columns: 'text' and 'label'. "
                f"Found: {list(df.columns)}"
            )

        # Drop rows with missing text or invalid labels
        df = df.dropna(subset=["text", "label"])
        df = df[df["label"].isin([0, 1])]

        emails = df["text"].astype(str).tolist()
        labels = df["label"].astype(int).tolist()

        phishing_count = sum(labels)
        logger.info(
            "Dataset loaded: %d emails (%d phishing, %d safe)",
            len(emails), phishing_count, len(emails) - phishing_count,
        )
        return emails, labels

    else:
        logger.info("No CSV found — using built-in demo dataset (%d emails).", len(DEMO_EMAILS))
        logger.warning(
            "Demo data is too small for production accuracy. "
            "For 85%%+ accuracy, download a real dataset (see file header)."
        )
        emails = [e for e, _ in DEMO_EMAILS]
        labels = [l for _, l in DEMO_EMAILS]
        return emails, labels




def main():
    """
    Main training entrypoint.
    Run this with: python scripts/train_model.py
    """
    print("\n" + "═" * 55)
    print("  🛡️  PhishGuard AI — Model Training")
    print("═" * 55)

    # ── LOAD DATA ─────────────────────────────────────────────
    dataset_path = os.path.join(BACKEND_DIR, "ml", "datasets", "emails.csv")
    emails, labels = load_dataset(dataset_path)

    print(f"\n  Dataset   : {len(emails)} emails")
    print(f"  Phishing  : {sum(labels)} ({sum(labels)/len(labels)*100:.0f}%)")
    print(f"  Safe      : {len(labels)-sum(labels)}")
    print(f"  Model     : Random Forest (200 trees)")
    print("═" * 55 + "\n")

    # ── TRAIN ─────────────────────────────────────────────────
    trainer = PhishingModelTrainer(
        model_name="random_forest",
        tfidf_max_features=5000,
        test_size=0.2,
        random_state=42,
    )
    metrics = trainer.train(emails, labels)

    # ── EVALUATE ──────────────────────────────────────────────
    print("\n📊 Running full evaluation report...")
    evaluator = ModelEvaluator(trainer)

    # Use training data for demo (in production, use a held-out set)
    # Build a balanced sample — ROC AUC needs BOTH classes present.
    # emails[:20] are all phishing (one class only) which causes a crash.
    phishing_pairs = [(e, l) for e, l in zip(emails, labels) if l == 1][:10]
    safe_pairs     = [(e, l) for e, l in zip(emails, labels) if l == 0][:10]
    eval_emails    = [e for e, _ in phishing_pairs + safe_pairs]
    eval_labels    = [l for _, l in phishing_pairs + safe_pairs]
    report = evaluator.full_report(eval_emails, eval_labels)
    evaluator.print_report(report)

    # ── SAVE ──────────────────────────────────────────────────
    save_dir = os.path.join(BACKEND_DIR, "ml", "saved_models")
    trainer.save(save_dir)

    print("\n" + "═" * 55)
    print("  ✅ Training complete!")
    print(f"  Accuracy : {metrics['accuracy']*100:.1f}%")
    print(f"  F1 Score : {metrics['f1_score']*100:.1f}%")
    print(f"  Recall   : {metrics['recall']*100:.1f}%  (phishing caught)")
    print(f"  Saved to : {save_dir}")
    print("\n  Restart the Flask server to load the new model.")
    print("  Then test: POST http://localhost:5000/api/detect")
    print("═" * 55 + "\n")


if __name__ == "__main__":
    main()