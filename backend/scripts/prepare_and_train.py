# =============================================================
#  backend/scripts/prepare_and_train.py
#
#  PURPOSE:
#    1. Parse all three raw datasets into a unified format
#    2. Combine, balance, and save as clean CSV
#    3. Train PhishingModelTrainer on the combined dataset
#    4. Stream progress events for the ML dashboard (SSE)
#    5. Save the new model and append to training history
#
#  USAGE:
#    # From ~/code/phishguard with .venv active:
#    python backend/scripts/prepare_and_train.py
#
#    # Stream progress to ML dashboard (called by Flask route):
#    python backend/scripts/prepare_and_train.py --stream
#
#  CONCEPT: Why We Parse Three Different Formats
#
#    SpamAssassin (spam/ and easy_ham/) uses the Unix mbox
#    format: each file IS one email with raw headers at the
#    top, then a blank line, then the body. We use Python's
#    built-in email.parser to extract the body text, ignoring
#    the headers (we want content features, not routing info).
#
#    fraudulent_emails.txt uses mbox CONCATENATION: many emails
#    in one file, each starting with "From " (no colon) on its
#    own line. Python's mailbox.mbox() handles this natively.
#
#    All three produce the same output: a string of email text
#    and an integer label (0=safe, 1=phishing/fraud).
# =============================================================

import os
import sys
import csv
import json
import mailbox
import logging
import argparse
import email
import email.parser
import email.policy
import random
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Generator

# ── Path setup ────────────────────────────────────────────────
# Works locally (run from project root) AND inside Docker
# (WORKDIR=/app which IS the backend folder).
#
# Strategy: we try multiple candidate paths and add all that
# exist. sys.path deduplicates automatically.
#
#   Local:  ~/code/phishguard/backend  → contains ml/, app/, etc.
#   Docker: /app                       → same folder, different mount
#
_script_dir  = Path(__file__).resolve().parent          # .../scripts/
BACKEND_ROOT = _script_dir.parent                       # .../backend/ OR /app
PROJECT_ROOT = BACKEND_ROOT.parent                      # .../phishguard/

# Insert backend root so `from ml.trainer import ...` works
sys.path.insert(0, str(BACKEND_ROOT))

# Also insert /app explicitly for Docker environments
_docker_app = Path("/app")
if _docker_app.exists() and str(_docker_app) not in sys.path:
    sys.path.insert(0, str(_docker_app))

ML_DIR      = BACKEND_ROOT / "ml"
DATASET_DIR = ML_DIR / "datasets"
MODEL_DIR   = ML_DIR / "saved_models"
HISTORY_DIR = ML_DIR / "training_history"

COMBINED_CSV  = DATASET_DIR / "combined_dataset.csv"
HISTORY_FILE  = HISTORY_DIR / "runs.json"

# ── Logging ───────────────────────────────────────────────────
# When --stream flag is used, log lines are prefixed with SSE
# format so Flask can forward them directly to the browser.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("phishguard.train")


# =============================================================
#  STEP 1: DATASET PARSERS
#  Each parser is a generator that yields (text, label) tuples.
#  Generators are used so we never load all emails into RAM
#  at once — important for large datasets.
# =============================================================

def extract_email_text(msg) -> str:
    """
    Extracts plain text from a parsed email.Message object.

    Handles multipart emails (HTML + text alternatives) by
    preferring the plain text part. Falls back to HTML with
    tags stripped if no plain text exists.

    CONCEPT: MIME and multipart emails
      Modern emails are MIME-encoded and often contain two
      versions of the same content: text/plain (for old email
      clients) and text/html (for modern ones). The email.parser
      module exposes both. We prefer text/plain because TF-IDF
      on clean text is more reliable than TF-IDF on HTML with
      tags mixed in.
    """
    text_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition  = str(part.get("Content-Disposition", ""))

            # Skip attachments
            if "attachment" in disposition:
                continue

            if content_type == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        text_parts.append(
                            payload.decode(charset, errors="replace")
                        )
                except Exception:
                    pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                text_parts.append(
                    payload.decode(charset, errors="replace")
                )
        except Exception:
            pass

    full_text = " ".join(text_parts).strip()

    # Include subject — it is one of the strongest phishing signals
    subject = msg.get("Subject", "")
    if subject:
        full_text = f"Subject: {subject}\n\n{full_text}"

    return full_text


def parse_spamassassin_folder(
    folder_path: Path,
    label: int,
) -> Generator[Tuple[str, int], None, None]:
    """
    Parses a SpamAssassin folder where each FILE is one email.

    SpamAssassin format: raw email file with headers + blank
    line + body. Python's email.parser handles this perfectly.

    Args:
        folder_path: Path to spam/ or easy_ham/ directory
        label: 0 for ham (legitimate), 1 for spam/phishing

    Yields:
        (email_text, label) tuples
    """
    if not folder_path.exists():
        logger.warning("Dataset folder not found: %s", folder_path)
        return

    parsed = 0
    skipped = 0

    for filepath in sorted(folder_path.iterdir()):
        # Skip hidden files and directories
        if filepath.name.startswith(".") or filepath.is_dir():
            continue

        try:
            raw = filepath.read_bytes()
            parser = email.parser.BytesParser(policy=email.policy.compat32)
            msg = parser.parsebytes(raw)
            text = extract_email_text(msg)

            # Skip if we couldn't extract meaningful text
            # (the mv-script files in spam/ will be empty after parsing)
            if len(text.strip()) < 20:
                skipped += 1
                continue

            # Skip shell script files (SpamAssassin packaging artifact)
            if text.strip().startswith("mv "):
                skipped += 1
                continue

            yield (text, label)
            parsed += 1

        except Exception as e:
            skipped += 1
            logger.debug("Skipped %s: %s", filepath.name, e)

    logger.info(
        "%-20s → %4d parsed, %4d skipped  [label=%d]",
        folder_path.name + "/", parsed, skipped, label
    )


def parse_fraudulent_emails(
    filepath: Path,
    label: int = 1,
) -> Generator[Tuple[str, int], None, None]:
    """
    Parses the mbox-format fraudulent_emails.txt file.

    This file contains many emails concatenated, each starting
    with "From " (the mbox separator). Python's mailbox.mbox()
    handles this format natively.

    Note: These are 419/advance-fee fraud emails. They are
    labelled as phishing (1) because they share the same
    social-engineering psychology as phishing — urgency,
    authority impersonation, financial lure, request for
    personal information.

    Args:
        filepath: Path to fraudulent_emails.txt
        label:    1 (phishing/fraud)

    Yields:
        (email_text, label) tuples
    """
    if not filepath.exists():
        logger.warning("Fraudulent emails file not found: %s", filepath)
        return

    parsed = 0
    skipped = 0

    try:
        mbox = mailbox.mbox(str(filepath))
        for msg in mbox:
            try:
                text = extract_email_text(msg)
                if len(text.strip()) < 20:
                    skipped += 1
                    continue
                yield (text, label)
                parsed += 1
            except Exception as e:
                skipped += 1
                logger.debug("Skipped mbox entry: %s", e)

    except Exception as e:
        logger.error("Failed to parse mbox file %s: %s", filepath, e)

    logger.info(
        "%-20s → %4d parsed, %4d skipped  [label=%d]",
        filepath.name, parsed, skipped, label
    )


# =============================================================
#  STEP 2: COMBINE AND BALANCE DATASETS
# =============================================================

def build_combined_dataset(
    stream: bool = False,
) -> Tuple[List[str], List[int]]:
    """
    Loads all three datasets, combines them, and balances
    the class distribution.

    CONCEPT: Class Balancing
      If we have 2,551 legitimate emails but only 501 phishing
      emails, a naive classifier can reach 83% accuracy by
      just predicting "safe" every time. class_weight="balanced"
      in the RandomForest partially compensates for this, but
      it is better practice to also balance the training data.

      Strategy: oversample the minority class by duplicating
      examples randomly until both classes are equal size.
      This is called Random Oversampling. More sophisticated
      methods (SMOTE) exist but are overkill for text data.

    Returns:
        (emails, labels) — balanced, shuffled lists
    """
    _log(stream, "INFO", "=" * 50)
    _log(stream, "INFO", "  LOADING DATASETS")
    _log(stream, "INFO", "=" * 50)

    phishing_emails = []
    safe_emails     = []

    # ── Dataset 1: SpamAssassin spam (phishing/spam = label 1) ─
    for text, label in parse_spamassassin_folder(
        DATASET_DIR / "spam", label=1
    ):
        phishing_emails.append(text)

    # ── Dataset 2: SpamAssassin easy_ham (safe = label 0) ──────
    for text, label in parse_spamassassin_folder(
        DATASET_DIR / "easy_ham", label=0
    ):
        safe_emails.append(text)

    # ── Dataset 3: Fraudulent emails (phishing = label 1) ──────
    fraud_file = DATASET_DIR / "fraudulent_emails.txt"
    if not fraud_file.exists():
        legacy = DATASET_DIR / "fradulent_emails.txt"
        if legacy.exists():
            fraud_file = legacy

    for text, label in parse_fraudulent_emails(fraud_file, label=1):
        phishing_emails.append(text)

    # ── Summary ────────────────────────────────────────────────
    _log(stream, "INFO", "─" * 50)
    _log(stream, "INFO", f"  Phishing emails : {len(phishing_emails):,}")
    _log(stream, "INFO", f"  Safe emails     : {len(safe_emails):,}")
    _log(stream, "INFO", f"  Total raw       : {len(phishing_emails) + len(safe_emails):,}")

    if len(phishing_emails) == 0:
        raise ValueError(
            "No phishing emails found. Check your dataset paths.\n"
            f"Expected: {DATASET_DIR / 'spam'} and {fraud_file}"
        )
    if len(safe_emails) == 0:
        raise ValueError(
            "No safe emails found. Check your dataset paths.\n"
            f"Expected: {DATASET_DIR / 'easy_ham'}"
        )

    # ── Balance classes ────────────────────────────────────────
    max_class = max(len(phishing_emails), len(safe_emails))

    # Oversample minority class by random duplication
    while len(phishing_emails) < max_class:
        phishing_emails.append(random.choice(phishing_emails))
    while len(safe_emails) < max_class:
        safe_emails.append(random.choice(safe_emails))

    # Combine and shuffle
    emails = phishing_emails + safe_emails
    labels = [1] * len(phishing_emails) + [0] * len(safe_emails)

    combined = list(zip(emails, labels))
    random.shuffle(combined)
    emails, labels = zip(*combined)

    _log(stream, "INFO", f"  After balancing : {len(emails):,} total ({max_class:,} per class)")
    _log(stream, "INFO", "─" * 50)

    return list(emails), list(labels)


def save_combined_csv(emails: List[str], labels: List[int]) -> None:
    """
    Saves combined dataset as CSV so future retraining does not
    need to re-parse all raw files.

    CSV columns: text, label
    - text:  email body text (newlines replaced with \\n for CSV)
    - label: 0 (safe) or 1 (phishing)
    """
    DATASET_DIR.mkdir(parents=True, exist_ok=True)

    with open(COMBINED_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        writer.writerow(["text", "label"])
        for text, label in zip(emails, labels):
            # Sanitise: replace newlines for CSV storage
            clean = text.replace("\n", " ").replace("\r", " ")
            writer.writerow([clean, label])

    size_mb = COMBINED_CSV.stat().st_size / (1024 * 1024)
    logger.info("Saved combined dataset: %s (%.1f MB)", COMBINED_CSV, size_mb)


# =============================================================
#  STEP 3: TRAIN
# =============================================================

def train(stream: bool = False) -> dict:
    """
    Full pipeline: parse → balance → train → save → log history.

    Args:
        stream: if True, emit SSE-formatted progress lines to
                stdout for Flask to forward to the dashboard.

    Returns:
        Training metrics dict from PhishingModelTrainer.
    """
    from ml.trainer import PhishingModelTrainer

    random.seed(42)

    # ── Load data ──────────────────────────────────────────────
    emails, labels = build_combined_dataset(stream=stream)
    save_combined_csv(emails, labels)

    # ── Train ──────────────────────────────────────────────────
    _log(stream, "INFO", "")
    _log(stream, "INFO", "=" * 50)
    _log(stream, "INFO", "  TRAINING MODEL")
    _log(stream, "INFO", "=" * 50)
    _log(stream, "INFO", f"  Algorithm   : Random Forest")
    _log(stream, "INFO", f"  TF-IDF vocab: 5,000 features + bigrams")
    _log(stream, "INFO", f"  Manual feats: 35 hand-crafted signals")
    _log(stream, "INFO", f"  Dataset size: {len(emails):,} emails")
    _log(stream, "INFO", "")

    trainer = PhishingModelTrainer(
        model_name="random_forest",
        tfidf_max_features=5000,
        test_size=0.2,
        random_state=42,
    )

    _log(stream, "INFO", "Extracting features and splitting data...")
    metrics = trainer.train(emails, labels)

    # ── Save model ─────────────────────────────────────────────
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    trainer.save(str(MODEL_DIR))

    # ── Log training history ───────────────────────────────────
    _save_history(metrics, len(emails))

    # ── Final summary ──────────────────────────────────────────
    _log(stream, "INFO", "")
    _log(stream, "INFO", "=" * 50)
    _log(stream, "INFO", "  TRAINING COMPLETE")
    _log(stream, "INFO", "=" * 50)
    _log(stream, "INFO", f"  Accuracy  : {metrics['accuracy']*100:.1f}%")
    _log(stream, "INFO", f"  Precision : {metrics['precision']*100:.1f}%")
    _log(stream, "INFO", f"  Recall    : {metrics['recall']*100:.1f}%")
    _log(stream, "INFO", f"  F1 Score  : {metrics['f1_score']*100:.1f}%")
    _log(stream, "INFO", f"  ROC-AUC   : {metrics['roc_auc']:.4f}")
    _log(stream, "INFO", f"  CV F1     : {metrics['cv_f1_mean']:.3f} ± {metrics['cv_f1_std']:.3f}")
    _log(stream, "INFO", "")
    _log(stream, "INFO", f"  False Negatives (missed phishing): {metrics['false_negatives']}")
    _log(stream, "INFO", f"  False Positives (safe flagged)   : {metrics['false_positives']}")
    _log(stream, "INFO", "")
    _log(stream, "INFO", f"  Model saved to: {MODEL_DIR}")
    _log(stream, "INFO", "TRAINING_DONE")  # sentinel for SSE client

    return metrics


def _log(stream: bool, level: str, message: str) -> None:
    """
    Dual-output logger: writes to Python logger AND to stdout
    in SSE format when --stream is active.

    SSE format:  data: LEVEL | message\n\n
    The Flask route reads stdout line by line and forwards
    each line to the browser as a Server-Sent Event.
    """
    getattr(logger, level.lower(), logger.info)(message)
    if stream:
        # Flush immediately so Flask captures it in real time
        print(f"data: {level} | {message}", flush=True)


def _save_history(metrics: dict, n_samples: int) -> None:
    """
    Appends this training run to the history log.
    Used by the ML dashboard to show performance over time.
    """
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    history = []
    if HISTORY_FILE.exists():
        try:
            history = json.loads(HISTORY_FILE.read_text())
        except Exception:
            history = []

    run = {
        "run_id":       len(history) + 1,
        "trained_at":   datetime.now().isoformat(),
        "n_samples":    n_samples,
        "accuracy":     metrics["accuracy"],
        "precision":    metrics["precision"],
        "recall":       metrics["recall"],
        "f1_score":     metrics["f1_score"],
        "roc_auc":      metrics["roc_auc"],
        "cv_f1_mean":   metrics["cv_f1_mean"],
        "cv_f1_std":    metrics["cv_f1_std"],
        "false_positives": metrics["false_positives"],
        "false_negatives": metrics["false_negatives"],
        "training_time_seconds": metrics["training_time_seconds"],
    }

    history.append(run)

    # Keep last 50 runs
    history = history[-50:]
    HISTORY_FILE.write_text(json.dumps(history, indent=2))
    logger.info("Training history saved (%d runs)", len(history))


# =============================================================
#  ENTRY POINT
# =============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PhishGuard ML training pipeline"
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        help="Emit SSE-formatted progress to stdout (for Flask dashboard)"
    )
    parser.add_argument(
        "--parse-only",
        action="store_true",
        help="Only parse datasets and save CSV, do not train"
    )
    args = parser.parse_args()

    if args.parse_only:
        emails, labels = build_combined_dataset(stream=args.stream)
        save_combined_csv(emails, labels)
        print(f"Dataset saved: {COMBINED_CSV}")
    else:
        metrics = train(stream=args.stream)
        sys.exit(0)
