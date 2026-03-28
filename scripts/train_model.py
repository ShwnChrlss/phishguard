# =============================================================
#  backend/scripts/train_model.py
#  PhishGuard Model Training Entry Point
# =============================================================
#
#  This is the script you run to train (or retrain) the model.
#  It reads the combined dataset produced by prepare_datasets.py,
#  feeds it to your PhishingModelTrainer, evaluates the result,
#  and saves the new model to saved_models/.
#
#  The existing model is NOT overwritten unless you confirm,
#  or unless the new model performs better (see --auto-replace).
#
#  USAGE:
#    cd ~/code/phishguard
#    source .venv/bin/activate
#
#    # Basic training run:
#    python backend/scripts/train_model.py
#
#    # Choose model type:
#    python backend/scripts/train_model.py --model gradient_boosting
#
#    # Use a custom dataset CSV:
#    python backend/scripts/train_model.py \
#        --dataset backend/ml/datasets/combined_dataset.csv
#
#    # Automatically replace old model if new one is better:
#    python backend/scripts/train_model.py --auto-replace
#
#    # Expand TF-IDF vocabulary (more features = slower, more accurate):
#    python backend/scripts/train_model.py --tfidf-features 10000
#
#  CONCEPT: Why we compare old vs new before replacing
#    Retraining on new data can sometimes HURT performance if
#    the new data is noisy, mislabelled, or very different
#    from what your model will see in production.
#    By comparing F1 scores before replacing, you protect
#    against accidentally deploying a worse model.
# =============================================================

import os
import sys
import csv
import json
import logging
import argparse
import shutil
from pathlib import Path
from datetime import datetime
from typing import List, Tuple

# Add project root to path so we can import from backend/ml/
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from ml.trainer import PhishingModelTrainer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Default paths ─────────────────────────────────────────────
DATASETS_DIR   = PROJECT_ROOT / "backend" / "ml" / "datasets"
MODELS_DIR     = PROJECT_ROOT / "backend" / "ml" / "saved_models"
DEFAULT_CSV    = DATASETS_DIR / "combined_dataset.csv"
TRAINING_LOG   = DATASETS_DIR / "training_history.jsonl"


# =============================================================
#  LOAD DATASET FROM CSV
# =============================================================

def load_dataset(csv_path: Path) -> Tuple[List[str], List[int]]:
    """
    Reads the combined_dataset.csv produced by prepare_datasets.py
    and returns the two lists your trainer.train() expects.

    Returns:
        (emails, labels) where:
          emails — list of email text strings
          labels — list of 0/1 integers (0=safe, 1=phishing)
    """
    if not csv_path.exists():
        logger.error(
            "Dataset not found: %s\n"
            "Run first: python backend/scripts/prepare_datasets.py --help",
            csv_path
        )
        sys.exit(1)

    emails = []
    labels = []
    skipped = 0

    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)

        for row in reader:
            text  = row.get("text", "").strip()
            label = row.get("label", "").strip()

            if not text:
                skipped += 1
                continue

            try:
                label_int = int(label)
                if label_int not in (0, 1):
                    skipped += 1
                    continue
            except ValueError:
                skipped += 1
                continue

            emails.append(text)
            labels.append(label_int)

    phishing_count = sum(labels)
    safe_count     = len(labels) - phishing_count

    logger.info(
        "Loaded %d samples: %d phishing, %d safe (skipped %d malformed rows)",
        len(emails), phishing_count, safe_count, skipped
    )

    if len(emails) < 100:
        logger.warning(
            "Only %d samples — model quality will be poor. "
            "Aim for at least 1,000 samples (5,000+ recommended).",
            len(emails)
        )

    return emails, labels


# =============================================================
#  LOAD EXISTING MODEL METRICS (for comparison)
# =============================================================

def load_existing_metrics(models_dir: Path) -> dict:
    """
    Reads the metadata.json of the currently deployed model
    so we can compare it against the newly trained one.

    Returns {} if no model exists yet (first training run).
    """
    metadata_path = models_dir / "metadata.json"
    if not metadata_path.exists():
        return {}

    try:
        with open(metadata_path) as f:
            meta = json.load(f)
        metrics = meta.get("metrics", {})
        logger.info(
            "Existing model: F1=%.4f, Recall=%.4f, trained at %s",
            metrics.get("f1_score", 0),
            metrics.get("recall", 0),
            meta.get("trained_at", "unknown"),
        )
        return metrics
    except Exception as e:
        logger.warning("Could not read existing metrics: %s", e)
        return {}


# =============================================================
#  SAVE TRAINING HISTORY
# =============================================================

def append_training_history(metrics: dict, model_name: str, dataset_path: str) -> None:
    """
    Appends a training run record to training_history.jsonl.

    JSONL (JSON Lines) format stores one JSON object per line,
    making it easy to parse training history programmatically
    and easy to review manually.

    Over time this file tells you:
      - Whether model quality is improving or degrading
      - Which datasets produced the best results
      - When significant performance changes happened
    """
    TRAINING_LOG.parent.mkdir(parents=True, exist_ok=True)

    record = {
        "timestamp":    datetime.now().isoformat(),
        "model_name":   model_name,
        "dataset_path": str(dataset_path),
        "metrics": {
            "accuracy":  metrics.get("accuracy"),
            "precision": metrics.get("precision"),
            "recall":    metrics.get("recall"),
            "f1_score":  metrics.get("f1_score"),
            "roc_auc":   metrics.get("roc_auc"),
            "cv_f1_mean": metrics.get("cv_f1_mean"),
            "n_train":   metrics.get("n_train"),
            "n_test":    metrics.get("n_test"),
        }
    }

    with open(TRAINING_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    logger.info("Training record appended to: %s", TRAINING_LOG)


# =============================================================
#  BACKUP EXISTING MODEL
# =============================================================

def backup_existing_model(models_dir: Path) -> Optional[Path]:
    """
    Creates a timestamped backup of the current model files
    before replacing them.

    This is your safety net. If the new model turns out to be
    worse in production, you can restore the backup.

    Returns the backup directory path, or None if no model exists.
    """
    model_path = models_dir / "model.pkl"
    if not model_path.exists():
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = models_dir / f"backup_{timestamp}"
    backup_dir.mkdir(parents=True, exist_ok=True)

    for filename in ("model.pkl", "vectorizer.pkl", "metadata.json"):
        src = models_dir / filename
        if src.exists():
            shutil.copy2(src, backup_dir / filename)

    logger.info("Backed up existing model to: %s", backup_dir)
    return backup_dir


# Fix missing Optional import
from typing import Optional


# =============================================================
#  MAIN
# =============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Train the PhishGuard ML model",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Standard training run (reads combined_dataset.csv):
  python backend/scripts/train_model.py

  # Use gradient boosting instead of random forest:
  python backend/scripts/train_model.py --model gradient_boosting

  # Larger TF-IDF vocabulary (more accurate, slower to train):
  python backend/scripts/train_model.py --tfidf-features 10000

  # Auto-replace old model if new one has better F1:
  python backend/scripts/train_model.py --auto-replace

  # Full pipeline (prepare data then train):
  python backend/scripts/prepare_datasets.py --spamassassin ~/Downloads/sa/
  python backend/scripts/train_model.py --auto-replace

Understanding the metrics output:
  Recall is the most important metric for PhishGuard.
  It measures: of all real phishing emails, what % did we catch?
  A recall of 0.95 means we catch 95 out of 100 phishing emails.
  The 5 we miss are false negatives — the dangerous ones.

  Precision measures: of emails we flagged, what % were real phishing?
  Low precision = many false alarms (annoying but not dangerous).
  Low recall    = missed phishing (dangerous).

  For a security tool, optimise for recall first, precision second.
        """
    )

    parser.add_argument("--dataset", type=str, default=str(DEFAULT_CSV),
        help=f"Path to training CSV (default: {DEFAULT_CSV})")
    parser.add_argument("--model", type=str, default="random_forest",
        choices=["random_forest", "gradient_boosting"],
        help="Classifier to use (default: random_forest)")
    parser.add_argument("--tfidf-features", type=int, default=5000,
        help="TF-IDF vocabulary size (default: 5000, max recommended: 15000)")
    parser.add_argument("--test-size", type=float, default=0.2,
        help="Fraction of data for testing (default: 0.2 = 20%%)")
    parser.add_argument("--output-dir", type=str, default=str(MODELS_DIR),
        help=f"Directory to save model (default: {MODELS_DIR})")
    parser.add_argument("--auto-replace", action="store_true",
        help="Automatically replace old model if new F1 is higher")
    parser.add_argument("--force-replace", action="store_true",
        help="Replace old model regardless of performance comparison")
    parser.add_argument("--no-backup", action="store_true",
        help="Skip backing up the existing model before replacing")

    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Step 1: Load dataset ───────────────────────────────
    logger.info("=" * 55)
    logger.info("  PhishGuard Model Training")
    logger.info("=" * 55)
    logger.info("Dataset:        %s", args.dataset)
    logger.info("Model type:     %s", args.model)
    logger.info("TF-IDF features:%d", args.tfidf_features)
    logger.info("Test split:     %.0f%%", args.test_size * 100)
    logger.info("=" * 55)

    emails, labels = load_dataset(Path(args.dataset))

    # ── Step 2: Load existing metrics for comparison ───────
    existing_metrics = load_existing_metrics(output_dir)
    existing_f1      = existing_metrics.get("f1_score", 0.0)

    # ── Step 3: Train new model ────────────────────────────
    trainer = PhishingModelTrainer(
        model_name=args.model,
        tfidf_max_features=args.tfidf_features,
        test_size=args.test_size,
    )

    metrics = trainer.train(emails, labels)
    new_f1  = metrics.get("f1_score", 0.0)

    # ── Step 4: Log training history ───────────────────────
    append_training_history(metrics, args.model, args.dataset)

    # ── Step 5: Decide whether to save ────────────────────
    logger.info("=" * 55)

    if args.force_replace:
        decision = "force_replace"
        logger.info("Force replace: saving new model unconditionally.")

    elif not existing_metrics:
        decision = "first_model"
        logger.info("No existing model found — saving as first model.")

    elif args.auto_replace:
        if new_f1 >= existing_f1:
            decision = "auto_replace_better"
            logger.info(
                "New F1 (%.4f) >= existing F1 (%.4f) — auto-replacing.",
                new_f1, existing_f1
            )
        else:
            decision = "auto_replace_worse"
            logger.warning(
                "New F1 (%.4f) < existing F1 (%.4f) — NOT replacing. "
                "Use --force-replace to override.",
                new_f1, existing_f1
            )

    else:
        # Interactive mode — ask the user
        logger.info(
            "Comparison: existing F1=%.4f | new F1=%.4f | delta=%+.4f",
            existing_f1, new_f1, new_f1 - existing_f1
        )
        try:
            answer = input("\nReplace existing model with new one? [y/N]: ").strip().lower()
            decision = "user_yes" if answer == "y" else "user_no"
        except (EOFError, KeyboardInterrupt):
            decision = "user_no"

    # ── Step 6: Save if decided ────────────────────────────
    should_save = decision in ("first_model", "force_replace",
                               "auto_replace_better", "user_yes")

    if should_save:
        if not args.no_backup and existing_metrics:
            backup_existing_model(output_dir)

        trainer.save(str(output_dir))
        logger.info("New model saved to: %s", output_dir)
        logger.info(
            "Restart your Flask app to load the new model: "
            "docker-compose restart app"
        )
    else:
        logger.info(
            "Existing model kept. New model was NOT saved.\n"
            "To save anyway: re-run with --force-replace"
        )

    # ── Step 7: Print final summary ────────────────────────
    logger.info("=" * 55)
    logger.info("  FINAL SUMMARY")
    logger.info("=" * 55)
    logger.info("  Accuracy  : %.1f%%", metrics["accuracy"]  * 100)
    logger.info("  Precision : %.1f%%", metrics["precision"] * 100)
    logger.info("  Recall    : %.1f%%", metrics["recall"]    * 100)
    logger.info("  F1 Score  : %.1f%%", metrics["f1_score"]  * 100)
    logger.info("  ROC-AUC   : %.4f",   metrics["roc_auc"])
    logger.info("  CV F1     : %.3f ± %.3f",
                metrics["cv_f1_mean"], metrics["cv_f1_std"])
    logger.info("  Missed phishing (FN): %d", metrics["false_negatives"])
    logger.info("  False alarms   (FP): %d", metrics["false_positives"])
    logger.info("=" * 55)

    if metrics["false_negatives"] > 0:
        pct_missed = metrics["false_negatives"] / (
            metrics["false_negatives"] + metrics["true_positives"]
        ) * 100
        logger.warning(
            "%.1f%% of phishing emails in the test set were MISSED. "
            "More diverse training data will reduce this.",
            pct_missed
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
