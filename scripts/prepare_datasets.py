# =============================================================
#  backend/scripts/prepare_datasets.py
#  Dataset Download, Preprocessing, and Consolidation Pipeline
# =============================================================
#
#  CONCEPT: Why preprocessing matters
#
#  Raw email datasets come in many formats — raw .eml files,
#  CSV files with different column names, JSON from APIs,
#  mbox archives, plain text dumps. Your trainer.py needs
#  exactly two Python lists:
#
#    emails: List[str]   — raw text of each email
#    labels: List[int]   — 0 = safe, 1 = phishing
#
#  This script is the bridge between messy raw data and that
#  clean, consistent format. It handles every dataset format
#  we use and outputs a single unified CSV that train_model.py
#  reads in one line.
#
#  DATASETS HANDLED:
#    1. SpamAssassin Public Corpus  (spam + ham folders)
#    2. Nazario Phishing Corpus     (raw .eml phishing files)
#    3. Kaggle CEAS/Fraud Corpus    (CSV format)
#    4. PhishTank URL dataset       (JSON — for URL scanner)
#    5. Manual Kenya-specific       (custom CSV you build over time)
#
#  OUTPUT:
#    backend/ml/datasets/combined_dataset.csv
#    Columns: text (str), label (int: 0=safe, 1=phishing), source (str)
#
#  USAGE:
#    cd ~/code/phishguard
#    source .venv/bin/activate
#    python backend/scripts/prepare_datasets.py --help
#    python backend/scripts/prepare_datasets.py --all
#    python backend/scripts/prepare_datasets.py --spamassassin path/to/folder
# =============================================================

import os
import re
import csv
import sys
import json
import email
import gzip
import tarfile
import logging
import argparse
import random
from pathlib import Path
from typing import List, Tuple, Optional
from email import policy
from email.parser import BytesParser, Parser

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Output path ───────────────────────────────────────────────
# All paths are relative to the project root (~/code/phishguard)
PROJECT_ROOT  = Path(__file__).resolve().parent.parent.parent
DATASETS_DIR  = PROJECT_ROOT / "backend" / "ml" / "datasets"
OUTPUT_CSV    = DATASETS_DIR / "combined_dataset.csv"
DATASETS_DIR.mkdir(parents=True, exist_ok=True)


# =============================================================
#  EMAIL PARSING UTILITIES
# =============================================================

def parse_raw_email(raw: str) -> str:
    """
    Extracts clean, readable text from a raw email string.

    Raw emails contain headers, MIME boundaries, base64-encoded
    parts, and HTML markup that we do not want in our training
    data — we want the CONTENT, the words, the message.

    This function:
      1. Parses the MIME structure to find text parts
      2. Prefers plain text over HTML when both exist
      3. Strips HTML tags from HTML-only emails
      4. Decodes quoted-printable and base64 encoding
      5. Concatenates subject + body for richer signal

    Why include the subject line?
      "URGENT: Your account has been suspended" is a phishing
      signal entirely contained in the subject. Ignoring it
      would lose one of the strongest single-line indicators.
    """
    try:
        msg = Parser(policy=policy.default).parsestr(raw)
    except Exception:
        # If parsing fails, return raw text with headers stripped
        return _strip_headers(raw)

    # Collect subject as part of the text
    subject = msg.get("subject", "") or ""
    subject = _decode_header_value(subject)

    # Walk the MIME tree collecting text parts
    plain_parts = []
    html_parts  = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
            except Exception:
                continue

            if ctype == "text/plain":
                plain_parts.append(text)
            elif ctype == "text/html":
                html_parts.append(_strip_html(text))
    else:
        # Single-part message
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
                ctype = msg.get_content_type()
                if ctype == "text/html":
                    html_parts.append(_strip_html(text))
                else:
                    plain_parts.append(text)
        except Exception:
            plain_parts.append(str(msg.get_payload()))

    # Prefer plain text; fall back to stripped HTML
    body_parts = plain_parts if plain_parts else html_parts
    body = " ".join(body_parts)

    # Combine subject + body — subject is a rich signal
    full_text = f"{subject} {body}".strip()

    # Normalise whitespace
    full_text = re.sub(r'\s+', ' ', full_text)

    return full_text[:50000]  # cap at 50K chars to prevent memory issues


def _decode_header_value(value: str) -> str:
    """Decodes RFC2047 encoded email headers (=?UTF-8?B?...?=)."""
    from email.header import decode_header
    try:
        parts = decode_header(value)
        decoded = []
        for part, charset in parts:
            if isinstance(part, bytes):
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                decoded.append(str(part))
        return " ".join(decoded)
    except Exception:
        return value


def _strip_html(html: str) -> str:
    """Removes HTML tags, leaving readable text content."""
    # Remove script and style blocks entirely
    html = re.sub(r'<(script|style)[^>]*>.*?</(script|style)>', ' ', html,
                  flags=re.DOTALL | re.IGNORECASE)
    # Remove all remaining tags
    html = re.sub(r'<[^>]+>', ' ', html)
    # Decode common HTML entities
    html = html.replace("&nbsp;", " ").replace("&amp;", "&")
    html = html.replace("&lt;", "<").replace("&gt;", ">")
    html = html.replace("&quot;", '"').replace("&#39;", "'")
    return html


def _strip_headers(raw: str) -> str:
    """
    Fallback: removes email headers from raw text by finding
    the first blank line (which separates headers from body
    in RFC 2822 email format).
    """
    lines = raw.split("\n")
    body_start = 0
    for i, line in enumerate(lines):
        if line.strip() == "":
            body_start = i + 1
            break
    return " ".join(lines[body_start:])


def is_valid_sample(text: str, min_words: int = 5) -> bool:
    """
    Rejects samples that are too short to be useful for training.
    A 3-word email cannot teach the model anything reliable.
    """
    return len(text.split()) >= min_words


# =============================================================
#  DATASET LOADERS
#  One function per dataset format.
#  Each returns: List[Tuple[str, int, str]]
#    (text, label, source_name)
# =============================================================

def load_spamassassin(base_path: str) -> List[Tuple[str, int, str]]:
    """
    Loads the SpamAssassin Public Corpus.

    Directory structure expected:
      base_path/
        spam/           ← spam emails (we label as phishing=1)
        easy_ham/       ← legitimate emails (label=0)
        hard_ham/       ← legitimate but spam-like emails (label=0)

    Download from:
      https://spamassassin.apache.org/old/publiccorpus/
      Get: 20030228_spam.tar.bz2, 20030228_easy_ham.tar.bz2
      Extract both into the same base_path folder.

    CONCEPT: Why spam ≠ phishing but is still useful
      Spam is unsolicited bulk email. Phishing is targeted
      deception. They overlap heavily in linguistic patterns —
      urgency, lures, suspicious links — which is why spam
      datasets improve phishing detection even though the
      labels are not identical.
    """
    samples = []
    base = Path(base_path)

    # Map folder name → label
    folder_labels = {
        "spam":     1,  # treat spam as phishing-like
        "spam_2":   1,
        "easy_ham": 0,
        "hard_ham": 0,
    }

    for folder_name, label in folder_labels.items():
        folder = base / folder_name
        if not folder.exists():
            logger.debug("SpamAssassin folder not found: %s — skipping", folder)
            continue

        count = 0
        for filepath in folder.iterdir():
            if not filepath.is_file():
                continue
            try:
                # SpamAssassin files are raw RFC 2822 email format
                raw = filepath.read_text(encoding="utf-8", errors="replace")
                text = parse_raw_email(raw)
                if is_valid_sample(text):
                    samples.append((text, label, "spamassassin"))
                    count += 1
            except Exception as e:
                logger.debug("Error reading %s: %s", filepath, e)

        logger.info("SpamAssassin %-12s → %d samples (label=%d)", folder_name, count, label)

    return samples


def load_nazario(base_path: str) -> List[Tuple[str, int, str]]:
    """
    Loads the Nazario Phishing Email Corpus.

    All files in this corpus are real phishing emails → label=1.

    Download:
      git clone https://github.com/rf-/phishing-emails
      Pass the cloned directory as base_path.

    Why this dataset is valuable:
      Unlike academic datasets with synthetic phishing samples,
      Nazario collected actual emails from live phishing campaigns.
      They contain real attacker infrastructure, real brand
      impersonation, and real social engineering language —
      exactly what your model needs to recognise.
    """
    samples = []
    base = Path(base_path)

    if not base.exists():
        logger.warning("Nazario path not found: %s — skipping", base_path)
        return samples

    # Walk all files recursively — corpus has subdirectories
    for filepath in base.rglob("*"):
        if not filepath.is_file():
            continue
        # Skip git metadata, README files etc.
        if filepath.suffix in (".md", ".txt", ".py", ".json") and filepath.name != "":
            if filepath.name.lower() in ("readme.md", "readme.txt", "license"):
                continue

        try:
            raw = filepath.read_text(encoding="utf-8", errors="replace")
            text = parse_raw_email(raw)
            if is_valid_sample(text):
                samples.append((text, 1, "nazario"))
        except Exception as e:
            logger.debug("Error reading %s: %s", filepath, e)

    logger.info("Nazario corpus → %d phishing samples", len(samples))
    return samples


def load_csv_dataset(
    csv_path: str,
    text_column: str,
    label_column: str,
    phishing_value,
    source_name: str,
    max_rows: Optional[int] = None,
) -> List[Tuple[str, int, str]]:
    """
    Generic CSV loader. Works for any CSV-format dataset.

    Args:
        csv_path:      Path to the CSV file
        text_column:   Name of the column containing email text
        label_column:  Name of the column containing the label
        phishing_value: The value in label_column that means "phishing"
                        e.g. "1", "spam", "phishing", True
        source_name:   A string tag identifying this dataset
        max_rows:      Optional limit (useful for very large datasets)

    Handles:
      - Kaggle CEAS phishing dataset
      - Enron email dataset (if pre-processed to CSV)
      - Any other CSV with text + label columns
    """
    samples = []
    csv_path = Path(csv_path)

    if not csv_path.exists():
        logger.warning("CSV not found: %s — skipping", csv_path)
        return samples

    # Detect if gzipped
    open_fn = gzip.open if str(csv_path).endswith(".gz") else open

    try:
        with open_fn(csv_path, "rt", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)

            for i, row in enumerate(reader):
                if max_rows and i >= max_rows:
                    break

                text = row.get(text_column, "").strip()
                raw_label = row.get(label_column, "").strip()

                if not text:
                    continue

                # Flexible label comparison — handle int/string/bool
                is_phishing = str(raw_label).lower() == str(phishing_value).lower()
                label = 1 if is_phishing else 0

                if is_valid_sample(text):
                    samples.append((text, label, source_name))

    except Exception as e:
        logger.error("Error loading CSV %s: %s", csv_path, e)

    phishing_count = sum(1 for _, l, _ in samples if l == 1)
    safe_count     = len(samples) - phishing_count
    logger.info(
        "%-25s → %d total (%d phishing, %d safe)",
        source_name, len(samples), phishing_count, safe_count
    )
    return samples


def load_kenya_dataset(csv_path: str) -> List[Tuple[str, int, str]]:
    """
    Loads your manually curated Kenya-specific phishing dataset.

    Format: CSV with columns: text, label (1=phishing, 0=safe), notes
    You build this CSV over time by:
      - Collecting real MPESA scam messages
      - Adding fake KRA notice text
      - Recording Safaricom impersonation SMS examples
      - Documenting eCitizen phishing page copy

    Even 200-300 high-quality Kenya-specific examples will
    meaningfully improve detection of local threats, because
    these patterns appear in no other dataset.

    Start by creating the file manually:
      backend/ml/datasets/kenya_phishing.csv
    with headers: text,label,notes
    """
    path = Path(csv_path)
    if not path.exists():
        logger.info(
            "Kenya dataset not found at %s — "
            "create it manually to add local threat context.", csv_path
        )
        return []

    return load_csv_dataset(
        csv_path=csv_path,
        text_column="text",
        label_column="label",
        phishing_value="1",
        source_name="kenya_custom",
    )


# =============================================================
#  DATASET BALANCING
# =============================================================

def balance_dataset(
    samples: List[Tuple[str, int, str]],
    strategy: str = "oversample",
    ratio: float = 1.5,
) -> List[Tuple[str, int, str]]:
    """
    Balances the dataset so phishing and safe classes are
    reasonably proportioned.

    CONCEPT: Why balance matters
      If your dataset is 90% safe emails and 10% phishing,
      a model that predicts "safe" for EVERYTHING achieves
      90% accuracy — without learning anything useful.
      The class_weight="balanced" in your RandomForest helps,
      but starting with a better-balanced dataset is cleaner.

    Strategies:
      "oversample": duplicate minority class samples until
                    the minority:majority ratio >= 1:ratio
                    Simple but effective for small datasets.

      "undersample": remove majority class samples.
                     Loses data — only use if majority is
                     vastly larger (10x+).

    Args:
        samples:  list of (text, label, source) tuples
        strategy: "oversample" or "undersample"
        ratio:    target minority:majority ratio (1.5 = 3:2)
    """
    phishing = [(t, l, s) for t, l, s in samples if l == 1]
    safe     = [(t, l, s) for t, l, s in samples if l == 0]

    n_phish  = len(phishing)
    n_safe   = len(safe)

    logger.info(
        "Pre-balance: %d phishing, %d safe (ratio 1:%.1f)",
        n_phish, n_safe, n_safe / max(n_phish, 1)
    )

    if strategy == "oversample" and n_phish < n_safe:
        # How many phishing samples do we need?
        target_phish = int(n_safe / ratio)
        if target_phish > n_phish:
            # Repeat the phishing list with random sampling
            extra = random.choices(phishing, k=target_phish - n_phish)
            phishing = phishing + extra
            logger.info("Oversampled phishing: %d → %d", n_phish, len(phishing))

    elif strategy == "undersample" and n_safe > n_phish * ratio * 2:
        # Only undersample if safe is dramatically larger
        target_safe = int(n_phish * ratio)
        safe = random.sample(safe, target_safe)
        logger.info("Undersampled safe: %d → %d", n_safe, len(safe))

    balanced = phishing + safe
    random.shuffle(balanced)

    n_phish_final = sum(1 for _, l, _ in balanced if l == 1)
    n_safe_final  = len(balanced) - n_phish_final
    logger.info(
        "Post-balance: %d phishing, %d safe (ratio 1:%.1f)",
        n_phish_final, n_safe_final, n_safe_final / max(n_phish_final, 1)
    )

    return balanced


# =============================================================
#  DEDUPLICATION
# =============================================================

def deduplicate(samples: List[Tuple[str, int, str]]) -> List[Tuple[str, int, str]]:
    """
    Removes duplicate email texts.

    Duplicates in training data are harmful because they cause
    the model to overweight patterns that happen to appear in
    duplicated examples. If the same email appears 100 times
    in your training data, the model effectively treats it as
    100x more important than unique examples.

    We use the first 200 characters as a fingerprint — fast
    and effective for detecting duplicate emails without
    full-text comparison.
    """
    seen     = set()
    unique   = []
    removed  = 0

    for text, label, source in samples:
        # Use first 200 chars as fingerprint (fast, effective)
        fingerprint = text[:200].strip().lower()
        if fingerprint not in seen:
            seen.add(fingerprint)
            unique.append((text, label, source))
        else:
            removed += 1

    logger.info("Deduplication: removed %d duplicates, kept %d", removed, len(unique))
    return unique


# =============================================================
#  SAVE COMBINED DATASET
# =============================================================

def save_combined_csv(
    samples: List[Tuple[str, int, str]],
    output_path: Path,
) -> None:
    """
    Saves the consolidated dataset to a CSV file.

    Columns:
      text   — the email text (cleaned, decoded)
      label  — 0 = safe, 1 = phishing
      source — which dataset this sample came from

    The source column is not used by the trainer but is
    invaluable for debugging: if your model performs poorly
    on a specific type of threat, you can filter by source
    to see if that threat type is underrepresented.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        writer.writerow(["text", "label", "source"])
        for text, label, source in samples:
            # Replace newlines in text to keep CSV well-formed
            clean_text = text.replace("\n", " ").replace("\r", " ")
            writer.writerow([clean_text, label, source])

    size_mb = output_path.stat().st_size / (1024 * 1024)
    logger.info(
        "Saved %d samples to %s (%.1f MB)",
        len(samples), output_path, size_mb
    )

    # Print source breakdown
    source_counts = {}
    for _, _, src in samples:
        source_counts[src] = source_counts.get(src, 0) + 1
    logger.info("Source breakdown:")
    for src, count in sorted(source_counts.items(), key=lambda x: -x[1]):
        logger.info("  %-25s %d", src, count)


# =============================================================
#  MAIN CLI
# =============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Prepare PhishGuard training datasets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process all available datasets and combine them:
  python backend/scripts/prepare_datasets.py --all

  # Process just SpamAssassin:
  python backend/scripts/prepare_datasets.py \\
      --spamassassin ~/Downloads/spamassassin/

  # Process SpamAssassin + Nazario:
  python backend/scripts/prepare_datasets.py \\
      --spamassassin ~/Downloads/spamassassin/ \\
      --nazario ~/Downloads/phishing-emails/

  # Include a Kaggle CSV dataset:
  python backend/scripts/prepare_datasets.py \\
      --csv ~/Downloads/emails.csv \\
      --csv-text-col text \\
      --csv-label-col label \\
      --csv-phishing-value 1 \\
      --csv-source kaggle_ceas

Dataset download instructions:
  SpamAssassin: https://spamassassin.apache.org/old/publiccorpus/
    Download: 20030228_spam.tar.bz2 and 20030228_easy_ham.tar.bz2
    Extract both to the same folder, then pass that folder path.

  Nazario:  git clone https://github.com/rf-/phishing-emails

  Kaggle CEAS / Fraud Corpus:
    https://www.kaggle.com/datasets/rtatman/fraudulent-email-corpus
    Download emails.csv, then use --csv with appropriate column names.

  Kenya custom: Create backend/ml/datasets/kenya_phishing.csv manually
    with columns: text, label (1=phishing/0=safe), notes
        """
    )

    parser.add_argument("--all", action="store_true",
        help="Process all datasets found in default locations")
    parser.add_argument("--spamassassin", type=str, metavar="PATH",
        help="Path to SpamAssassin corpus directory")
    parser.add_argument("--nazario", type=str, metavar="PATH",
        help="Path to cloned Nazario phishing-emails repo")
    parser.add_argument("--csv", type=str, metavar="PATH",
        help="Path to a CSV dataset file")
    parser.add_argument("--csv-text-col", type=str, default="text",
        help="Column name for email text in CSV (default: text)")
    parser.add_argument("--csv-label-col", type=str, default="label",
        help="Column name for label in CSV (default: label)")
    parser.add_argument("--csv-phishing-value", type=str, default="1",
        help="Label value that means phishing (default: 1)")
    parser.add_argument("--csv-source", type=str, default="csv_dataset",
        help="Source tag for CSV dataset (default: csv_dataset)")
    parser.add_argument("--output", type=str, default=str(OUTPUT_CSV),
        help=f"Output CSV path (default: {OUTPUT_CSV})")
    parser.add_argument("--no-balance", action="store_true",
        help="Skip dataset balancing")
    parser.add_argument("--no-dedup", action="store_true",
        help="Skip deduplication")
    parser.add_argument("--seed", type=int, default=42,
        help="Random seed for reproducibility (default: 42)")

    args = parser.parse_args()

    random.seed(args.seed)

    if not any([args.all, args.spamassassin, args.nazario, args.csv]):
        parser.print_help()
        sys.exit(1)

    all_samples = []

    # ── Load SpamAssassin ──────────────────────────────────
    spamassassin_path = args.spamassassin
    if args.all and not spamassassin_path:
        # Check default location
        default = Path.home() / "Downloads" / "spamassassin"
        if default.exists():
            spamassassin_path = str(default)

    if spamassassin_path:
        logger.info("Loading SpamAssassin from: %s", spamassassin_path)
        all_samples.extend(load_spamassassin(spamassassin_path))

    # ── Load Nazario ──────────────────────────────────────
    nazario_path = args.nazario
    if args.all and not nazario_path:
        default = Path.home() / "Downloads" / "phishing-emails"
        if default.exists():
            nazario_path = str(default)

    if nazario_path:
        logger.info("Loading Nazario corpus from: %s", nazario_path)
        all_samples.extend(load_nazario(nazario_path))

    # ── Load CSV dataset ──────────────────────────────────
    if args.csv:
        logger.info("Loading CSV dataset from: %s", args.csv)
        all_samples.extend(load_csv_dataset(
            csv_path=args.csv,
            text_column=args.csv_text_col,
            label_column=args.csv_label_col,
            phishing_value=args.csv_phishing_value,
            source_name=args.csv_source,
        ))

    # ── Load Kenya custom dataset (always if exists) ──────
    kenya_path = DATASETS_DIR / "kenya_phishing.csv"
    kenya_samples = load_kenya_dataset(str(kenya_path))
    all_samples.extend(kenya_samples)

    if not all_samples:
        logger.error(
            "No samples loaded. Download datasets and pass their paths. "
            "Run: python backend/scripts/prepare_datasets.py --help"
        )
        sys.exit(1)

    logger.info("Total raw samples: %d", len(all_samples))

    # ── Deduplicate ────────────────────────────────────────
    if not args.no_dedup:
        all_samples = deduplicate(all_samples)

    # ── Balance ────────────────────────────────────────────
    if not args.no_balance:
        all_samples = balance_dataset(all_samples)

    # ── Save ───────────────────────────────────────────────
    save_combined_csv(all_samples, Path(args.output))
    logger.info("Done. Next step: python backend/scripts/train_model.py")


if __name__ == "__main__":
    main()
