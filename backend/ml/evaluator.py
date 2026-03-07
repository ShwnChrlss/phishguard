# =============================================================
#  backend/ml/evaluator.py
#  Model Evaluation & Reporting
# =============================================================
#
#  CONCEPT: Why evaluation deserves its own file
#
#  Training a model is only half the work. Evaluation answers:
#    - How accurate is it REALLY on unseen data?
#    - WHERE does it go wrong? (which email types does it miss?)
#    - Is it improving or degrading over time?
#    - Should we swap to a different algorithm?
#
#  This file provides tools to answer all of those questions
#  without cluttering trainer.py.
#
#  CONCEPT: The Confusion Matrix in depth
#
#    Actual →     SAFE       PHISHING
#    Predicted ↓
#    SAFE         TN          FN ← MISSED phishing (dangerous!)
#    PHISHING     FP ← false  TP ← correctly caught
#                 alarm
#
#    TN (True Negative):   Safe email, correctly labelled safe. ✅
#    TP (True Positive):   Phishing, correctly caught. ✅
#    FP (False Positive):  Safe email wrongly flagged. ⚠️ annoys users
#    FN (False Negative):  Phishing that slipped through. 🚨 dangerous!
#
#    For a security system, FN is the most critical error.
#    A missed phishing email can lead to a data breach.
#    We tune the model to minimise FN even at the cost of
#    slightly more FP (users see a few more false alarms).
# =============================================================

import os
import json
import logging
import numpy as np
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class ModelEvaluator:
    """
    Evaluates a trained PhishingModelTrainer on labelled data
    and generates human-readable reports.

    Usage:
        evaluator = ModelEvaluator(trainer)
        report = evaluator.full_report(test_emails, test_labels)
        evaluator.print_report(report)
        evaluator.save_report(report, "ml/reports/")
    """

    def __init__(self, trainer):
        """
        Args:
            trainer: A trained PhishingModelTrainer instance.
        """
        if not trainer.is_trained:
            raise ValueError("Trainer must be trained before evaluation.")
        self.trainer = trainer

    def full_report(
        self,
        emails: List[str],
        labels: List[int],
    ) -> Dict:
        """
        Runs the model on labelled emails and returns a comprehensive
        evaluation report dictionary.

        Args:
            emails: List of email strings (test set).
            labels: List of 0/1 labels (ground truth).

        Returns:
            Dict with accuracy, confusion matrix, per-class metrics,
            feature importance, and worst mistakes.
        """
        logger.info("Evaluating on %d emails...", len(emails))

        # Get predictions and probabilities for each email
        results = [self.trainer.predict(email) for email in emails]

        predictions   = [1 if r["is_phishing"] else 0 for r in results]
        probabilities = [r["risk_score"] / 100                for r in results]

        report = {
            "evaluated_at":    datetime.now().isoformat(),
            "n_samples":       len(emails),
            "n_phishing":      sum(labels),
            "n_safe":          len(labels) - sum(labels),
            "metrics":         self.trainer._compute_metrics(
                                    labels, predictions, np.array(probabilities)
                               ),
            "feature_importance": self._feature_importance(top_n=20),
            "error_analysis":  self._error_analysis(emails, labels, results),
            "threshold_analysis": self._threshold_analysis(labels, probabilities),
        }

        return report

    def _feature_importance(self, top_n: int = 20) -> List[Dict]:
        """
        Returns the top N most important features from the Random Forest.

        CONCEPT: Feature Importance in Random Forests
          Each tree in the forest splits on features that best
          separate phishing from safe. A feature used for many
          high-up splits (close to the root) is very important.
          scikit-learn tracks this and exposes it as
          .feature_importances_ — an array where higher = more
          important for making the right prediction.

          This tells you: "the model relies heavily on 'url_count'
          and 'urgency_word_count' to make decisions" — which
          confirms our feature engineering was on the right track.
        """
        classifier = self.trainer.classifier
        feature_names = self.trainer.feature_names

        # RandomForest has feature_importances_; GradientBoosting too
        if not hasattr(classifier, "feature_importances_"):
            return []

        importances = classifier.feature_importances_

        if not feature_names or len(feature_names) != len(importances):
            # Fall back to generic names if mismatch
            feature_names = [f"feature_{i}" for i in range(len(importances))]

        # Sort by importance descending, take top N
        top_indices = np.argsort(importances)[::-1][:top_n]

        return [
            {
                "rank":       int(rank + 1),
                "feature":    feature_names[i],
                "importance": round(float(importances[i]), 6),
            }
            for rank, i in enumerate(top_indices)
        ]

    def _error_analysis(
        self,
        emails: List[str],
        labels: List[int],
        results: List[Dict],
    ) -> Dict:
        """
        Identifies where the model makes mistakes.

        CONCEPT: Error Analysis
          Looking at your WRONG predictions teaches you more than
          looking at your right ones. If false negatives (missed
          phishing) all share a pattern — maybe they're written
          in perfect grammar and have no urgency words — you know
          what to improve next (more training data of that type,
          new features, etc.).

        Returns dicts of:
          false_negatives: phishing emails we missed (most critical)
          false_positives: safe emails we wrongly flagged
        """
        false_negatives = []  # phishing missed — most dangerous
        false_positives = []  # safe emails flagged — false alarms

        for email, label, result in zip(emails, labels, results):
            predicted = 1 if result["is_phishing"] else 0

            if label == 1 and predicted == 0:
                # Phishing that slipped through
                false_negatives.append({
                    "email_preview": email[:120] + "...",
                    "risk_score":    result["risk_score"],
                    "confidence":    result["confidence"],
                    "why_missed":    "Low risk score — model was not confident enough",
                })

            elif label == 0 and predicted == 1:
                # Safe email wrongly flagged
                false_positives.append({
                    "email_preview": email[:120] + "...",
                    "risk_score":    result["risk_score"],
                    "explanation":   result["explanation"],
                })

        return {
            "false_negative_count": len(false_negatives),
            "false_positive_count": len(false_positives),
            "false_negatives_sample": false_negatives[:5],   # show up to 5
            "false_positives_sample": false_positives[:5],
        }

    def _threshold_analysis(
        self,
        labels: List[int],
        probabilities: List[float],
    ) -> List[Dict]:
        """
        Tests different decision thresholds and reports their effect.

        CONCEPT: Classification Threshold
          By default, the model predicts "phishing" if
          phishing_probability >= 0.5 (50%).

          But you can TUNE this:
            Lower threshold (e.g. 0.3) → catch MORE phishing
              (higher recall) but flag more safe emails (lower precision)
            Higher threshold (e.g. 0.7) → fewer false alarms
              (higher precision) but miss more phishing (lower recall)

          For a security system, we usually prefer a LOWER threshold
          (catch more, tolerate some false alarms) because missing
          real phishing is more dangerous than annoying users with
          occasional false positives.

          This analysis lets you pick the best threshold for your
          organisation's risk tolerance.
        """
        from sklearn.metrics import precision_score, recall_score, f1_score

        thresholds = [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
        results = []

        for threshold in thresholds:
            predicted = [1 if p >= threshold else 0 for p in probabilities]
            p = round(precision_score(labels, predicted, zero_division=0), 3)
            r = round(recall_score(labels, predicted, zero_division=0), 3)
            f = round(f1_score(labels, predicted, zero_division=0), 3)
            caught   = sum(1 for l, pred in zip(labels, predicted) if l == 1 and pred == 1)
            total_ph = sum(labels)
            results.append({
                "threshold":  threshold,
                "precision":  p,
                "recall":     r,
                "f1":         f,
                "phishing_caught":  f"{caught}/{total_ph}",
            })

        return results

    def print_report(self, report: Dict) -> None:
        """Prints a formatted evaluation summary to the terminal."""
        m  = report["metrics"]
        ea = report["error_analysis"]

        divider = "═" * 50
        print(f"\n{divider}")
        print("  📊  MODEL EVALUATION REPORT")
        print(divider)
        print(f"  Evaluated : {report['evaluated_at']}")
        print(f"  Samples   : {report['n_samples']} "
              f"({report['n_phishing']} phishing, {report['n_safe']} safe)")
        print(divider)
        print(f"  Accuracy  : {m['accuracy']*100:.1f}%")
        print(f"  Precision : {m['precision']*100:.1f}%")
        print(f"  Recall    : {m['recall']*100:.1f}%  ← % of phishing caught")
        print(f"  F1 Score  : {m['f1_score']*100:.1f}%")
        print(f"  ROC-AUC   : {m['roc_auc']:.4f}")
        print(divider)
        print("  Confusion Matrix:")
        cm = m["confusion_matrix"]
        print(f"              Pred Safe   Pred Phish")
        print(f"  Real Safe   {cm[0][0]:>8}   {cm[0][1]:>10}")
        print(f"  Real Phish  {cm[1][0]:>8}   {cm[1][1]:>10}")
        print(divider)
        print(f"  False Negatives (MISSED phishing): {ea['false_negative_count']}")
        print(f"  False Positives (false alarms)   : {ea['false_positive_count']}")
        print(divider)

        print("\n  Top 10 Most Important Features:")
        for feat in report["feature_importance"][:10]:
            bar = "█" * int(feat["importance"] * 500)
            print(f"  {feat['rank']:>2}. {feat['feature']:<35} {bar}")

        print(f"\n{divider}")
        print("  Threshold Analysis (tune for your risk tolerance):")
        print(f"  {'Threshold':>9}  {'Precision':>9}  {'Recall':>6}  "
              f"{'F1':>4}  {'Caught':>8}")
        for row in report["threshold_analysis"]:
            print(f"  {row['threshold']:>9.1f}  {row['precision']:>9.3f}  "
                  f"{row['recall']:>6.3f}  {row['f1']:>4.3f}  "
                  f"{row['phishing_caught']:>8}")
        print(divider + "\n")

    def save_report(self, report: Dict, directory: str) -> str:
        """
        Saves the evaluation report as a JSON file.

        Args:
            report:    The dict returned by full_report().
            directory: Where to save (e.g. "ml/reports/").

        Returns:
            Full path of the saved file.
        """
        os.makedirs(directory, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(directory, f"eval_{timestamp}.json")

        with open(path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        logger.info("Evaluation report saved to: %s", path)
        return path