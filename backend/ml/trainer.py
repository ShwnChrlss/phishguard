# =============================================================
#  backend/ml/trainer.py
#  Machine Learning Training Pipeline
# =============================================================
#
#  CONCEPT: The ML Pipeline
#
#  Raw Email Text
#       │
#       ├─── TfidfVectorizer ──→ word importance scores (sparse matrix)
#       │                        e.g. {"click": 0.8, "verify": 0.6, ...}
#       │
#       ├─── EmailFeatureExtractor ──→ hand-crafted numbers
#       │                              e.g. [3, 1, 0, 0.4, 2, ...]
#       │
#       └─── numpy.hstack() ──→ ONE combined feature row per email
#                               [tfidf_scores... | manual_features...]
#                               shape: (n_emails, n_tfidf + n_manual)
#                                       ≈ (n_emails, 5025)
#
#  That matrix gets fed to RandomForestClassifier.fit()
#  The model learns which combinations → phishing vs safe.
#
#  CONCEPT: TF-IDF (Term Frequency - Inverse Document Frequency)
#
#    TF (Term Frequency):
#      How often does "urgent" appear in THIS email?
#      If "urgent" appears 5 times in a 100-word email → TF = 0.05
#
#    IDF (Inverse Document Frequency):
#      How rare is "urgent" across ALL emails?
#      If "urgent" appears in 10 of 1000 emails:
#        IDF = log(1000/10) = log(100) ≈ 4.6
#      Common words ("the", "and") have low IDF ≈ 0.
#      Rare words ("cryptocurrency") have high IDF.
#
#    TF-IDF = TF × IDF
#      Words that appear often in THIS email but rarely in
#      others get a HIGH score → they characterise this email.
#
#    ngram_range=(1,2) means we look at:
#      Single words:  "urgent", "verify", "account"
#      Word pairs:    "urgent verify", "verify account", "click here"
#      "click here" as a pair is more suspicious than "click" or
#      "here" alone — capturing context improves accuracy.
#
#  CONCEPT: Random Forest
#
#    A single Decision Tree asks yes/no questions:
#      "Does it have > 2 urgency words?"
#        YES → "Does it have an IP URL?"
#               YES → PHISHING (95% confidence)
#               NO  → "Is caps_ratio > 0.3?" → ...
#        NO  → SAFE
#
#    Problem: one tree overfits. It memorises training data
#    perfectly but fails on new emails.
#
#    Random Forest = 200 trees, each trained on a random
#    SUBSET of the data and a random SUBSET of features.
#    Each tree makes its own prediction. The forest takes
#    a majority vote. 
#    Majority vote cancels out individual tree errors
#    → much more reliable on new, unseen emails.
#
#  CONCEPT: Train/Test Split
#
#    If you test accuracy on the same data you trained on,
#    you get ~100% — the model just memorised the answers.
#    That's like studying past exam papers and measuring
#    how well you can repeat them verbatim.
#
#    The real question: how does it do on NEW data it's
#    never seen? We hold out 20% of data before training,
#    train on 80%, then test on the held-out 20%.
#
#    stratify=labels ensures BOTH splits have the same
#    ratio of phishing:safe emails. Without this, your
#    test set might accidentally be 100% safe emails.
# =============================================================

import os
import sys
import logging
import numpy as np
import joblib
from datetime import datetime
from typing import List, Tuple, Dict, Optional

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

# Import our hand-crafted feature extractor
from ml.features import EmailFeatureExtractor

logger = logging.getLogger(__name__)


# =============================================================
#  MODEL REGISTRY
#  Maps model name strings to sklearn classes.
#  Lets callers choose a model without importing sklearn directly.
# =============================================================

AVAILABLE_MODELS = {
    "random_forest": RandomForestClassifier,
    "gradient_boosting": GradientBoostingClassifier,
}


# =============================================================
#  PHISHING TRAINER CLASS
# =============================================================

class PhishingModelTrainer:
    """
    Manages the full ML lifecycle:
      1. Preprocess text
      2. Extract features (TF-IDF + hand-crafted)
      3. Train classifier
      4. Evaluate performance
      5. Save model to disk

    Designed so you can swap the classifier (Random Forest →
    Gradient Boosting → SVM) without changing anything else.
    """

    def __init__(
        self,
        model_name:    str = "random_forest",
        tfidf_max_features: int = 5000,
        test_size:     float = 0.2,
        random_state:  int = 42,
    ):
        """
        Args:
            model_name:         "random_forest" or "gradient_boosting"
            tfidf_max_features: Vocabulary size. 5000 = keep only the
                                 5000 most informative words.
                                 Larger = more accurate but slower.
            test_size:          Fraction held out for evaluation.
                                 0.2 = 20% test, 80% train.
            random_state:       Seed for reproducibility. Using the
                                 same seed = same train/test split
                                 every time = comparable experiments.
        """
        self.model_name   = model_name
        self.test_size    = test_size
        self.random_state = random_state

        # ── TF-IDF VECTORIZER ─────────────────────────────────
        # max_features=5000: after scanning all training emails,
        #   keep only the 5000 words with the highest TF-IDF scores.
        #   Discarding rare/uninformative words reduces noise.
        #
        # ngram_range=(1, 2): extract single words AND word pairs.
        #   "click here" together is a stronger signal than
        #   "click" and "here" separately.
        #
        # stop_words="english": ignore "the", "a", "is", "and" etc.
        #   These add noise — every email uses them equally.
        #
        # sublinear_tf=True: apply log(1+tf) instead of raw tf.
        #   Prevents words that appear 100 times from dominating
        #   over words that appear 5 times. Compresses the scale.
        #
        # min_df=2: ignore words that appear in fewer than 2 emails.
        #   Typos and very rare words aren't useful signals.
        self.tfidf = TfidfVectorizer(
            max_features=tfidf_max_features,
            ngram_range=(1, 2),
            stop_words="english",
            sublinear_tf=True,
            min_df=2,
            analyzer="word",
            token_pattern=r"\b[a-zA-Z][a-zA-Z0-9]{1,}\b",
        )

        # ── HAND-CRAFTED FEATURE EXTRACTOR ────────────────────
        self.feature_extractor = EmailFeatureExtractor()

        # ── CLASSIFIER ────────────────────────────────────────
        self.classifier = self._build_classifier(model_name)

        # ── STATE ─────────────────────────────────────────────
        # These get populated after calling .train()
        self.is_trained:       bool = False
        self.training_metrics: Dict = {}
        self.feature_names:    List[str] = []
        self.trained_at:       Optional[str] = None

    def _build_classifier(self, name: str):
        """
        Builds and returns the chosen classifier with tuned
        hyperparameters.

        CONCEPT: Hyperparameters
          Regular parameters are LEARNED during training (e.g. the
          decision boundaries in each tree). Hyperparameters are
          settings you choose BEFORE training that control HOW
          training happens.

          n_estimators=200: number of trees. More = better accuracy
            up to a point, then diminishing returns. 200 is a good
            balance of accuracy vs training time.

          max_depth=20: how deep each tree can grow. Unlimited depth
            → overfitting (memorises training data). Capped depth
            → better generalisation to new emails.

          min_samples_split=5: a tree node must have at least 5
            emails before it splits further. Prevents tiny splits
            that only fit noise in training data.

          class_weight="balanced": our dataset might have more safe
            emails than phishing ones (imbalanced classes). "balanced"
            automatically increases the penalty for misclassifying
            the minority class (phishing). This prevents the model
            from just predicting "safe" for everything.

          n_jobs=-1: use ALL available CPU cores for training.
            Random forests are embarrassingly parallel — each tree
            can be trained independently.
        """
        if name not in AVAILABLE_MODELS:
            raise ValueError(
                f"Unknown model '{name}'. Choose from: {list(AVAILABLE_MODELS)}"
            )

        if name == "random_forest":
            return RandomForestClassifier(
                n_estimators=200,       # 200 trees voting
                max_depth=20,           # max tree depth
                min_samples_split=5,    # minimum emails per split
                min_samples_leaf=2,     # minimum emails per leaf
                max_features="sqrt",    # features per split = √(total)
                class_weight="balanced",
                random_state=self.random_state,
                n_jobs=-1,
            )
        elif name == "gradient_boosting":
            # Gradient Boosting builds trees SEQUENTIALLY.
            # Each tree corrects the mistakes of the previous one.
            # Often more accurate than Random Forest but slower.
            return GradientBoostingClassifier(
                n_estimators=150,
                max_depth=5,
                learning_rate=0.1,      # how much each tree corrects
                subsample=0.8,          # use 80% of data per tree
                random_state=self.random_state,
            )

    def _prepare_features(
        self,
        emails: List[str],
        fit: bool = False
    ) -> np.ndarray:
        """
        Converts email text into a numeric feature matrix.

        CONCEPT: fit vs transform
          TF-IDF needs two steps:
            fit()       → scan all emails, learn vocabulary + IDF scores
            transform() → convert emails to TF-IDF matrix

          During TRAINING:  fit=True  → fit_transform() (learn + convert)
          During PREDICTION: fit=False → transform() only (use learned vocab)

          Why not re-fit on prediction data?
          If you fit on new emails, the vocabulary changes. Words that
          weren't in training data get new indices. The model trained
          on the OLD indices produces nonsense predictions.
          Always: fit once on training data, transform everything else.

        Args:
            emails: list of email strings
            fit:    True during training, False during prediction

        Returns:
            np.ndarray of shape (n_emails, n_tfidf + n_manual_features)
        """
        # Part A: TF-IDF text features
        # fit_transform = fit + transform in one call (training only)
        # transform     = apply learned vocabulary (prediction)
        if fit:
            tfidf_matrix = self.tfidf.fit_transform(emails).toarray()
        else:
            tfidf_matrix = self.tfidf.transform(emails).toarray()

        # Part B: hand-crafted features
        # extract_batch() returns shape (n_emails, n_manual_features)
        manual_matrix = np.array(self.feature_extractor.extract_batch(emails))

        # Part C: combine horizontally
        # hstack concatenates column-wise:
        #   tfidf_matrix  shape: (n_emails, 5000)
        #   manual_matrix shape: (n_emails,   25)
        #   result        shape: (n_emails, 5025)
        combined = np.hstack([tfidf_matrix, manual_matrix])

        logger.debug(
            "Feature matrix: %d emails × %d features "
            "(%d TF-IDF + %d manual)",
            combined.shape[0], combined.shape[1],
            tfidf_matrix.shape[1], manual_matrix.shape[1],
        )

        return combined

    def train(
        self,
        emails: List[str],
        labels: List[int],
    ) -> Dict:
        """
        Full training pipeline. Call this once with your labelled data.

        Args:
            emails: list of email text strings
            labels: list of 0 (safe) or 1 (phishing) — one per email

        Returns:
            Dict of evaluation metrics (accuracy, precision, etc.)

        After calling this, the trainer is ready to call .predict().
        """
        if len(emails) != len(labels):
            raise ValueError(
                f"emails ({len(emails)}) and labels ({len(labels)}) "
                f"must be the same length."
            )

        if len(emails) < 10:
            raise ValueError(
                "Need at least 10 emails to train. "
                "More data = better model. Aim for 1000+."
            )

        logger.info("Starting training on %d emails...", len(emails))

        # ── STEP 1: TRAIN/TEST SPLIT ───────────────────────────
        # stratify=labels ensures the split preserves the ratio
        # of phishing:safe in both training and test sets.
        # Without stratify, a random split might put all phishing
        # examples in training, leaving only safe in the test set.
        X_train, X_test, y_train, y_test = train_test_split(
            emails,
            labels,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=labels,   # preserve class ratio in both halves
        )

        phishing_train = sum(y_train)
        phishing_test  = sum(y_test)
        logger.info(
            "Split: %d train (%d phishing, %d safe) | "
            "%d test (%d phishing, %d safe)",
            len(X_train), phishing_train, len(X_train) - phishing_train,
            len(X_test),  phishing_test,  len(X_test)  - phishing_test,
        )

        # ── STEP 2: FEATURE EXTRACTION ─────────────────────────
        logger.info("Extracting features...")
        # fit=True on training data — this is where TF-IDF learns
        # the vocabulary and computes IDF scores for every word.
        X_train_features = self._prepare_features(X_train, fit=True)
        # fit=False on test data — apply the SAME vocabulary.
        X_test_features  = self._prepare_features(X_test,  fit=False)

        # ── STEP 3: TRAIN THE CLASSIFIER ──────────────────────
        logger.info("Training %s...", self.model_name)
        start = datetime.now()
        self.classifier.fit(X_train_features, y_train)
        elapsed = (datetime.now() - start).total_seconds()
        logger.info("Training finished in %.1f seconds.", elapsed)

        # ── STEP 4: CROSS-VALIDATION ───────────────────────────
        # CONCEPT: Cross-Validation
        #   Instead of ONE train/test split, we do K splits.
        #   cv=5 means: split data into 5 chunks. Train on 4,
        #   test on 1. Rotate which chunk is the test set.
        #   Average the 5 accuracy scores.
        #   This gives a much more reliable accuracy estimate
        #   than a single split. It uses ALL data for both
        #   training and testing (at different times).
        #
        #   We use the TRAINING data only for cross-validation
        #   (not the held-out test set) to avoid data leakage.
        #
        #   SMALL DATASET NOTE:
        #   cv=5 requires at least 5 samples per class.
        #   With tiny datasets we reduce k automatically.
        #   Production datasets (1000+ emails) never hit this.
        min_class_count = min(
            sum(y_train),
            len(y_train) - sum(y_train)
        )
        n_folds = min(5, min_class_count)  # never more folds than smallest class

        if n_folds < 2:
            logger.warning(
                "Too few samples per class (%d) for cross-validation. "
                "Skipping CV. Add more training data for reliable estimates.",
                min_class_count
            )
            cv_scores = np.array([0.0])
        else:
            logger.info("Running %d-fold cross-validation...", n_folds)
            cv_scores = cross_val_score(
                self.classifier,
                X_train_features,
                y_train,
                cv=n_folds,
                scoring="f1",  # F1 balances precision and recall
                n_jobs=-1,
            )
        logger.info(
            "CV F1 scores: %s | Mean: %.3f ± %.3f",
            [f"{s:.3f}" for s in cv_scores],
            cv_scores.mean(),
            cv_scores.std(),
        )

        # ── STEP 5: EVALUATE ON HELD-OUT TEST SET ─────────────
        self.is_trained = True
        y_pred      = self.classifier.predict(X_test_features)
        y_pred_proba = self.classifier.predict_proba(X_test_features)[:, 1]

        metrics = self._compute_metrics(y_test, y_pred, y_pred_proba)
        metrics["cv_f1_mean"]   = round(float(cv_scores.mean()), 4)
        metrics["cv_f1_std"]    = round(float(cv_scores.std()), 4)
        metrics["training_time_seconds"] = round(elapsed, 2)
        metrics["n_train"]      = len(X_train)
        metrics["n_test"]       = len(X_test)
        metrics["model_name"]   = self.model_name
        metrics["trained_at"]   = datetime.now().isoformat()

        self.training_metrics = metrics
        self.trained_at = metrics["trained_at"]

        # Save feature names for interpretability
        tfidf_names   = list(self.tfidf.get_feature_names_out())
        manual_names  = self.feature_extractor.get_feature_names()
        self.feature_names = tfidf_names + manual_names

        self._log_metrics(metrics)
        return metrics

    def _compute_metrics(
        self,
        y_true: List[int],
        y_pred: List[int],
        y_prob: np.ndarray,
    ) -> Dict:
        """
        Computes a comprehensive set of evaluation metrics.

        CONCEPT: The Metrics Explained

          Accuracy:  (correct predictions) / (total predictions)
            Problem: if 95% of emails are safe, predicting "safe"
            always gives 95% accuracy — but catches 0 phishing!
            Accuracy alone is misleading on imbalanced data.

          Precision: of all emails we LABELLED as phishing,
            how many were actually phishing?
            = TP / (TP + FP)
            Low precision = lots of false alarms (safe emails
            incorrectly flagged). Annoying for users.

          Recall:    of all ACTUAL phishing emails, how many
            did we correctly catch?
            = TP / (TP + FN)
            Low recall = we're missing real phishing. Dangerous!
            For security, we want HIGH recall.

          F1 Score:  harmonic mean of precision and recall.
            = 2 × (precision × recall) / (precision + recall)
            Balances the two. Best single metric for phishing.

          ROC-AUC:   area under the ROC curve.
            Measures how well the model RANKS emails by risk.
            1.0 = perfect ranking. 0.5 = random guessing.

          Confusion Matrix:
            [[TN, FP],   TN = safe correctly identified
             [FN, TP]]   FP = safe incorrectly flagged as phishing
                         FN = phishing MISSED (most dangerous!)
                         TP = phishing correctly caught
        """
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

        return {
            "accuracy":         round(accuracy_score(y_true, y_pred), 4),
            "precision":        round(precision_score(y_true, y_pred, zero_division=0), 4),
            "recall":           round(recall_score(y_true, y_pred, zero_division=0), 4),
            "f1_score":         round(f1_score(y_true, y_pred, zero_division=0), 4),
            "roc_auc":          round(roc_auc_score(y_true, y_prob), 4),
            "confusion_matrix": cm.tolist(),
            "true_negatives":   int(tn),
            "false_positives":  int(fp),  # safe flagged as phishing
            "false_negatives":  int(fn),  # phishing missed!
            "true_positives":   int(tp),
            "classification_report": classification_report(
                y_true, y_pred,
                target_names=["Safe", "Phishing"],
                output_dict=True,
            ),
        }

    def _log_metrics(self, metrics: Dict) -> None:
        """Logs a clean summary of training results."""
        divider = "─" * 45
        logger.info(divider)
        logger.info("  TRAINING RESULTS")
        logger.info(divider)
        logger.info("  Accuracy  : %.1f%%", metrics["accuracy"]  * 100)
        logger.info("  Precision : %.1f%%", metrics["precision"] * 100)
        logger.info("  Recall    : %.1f%%", metrics["recall"]    * 100)
        logger.info("  F1 Score  : %.1f%%", metrics["f1_score"]  * 100)
        logger.info("  ROC-AUC   : %.4f",  metrics["roc_auc"])
        logger.info("  CV F1     : %.3f ± %.3f",
                    metrics["cv_f1_mean"], metrics["cv_f1_std"])
        logger.info(divider)
        cm = metrics["confusion_matrix"]
        logger.info("  Confusion Matrix:")
        logger.info("             Pred Safe  Pred Phish")
        logger.info("  Real Safe  %8d  %10d", cm[0][0], cm[0][1])
        logger.info("  Real Phish %8d  %10d", cm[1][0], cm[1][1])
        if metrics["false_negatives"] > 0:
            logger.warning(
                "  ⚠ %d phishing emails were MISSED (false negatives)",
                metrics["false_negatives"]
            )
        logger.info(divider)

    def save(self, directory: str) -> str:
        """
        Saves the trained model, vectorizer, and metadata to disk.

        CONCEPT: Why we save with joblib
          Training takes seconds to minutes. We don't want to
          retrain every time the server restarts. joblib efficiently
          serialises (converts to bytes) the entire sklearn objects —
          including the learned vocabulary, IDF weights, and all
          200 tree structures — into a single .pkl file.

          On the next server start, we load it in milliseconds.

        Saves 3 files:
          model.pkl      → the trained RandomForestClassifier
          vectorizer.pkl → the fitted TfidfVectorizer (with vocab)
          metadata.json  → metrics and training info (human-readable)

        Args:
            directory: folder to save into (e.g. ml/saved_models/)

        Returns:
            Path to the saved model file.
        """
        if not self.is_trained:
            raise RuntimeError("Cannot save — model has not been trained yet.")

        import json
        os.makedirs(directory, exist_ok=True)

        model_path      = os.path.join(directory, "model.pkl")
        vectorizer_path = os.path.join(directory, "vectorizer.pkl")
        metadata_path   = os.path.join(directory, "metadata.json")

        joblib.dump(self.classifier,  model_path)
        joblib.dump(self.tfidf,       vectorizer_path)

        # Save metadata as readable JSON (not binary)
        metadata = {
            "model_name":   self.model_name,
            "trained_at":   self.trained_at,
            "metrics":      {
                k: v for k, v in self.training_metrics.items()
                if k != "classification_report"  # skip verbose nested dict
            },
            "n_features":       len(self.feature_names),
            "n_tfidf_features": self.tfidf.max_features,
            "feature_extractor_features": self.feature_extractor.get_feature_names(),
        }

        with open(metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

        logger.info("Model saved to: %s", directory)
        logger.info("  model.pkl      : %s KB", os.path.getsize(model_path) // 1024)
        logger.info("  vectorizer.pkl : %s KB", os.path.getsize(vectorizer_path) // 1024)

        return model_path

    @classmethod
    def load(cls, directory: str) -> "PhishingModelTrainer":
        """
        Loads a previously saved trainer from disk.

        Usage:
            trainer = PhishingModelTrainer.load("ml/saved_models/")
            result  = trainer.predict("URGENT: verify now!")

        Args:
            directory: folder containing model.pkl and vectorizer.pkl

        Returns:
            A PhishingModelTrainer instance ready for predictions.
        """
        import json

        model_path      = os.path.join(directory, "model.pkl")
        vectorizer_path = os.path.join(directory, "vectorizer.pkl")
        metadata_path   = os.path.join(directory, "metadata.json")

        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"No saved model found at '{model_path}'.\n"
                f"Run: python scripts/train_model.py"
            )

        # Create a new trainer instance WITHOUT training
        instance = cls.__new__(cls)
        instance.classifier       = joblib.load(model_path)
        instance.tfidf            = joblib.load(vectorizer_path)
        instance.feature_extractor = EmailFeatureExtractor()
        instance.is_trained       = True
        instance.training_metrics = {}
        instance.feature_names    = []

        if os.path.exists(metadata_path):
            with open(metadata_path) as f:
                meta = json.load(f)
            instance.training_metrics = meta.get("metrics", {})
            instance.model_name       = meta.get("model_name", "unknown")
            instance.trained_at       = meta.get("trained_at", "unknown")
            logger.info(
                "Loaded model trained at %s | accuracy=%.1f%%",
                instance.trained_at,
                instance.training_metrics.get("accuracy", 0) * 100,
            )

        return instance

    def predict(self, email_text: str) -> Dict:
        """
        Analyses a single email and returns a structured result.

        Returns:
            {
              "label":       "phishing" | "safe",
              "is_phishing": True | False,
              "risk_score":  0-100  (int),
              "confidence":  0.0-1.0,
              "explanation": [...],   # list of human-readable reasons
              "features":    {...},   # raw feature values
            }
        """
        if not self.is_trained:
            raise RuntimeError(
                "Model not trained. Call .train() or .load() first."
            )

        # Extract features for this single email.
        # _prepare_features expects a LIST, so we wrap in [].
        # fit=False: use the vocabulary learned during training.
        features_matrix = self._prepare_features([email_text], fit=False)

        # predict() returns an array of class labels [0] or [1]
        prediction = int(self.classifier.predict(features_matrix)[0])

        # predict_proba() returns [[prob_safe, prob_phishing]]
        # We take index [0] for the first (only) email,
        # then [1] for the phishing probability.
        phishing_prob = float(
            self.classifier.predict_proba(features_matrix)[0][1]
        )

        # Risk score: 0-100 integer version of phishing probability
        risk_score = int(round(phishing_prob * 100))

        # Confidence: how sure is the model of its prediction?
        # If prediction=phishing, confidence = phishing_prob
        # If prediction=safe,     confidence = 1 - phishing_prob
        confidence = phishing_prob if prediction == 1 else (1 - phishing_prob)

        # Human-readable explanations from hand-crafted features
        raw_features = self.feature_extractor.extract(email_text)
        explanations = self._build_explanations(raw_features, phishing_prob)

        return {
            "label":       "phishing" if prediction == 1 else "safe",
            "is_phishing": bool(prediction == 1),
            "risk_score":  risk_score,
            "confidence":  round(confidence, 4),
            "explanation": explanations,
            "features":    raw_features,
        }

    def _build_explanations(
        self,
        features: Dict,
        risk: float,
    ) -> List[str]:
        """
        Converts raw feature values into plain English explanations.
        This answers: "WHY did you flag this email?"

        Each explanation includes:
        - An emoji severity indicator (🚨 critical, ⚠️ warning, ✅ ok)
        - A plain-English description of the finding
        - WHY it's suspicious (educational for the user)
        """
        reasons = []

        if features.get("has_ip_url"):
            reasons.append(
                "🚨 URL contains a raw IP address instead of a domain name. "
                "Legitimate services always use domain names like 'paypal.com'."
            )
        if features.get("has_lookalike_domain"):
            reasons.append(
                "🚨 Lookalike domain detected (e.g. 'paypa1.com' instead of "
                "'paypal.com'). Phishers register near-identical domains."
            )
        if features.get("has_hyperlink_mismatch"):
            reasons.append(
                "🚨 Link text and actual URL destination do not match. "
                "The visible link says one thing, but clicking goes elsewhere."
            )
        if features.get("has_hidden_text"):
            reasons.append(
                "🚨 Hidden text detected (display:none or visibility:hidden). "
                "Phishers hide text to confuse spam filters."
            )
        if features.get("has_at_in_url"):
            reasons.append(
                "🚨 URL contains @ symbol — a spoofing technique where "
                "everything before @ is ignored by the browser."
            )
        if features.get("urgency_word_count", 0) >= 2:
            reasons.append(
                f"⚠️ {int(features['urgency_word_count'])} urgency words found "
                "(e.g. 'urgent', 'suspended', 'act now'). "
                "Phishers create panic to stop you thinking critically."
            )
        if features.get("has_account_threat"):
            reasons.append(
                "⚠️ Threat of account closure or suspension detected. "
                "Legitimate companies give notice, not ultimatums via email."
            )
        if features.get("sensitive_word_count", 0) >= 2:
            reasons.append(
                f"⚠️ {int(features['sensitive_word_count'])} requests for "
                "sensitive information (password, SSN, card number). "
                "Legitimate organisations never ask for this via email."
            )
        if features.get("has_url_shortener"):
            reasons.append(
                "⚠️ URL shortener detected (bit.ly, tinyurl, etc.). "
                "These hide the real destination of the link."
            )
        if features.get("has_suspicious_tld"):
            reasons.append(
                "⚠️ Suspicious top-level domain (.tk, .ml, .xyz etc.). "
                "These free domains are disproportionately used in phishing."
            )
        if features.get("caps_ratio", 0) > 0.25:
            pct = int(features["caps_ratio"] * 100)
            reasons.append(
                f"⚠️ {pct}% of letters are uppercase. "
                "Excessive capitals are used to create artificial urgency."
            )
        if features.get("reward_word_count", 0) >= 2:
            reasons.append(
                "⚠️ Prize or reward language detected. "
                "'You have won' / 'Claim your gift' are classic lure tactics."
            )
        if features.get("impersonated_brand_count", 0) >= 2:
            reasons.append(
                f"⚠️ {int(features['impersonated_brand_count'])} well-known "
                "brands mentioned. Legitimate emails are from ONE company."
            )
        if features.get("form_tag_count", 0) > 0:
            reasons.append(
                "⚠️ HTML form detected — may be designed to capture and "
                "submit your personal information to an attacker's server."
            )
        if features.get("has_dangerous_attachment"):
            reasons.append(
                "🚨 Reference to a dangerous file type detected "
                "(.exe, .zip, macro-enabled Office files). "
                "Do not download or open."
            )

        if not reasons:
            reasons.append(
                "✅ No major phishing indicators detected. "
                "Always verify the sender independently before acting."
            )

        return reasons