# =============================================================
#  backend/app/services/detector.py
#  Phishing Detector Service
# =============================================================
#
#  CONCEPT: The Service Layer
#
#  We have three layers in this app:
#
#    Routes (routes/detect.py)
#      ↓ calls
#    Services (services/detector.py)   ← THIS FILE
#      ↓ calls
#    ML (ml/trainer.py)
#
#  WHY a service layer? Why not call the ML model directly
#  from the route?
#
#    1. SEPARATION OF CONCERNS
#       The route handles HTTP: parse request, return response.
#       The service handles BUSINESS LOGIC: what to do with data.
#       The ML layer handles MATH: numbers in, prediction out.
#       Each layer does ONE thing. Easier to test and change.
#
#    2. SINGLETON PATTERN
#       The model file is large (MB). We load it ONCE when the
#       server starts and reuse it for every request.
#       If we loaded it inside the route, it would reload on
#       every single API call — very slow!
#       The service holds the loaded model in memory.
#
#    3. TESTABILITY
#       Tests can import PhishingDetectorService and test it
#       without starting a Flask server at all.
#       Routes just pass data through — less to mock in tests.
#
#  SINGLETON PATTERN explained:
#    class PhishingDetectorService:
#        _instance = None     ← class-level variable, not instance
#
#        @classmethod
#        def get_instance(cls):
#            if cls._instance is None:
#                cls._instance = cls()  ← only created once
#            return cls._instance
#
#    First call:  creates the object, loads the model
#    All subsequent calls: return the SAME already-loaded object
# =============================================================

import os
import logging
from typing import Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# Compute paths relative to this file so they work regardless
# of which directory you run the server from.
_THIS_DIR    = os.path.dirname(os.path.abspath(__file__))    # .../app/services/
_BACKEND_DIR = os.path.dirname(os.path.dirname(_THIS_DIR))   # .../backend/
_MODELS_DIR  = os.path.join(_BACKEND_DIR, "ml", "saved_models")


class PhishingDetectorService:
    """
    Singleton service that wraps the trained PhishingModelTrainer.
    Loaded once at startup, shared across all API requests.

    Usage (in routes/detect.py):
        from app.services.detector import PhishingDetectorService

        detector = PhishingDetectorService.get_instance()
        result   = detector.predict(email_text)
    """

    # Class variable — shared across ALL instances.
    # Stores the one-and-only loaded model.
    _instance: Optional["PhishingDetectorService"] = None

    def __init__(self):
        """
        Private — use get_instance() instead of PhishingDetectorService().
        Loads the saved model from disk.
        """
        self._trainer    = None   # will hold the loaded PhishingModelTrainer
        self._is_ready   = False  # True once model is loaded
        self._loaded_at  = None
        self._load_model()

    @classmethod
    def get_instance(cls) -> "PhishingDetectorService":
        """
        Returns the shared singleton instance.
        Creates it (and loads the model) on the very first call.
        All subsequent calls return the already-loaded instance.

        This is the ONLY way to get a PhishingDetectorService.
        """
        if cls._instance is None:
            logger.info("PhishingDetectorService: first call — loading model...")
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """
        Forces the next get_instance() call to reload the model.
        Used after training a new model (so the server picks it up)
        and in tests (to ensure a clean state between test runs).
        """
        cls._instance = None
        logger.info("PhishingDetectorService: singleton reset.")

    def _load_model(self) -> None:
        """
        Loads the trained model from ml/saved_models/.
        Called once by __init__().

        We import PhishingModelTrainer here (inside the method)
        rather than at the top of the file.
        WHY? Importing at the top level would import scikit-learn,
        numpy etc. at server startup even if the model isn't trained
        yet. Lazy importing keeps startup fast and avoids errors
        when those packages aren't installed.
        """
        try:
            # Import here to keep startup fast
            from ml.trainer import PhishingModelTrainer

            if not os.path.exists(os.path.join(_MODELS_DIR, "model.pkl")):
                logger.warning(
                    "No trained model found at '%s'. "
                    "Run: python scripts/train_model.py",
                    _MODELS_DIR,
                )
                self._is_ready = False
                return

            self._trainer   = PhishingModelTrainer.load(_MODELS_DIR)
            self._is_ready  = True
            self._loaded_at = datetime.now().isoformat()
            logger.info(
                "✅ Phishing model loaded | accuracy=%.1f%% | loaded_at=%s",
                self._trainer.training_metrics.get("accuracy", 0) * 100,
                self._loaded_at,
            )

        except Exception as e:
            logger.error("Failed to load phishing model: %s", e, exc_info=True)
            self._is_ready = False

    # ── PUBLIC API ─────────────────────────────────────────────

    @property
    def is_ready(self) -> bool:
        """True if a trained model is loaded and ready to predict."""
        return self._is_ready

    @property
    def model_info(self) -> Dict:
        """Returns metadata about the loaded model (for the dashboard)."""
        if not self._is_ready or not self._trainer:
            return {"status": "not_loaded"}

        metrics = self._trainer.training_metrics
        return {
            "status":      "ready",
            "model_name":  getattr(self._trainer, "model_name", "unknown"),
            "trained_at":  getattr(self._trainer, "trained_at", "unknown"),
            "loaded_at":   self._loaded_at,
            "accuracy":    metrics.get("accuracy", 0),
            "f1_score":    metrics.get("f1_score", 0),
            "recall":      metrics.get("recall", 0),
        }

    def predict(self, email_text: str) -> Dict:
        """
        Analyses one email and returns a prediction result.

        Args:
            email_text: The full email body (and optionally headers).

        Returns:
            {
              "label":       "phishing" | "safe",
              "is_phishing": True | False,
              "risk_score":  0-100,
              "confidence":  0.0-1.0,
              "explanation": [...strings...],
              "features":    {...},
              "model_ready": True,
            }

        Raises:
            RuntimeError: if no trained model is loaded.
        """
        if not self._is_ready:
            raise RuntimeError(
                "Phishing detection model is not loaded. "
                "An admin must train the model first: "
                "python scripts/train_model.py"
            )

        result = self._trainer.predict(email_text)
        result["model_ready"] = True
        return result

    def predict_safe(self, email_text: str) -> Dict:
        """
        Like predict(), but returns a structured error dict instead
        of raising an exception when the model isn't ready.
        Useful for API routes that want to handle the "no model"
        case gracefully without a try/except in the route.
        """
        if not self._is_ready:
            return {
                "label":       "unknown",
                "is_phishing": False,
                "risk_score":  -1,
                "confidence":  0.0,
                "explanation": [
                    "⚠️ The detection model has not been trained yet. "
                    "Ask your administrator to run the training script."
                ],
                "features":    {},
                "model_ready": False,
            }
        return self.predict(email_text)