#!/usr/bin/env python3
# =============================================================
#  scripts/evaluate_model.py
#  Prints a detailed accuracy report for the trained model
#
#  RUN:  cd backend && python ../scripts/evaluate_model.py
# =============================================================

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from ml.evaluator import ModelEvaluator
from ml.trainer import PhishingModelTrainer

def main():
    print("\n🛡️  PhishGuard — Model Evaluation")
    print("=" * 50)

    trainer   = PhishingModelTrainer()
    evaluator = ModelEvaluator()

    # Load the saved model
    model_path = os.path.join(os.path.dirname(__file__), '..', 'backend', 'ml', 'saved_models')
    print(f"\n📂 Loading model from: {model_path}")

    try:
        trainer.load_model(model_path)
        print("✅ Model loaded successfully")
    except Exception as e:
        print(f"❌ Could not load model: {e}")
        print("   Run: python scripts/train_model.py first")
        sys.exit(1)

    # Generate evaluation report
    print("\n📊 Generating evaluation report...")
    evaluator.print_report(trainer)

if __name__ == "__main__":
    main()