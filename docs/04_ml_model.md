# ML Model Notes

## Detection Pipeline

PhishGuard uses a supervised learning pipeline for phishing detection.

Typical flow:

1. collect labelled email text
2. clean and unify datasets
3. convert text into numeric features
4. train a classifier
5. evaluate it on held-out data
6. save model artifacts for inference

## Core Theory

### Supervised learning

The model learns from examples with known labels:

- `0` = safe
- `1` = phishing

The training goal is to learn a boundary that separates the two classes.

### TF-IDF

The project uses TF-IDF-style text vectorisation.

Why:

- raw text cannot be consumed directly by most classical ML models
- TF-IDF turns text into weighted numeric features
- informative words get more influence than common filler words

### Logistic regression and related models

This project uses classical scikit-learn models as practical baselines.

Why that is good for learning:

- fast to train
- easy to inspect
- easier to explain than large neural networks

## Security-Specific Caveat

A phishing model is not a truth machine.

Attackers adapt quickly. That means:

- the data distribution shifts over time
- phishing language evolves
- highly polished scams can look legitimate

This is why the project combines:

- ML scoring
- heuristic explanations
- URL intelligence from VirusTotal

That combination is a defence-in-depth approach.

## Why `predict_safe()` Matters

The codebase intentionally exposes a safe prediction wrapper.

Engineering concept:

- production systems should degrade gracefully
- if the model is missing or broken, the app should fail usefully, not catastrophically

Here that means:

- return a structured "model not ready" result
- keep the HTTP route alive
- let the UI communicate the problem clearly

## Training Artifacts

Saved model assets typically include:

- trained estimator
- vectorizer
- metadata or evaluation summary

Concept:
- inference must use the exact same feature pipeline as training
- changing vectorizers without retraining breaks the meaning of the feature space

## Evaluation Metrics

Common metrics used in the project:

- accuracy
- precision
- recall
- F1 score
- ROC AUC

Why F1 matters in phishing detection:

- phishing is often less common than safe email
- a model can look "accurate" just by predicting safe too often
- F1 balances precision and recall better in imbalanced settings

## Production Monitoring Ideas

Useful real-world signals to watch:

- average confidence over time
- phishing rate over time
- false positives and false negatives
- feature drift
- dataset age

ML operations concept:

- model quality is not a one-time event
- deployment starts a monitoring problem, not the end of a training problem

## Retraining Philosophy

Retraining should not automatically replace the existing model without comparison.

Why:

- new data can be noisy
- labels can be wrong
- recent examples may overfit to one attack wave

Safer pattern:

1. train candidate model
2. compare metrics to current model
3. review change
4. promote if justified

## What To Improve Next

- richer header-based features
- URL lexical features
- domain-age lookups
- stronger evaluation sets
- feedback loop from analyst review
