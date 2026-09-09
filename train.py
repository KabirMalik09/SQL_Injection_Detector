"""
train.py — SQLShield Model Training Script
AI-Powered SQL Injection Detection System
Author: Kabir Malik (24CSU089), The NorthCap University

Trains 4 ML models:
  1. Logistic Regression
  2. Random Forest
  3. Gradient Boosting
  4. Linear SVM

Saves:
  - models/sqli_model.pkl        — best trained model
  - models/tfidf_vectorizer.pkl  — fitted TF-IDF vectorizer
  - models/model_results.json    — all metrics for UI dashboard
"""

import os
import json
import time
import warnings
import joblib
import numpy as np
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

warnings.filterwarnings("ignore")

# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────
DATA_PATH       = os.path.join("data", "Modified_SQL_Dataset.csv")
MODELS_DIR      = "models"
MODEL_PATH      = os.path.join(MODELS_DIR, "sqli_model.pkl")
VECTORIZER_PATH = os.path.join(MODELS_DIR, "tfidf_vectorizer.pkl")
RESULTS_PATH    = os.path.join(MODELS_DIR, "model_results.json")

RANDOM_STATE = 42
TEST_SIZE    = 0.20

TFIDF_PARAMS = {
    "analyzer":     "char_wb",
    "ngram_range":  (2, 4),
    "max_features": 5000,
    "sublinear_tf": True,
}

# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def print_banner():
    print("=" * 65)
    print("  SQLShield — ML Training Pipeline")
    print("  AI-Powered SQL Injection Detection System")
    print("  Author: Kabir Malik · The NorthCap University")
    print("=" * 65)


def load_data(path):
    """Load and validate the dataset."""
    print(f"\n[1/5] Loading dataset from: {path}")
    df = pd.read_csv(path)

    assert "Query" in df.columns and "Label" in df.columns, \
        "Dataset must have 'Query' and 'Label' columns."

    before = len(df)
    df = df.dropna(subset=["Query", "Label"])
    df = df[df["Query"].astype(str).str.strip() != ""]
    after = len(df)
    if before != after:
        print(f"  Warning: Dropped {before - after} null/empty rows.")

    df["Query"] = df["Query"].astype(str).str.strip()
    df["Label"] = df["Label"].astype(int)

    total  = len(df)
    benign = int((df["Label"] == 0).sum())
    sqli   = int((df["Label"] == 1).sum())
    print(f"  Total rows : {total:,}")
    print(f"  Benign (0) : {benign:,}  ({benign/total*100:.1f}%)")
    print(f"  SQLi   (1) : {sqli:,}  ({sqli/total*100:.1f}%)")

    return df["Query"].values, df["Label"].values, total, benign, sqli


def vectorize(X_train, X_test):
    """Fit TF-IDF on train, transform both splits."""
    print("\n[2/5] Vectorising with TF-IDF (char_wb, ngram 2-4, max 5000)")
    vec  = TfidfVectorizer(**TFIDF_PARAMS)
    X_tr = vec.fit_transform(X_train)
    X_te = vec.transform(X_test)
    print(f"  Feature matrix shape: {X_tr.shape}")
    return vec, X_tr, X_te


def build_models():
    """Return dict of model name to sklearn estimator."""
    return {
        "Logistic Regression": LogisticRegression(
            max_iter=1000, C=1.0, solver="lbfgs",
            random_state=RANDOM_STATE, n_jobs=-1,
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=200, max_depth=None, min_samples_split=2,
            random_state=RANDOM_STATE, n_jobs=-1,
        ),
        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators=150, learning_rate=0.1, max_depth=5,
            random_state=RANDOM_STATE,
        ),
        "Linear SVM": CalibratedClassifierCV(
            LinearSVC(C=1.0, max_iter=2000, random_state=RANDOM_STATE),
            cv=3,
        ),
    }


def train_and_evaluate(models, X_tr, X_te, y_tr, y_te):
    """Train each model, collect metrics, return results list."""
    print("\n[3/5] Training & evaluating models...\n")
    results = []

    for name, model in models.items():
        print(f"  Training: {name}")
        t0 = time.time()
        model.fit(X_tr, y_tr)
        elapsed = time.time() - t0

        y_pred = model.predict(X_te)
        acc  = float(accuracy_score(y_te, y_pred))
        prec = float(precision_score(y_te, y_pred, zero_division=0))
        rec  = float(recall_score(y_te, y_pred, zero_division=0))
        f1   = float(f1_score(y_te, y_pred, zero_division=0))

        print(f"     Accuracy : {acc:.4f}")
        print(f"     Precision: {prec:.4f}")
        print(f"     Recall   : {rec:.4f}")
        print(f"     F1-Score : {f1:.4f}")
        print(f"     Time     : {elapsed:.1f}s\n")

        results.append({
            "name":      name,
            "accuracy":  round(acc,  4),
            "precision": round(prec, 4),
            "recall":    round(rec,  4),
            "f1_score":  round(f1,   4),
            "is_best":   False,
            "_model":    model,
        })

    return results


def select_best(results):
    """Mark best model by F1, return its name and estimator."""
    best_idx = max(range(len(results)), key=lambda i: results[i]["f1_score"])
    results[best_idx]["is_best"] = True
    best_name  = results[best_idx]["name"]
    best_model = results[best_idx]["_model"]
    print(f"[4/5] Best model: {best_name}  (F1={results[best_idx]['f1_score']:.4f})")
    return best_name, best_model


def save_artifacts(vec, best_model, results, best_name, total, benign, sqli):
    """Persist vectorizer, model, and JSON results."""
    os.makedirs(MODELS_DIR, exist_ok=True)

    joblib.dump(vec, VECTORIZER_PATH)
    print(f"\n[5/5] Saved vectorizer -> {VECTORIZER_PATH}")

    joblib.dump(best_model, MODEL_PATH)
    print(f"      Saved model      -> {MODEL_PATH}")

    clean_results = [
        {k: v for k, v in r.items() if k != "_model"}
        for r in results
    ]

    payload = {
        "models": clean_results,
        "best_model": best_name,
        "vectorizer_params": {
            "analyzer":     TFIDF_PARAMS["analyzer"],
            "ngram_range":  list(TFIDF_PARAMS["ngram_range"]),
            "max_features": TFIDF_PARAMS["max_features"],
            "sublinear_tf": TFIDF_PARAMS["sublinear_tf"],
        },
        "dataset": {
            "total_rows":   total,
            "train_rows":   int(total * (1 - TEST_SIZE)),
            "test_rows":    int(total * TEST_SIZE),
            "benign_count": benign,
            "sqli_count":   sqli,
        },
    }

    with open(RESULTS_PATH, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"      Saved results    -> {RESULTS_PATH}")


def print_summary(results, best_name):
    print("\n" + "=" * 65)
    print("  MODEL COMPARISON SUMMARY")
    print("=" * 65)
    print(f"{'Model':<22} {'Accuracy':>9} {'Precision':>10} {'Recall':>8} {'F1-Score':>9}")
    print("-" * 65)
    for r in results:
        tag = " <- BEST" if r["is_best"] else ""
        print(
            f"{r['name']:<22} "
            f"{r['accuracy']:>9.4f} "
            f"{r['precision']:>10.4f} "
            f"{r['recall']:>8.4f} "
            f"{r['f1_score']:>9.4f}"
            f"{tag}"
        )
    print("=" * 65)
    print(f"\nArtifacts written to ./{MODELS_DIR}/")
    print("Training complete.\n")


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

def main():
    print_banner()

    X, y, total, benign, sqli = load_data(DATA_PATH)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y,
    )
    print(f"\n  Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    vectorizer, X_tr, X_te = vectorize(X_train, X_test)

    models  = build_models()
    results = train_and_evaluate(models, X_tr, X_te, y_train, y_test)

    best_name, best_model = select_best(results)

    save_artifacts(vectorizer, best_model, results, best_name,
                   total, benign, sqli)

    print_summary(results, best_name)


if __name__ == "__main__":
    main()
