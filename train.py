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
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc,
)

warnings.filterwarnings("ignore")

# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────
DATA_PATH       = os.path.join("data", "Modified_SQL_Dataset.csv")
MODELS_DIR      = "models"
IMG_DIR         = os.path.join("static", "img")
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
# FIX 7 — EVALUATION PLOTS
# ──────────────────────────────────────────────────────────────────────────────

def generate_evaluation_plots(best_model, X_te, y_te, best_name):
    """
    Generate confusion matrix and ROC curve for the best model.
    Saved to static/img/ at 150 DPI with dark_background style.
    """
    try:
        import matplotlib
        matplotlib.use("Agg")  # non-interactive backend
        import matplotlib.pyplot as plt
        import matplotlib.ticker as mticker
    except ImportError:
        print("  [WARN] matplotlib not installed — skipping evaluation plots.")
        print("         Install with: pip install matplotlib")
        return

    os.makedirs(IMG_DIR, exist_ok=True)
    plt.style.use("dark_background")

    ACCENT_BLUE  = "#58a6ff"
    ACCENT_GREEN = "#3fb950"
    ACCENT_RED   = "#f85149"
    BG_CARD      = "#161b22"
    BG_TERTIARY  = "#21262d"
    BORDER       = "#30363d"
    TEXT_SEC     = "#8b949e"
    TEXT_PRI     = "#e6edf3"

    y_pred = best_model.predict(X_te)

    # ── Confusion Matrix ──────────────────────────────────────────────────────
    cm = confusion_matrix(y_te, y_pred)
    fig, ax = plt.subplots(figsize=(5.5, 4.5), facecolor=BG_CARD)
    ax.set_facecolor(BG_CARD)

    im = ax.imshow(cm, interpolation="nearest", cmap="Blues", vmin=0)
    fig.colorbar(im, ax=ax, fraction=.04, pad=.03)

    classes = ["Benign", "SQL Injection"]
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(classes, color=TEXT_PRI, fontsize=11)
    ax.set_yticklabels(classes, color=TEXT_PRI, fontsize=11)

    thresh = cm.max() / 2.0
    for i in range(2):
        for j in range(2):
            ax.text(j, i, format(cm[i, j], "d"),
                    ha="center", va="center", fontsize=14, fontweight="bold",
                    color=TEXT_PRI if cm[i, j] < thresh else BG_CARD)

    ax.set_xlabel("Predicted Label", color=TEXT_SEC, fontsize=11, labelpad=10)
    ax.set_ylabel("True Label",      color=TEXT_SEC, fontsize=11, labelpad=10)
    ax.set_title(f"Confusion Matrix — {best_name}",
                 color=TEXT_PRI, fontsize=12, fontweight="bold", pad=14)
    ax.spines[:].set_color(BORDER)
    ax.tick_params(colors=TEXT_SEC)

    cm_path = os.path.join(IMG_DIR, "confusion_matrix.png")
    fig.tight_layout()
    fig.savefig(cm_path, dpi=150, bbox_inches="tight", facecolor=BG_CARD)
    plt.close(fig)
    print(f"      Saved confusion matrix  -> {cm_path}")

    # ── ROC Curve ────────────────────────────────────────────────────────────
    try:
        y_prob = best_model.predict_proba(X_te)[:, 1]
    except AttributeError:
        print("  [WARN] Model does not support predict_proba — skipping ROC curve.")
        return

    fpr, tpr, _ = roc_curve(y_te, y_prob)
    roc_auc     = auc(fpr, tpr)

    fig, ax = plt.subplots(figsize=(5.5, 4.5), facecolor=BG_CARD)
    ax.set_facecolor(BG_CARD)

    ax.plot(fpr, tpr, color=ACCENT_BLUE, lw=2.2,
            label=f"AUC = {roc_auc:.4f}")
    ax.fill_between(fpr, tpr, alpha=0.10, color=ACCENT_BLUE)
    ax.plot([0, 1], [0, 1], color=BORDER, lw=1, linestyle="--", label="Random")

    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.02])
    ax.set_xlabel("False Positive Rate", color=TEXT_SEC, fontsize=11, labelpad=10)
    ax.set_ylabel("True Positive Rate",  color=TEXT_SEC, fontsize=11, labelpad=10)
    ax.set_title(f"ROC Curve — {best_name}",
                 color=TEXT_PRI, fontsize=12, fontweight="bold", pad=14)
    ax.tick_params(colors=TEXT_SEC)
    ax.spines[:].set_color(BORDER)
    ax.xaxis.set_major_formatter(mticker.PercentFormatter(xmax=1))
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1))
    legend = ax.legend(loc="lower right", fontsize=11,
                       facecolor=BG_TERTIARY, edgecolor=BORDER,
                       labelcolor=TEXT_PRI)

    roc_path = os.path.join(IMG_DIR, "roc_curve.png")
    fig.tight_layout()
    fig.savefig(roc_path, dpi=150, bbox_inches="tight", facecolor=BG_CARD)
    plt.close(fig)
    print(f"      Saved ROC curve          -> {roc_path}")


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

    # FIX 7 — generate evaluation plots
    print("[+] Generating evaluation plots…")
    generate_evaluation_plots(best_model, X_te, y_test, best_name)
    print("    Done.\n")


if __name__ == "__main__":
    main()
