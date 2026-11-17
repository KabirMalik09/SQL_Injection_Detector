"""
train.py — SQLShield Model Training Pipeline with MLflow Tracking
AI-Powered SQL Injection Detection System
Author: Kabir Malik (24CSU089), The NorthCap University

Trains 3 required MLflow runs:
  Run 1 — Random Forest  (n_estimators=200, max_depth=None)   ← original
  Run 2 — Random Forest  (n_estimators=100, max_depth=10)     ← second HP set
  Run 3 — Logistic Regression (C=1.0)

Also trains the full original model set (Gradient Boosting, Linear SVM) for
the UI dashboard JSON — these are not logged as separate MLflow runs.

Saves:
  - models/model.joblib           — best run by F1 (sklearn Pipeline)
  - models/sqli_model.pkl         — best model (legacy, kept for compatibility)
  - models/tfidf_vectorizer.pkl   — fitted TF-IDF vectorizer (legacy)
  - models/model_results.json     — all metrics for UI dashboard
"""

from __future__ import annotations

import json
import os
import shutil
import time
import warnings
from pathlib import Path

import joblib
import mlflow
import mlflow.sklearn
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    auc,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

warnings.filterwarnings("ignore")

# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────
DATA_PATH       = os.path.join("data", "Modified_SQL_Dataset.csv")
MODELS_DIR      = "models"
IMG_DIR         = os.path.join("static", "img")
MODEL_PATH      = os.path.join(MODELS_DIR, "sqli_model.pkl")       # legacy
VECTORIZER_PATH = os.path.join(MODELS_DIR, "tfidf_vectorizer.pkl") # legacy
PIPELINE_PATH   = os.path.join(MODELS_DIR, "model.joblib")         # new
RESULTS_PATH    = os.path.join(MODELS_DIR, "model_results.json")

RANDOM_STATE = 42
TEST_SIZE    = 0.20

TFIDF_PARAMS = {
    "analyzer":     "char_wb",
    "ngram_range":  (2, 4),
    "max_features": 5000,
    "sublinear_tf": True,
}

MLFLOW_EXPERIMENT = "sqli-detection"

# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def print_banner():
    print("=" * 65)
    print("  SQLShield — ML Training Pipeline  (MLflow Edition)")
    print("  AI-Powered SQL Injection Detection System")
    print("  Author: Kabir Malik · The NorthCap University")
    print("=" * 65)


def load_data(path: str):
    """Load and validate the dataset (unchanged logic)."""
    print(f"\n[1/6] Loading dataset from: {path}")
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
    """Fit TF-IDF on train, transform both splits (unchanged logic)."""
    print("\n[2/6] Vectorising with TF-IDF (char_wb, ngram 2-4, max 5000)")
    vec  = TfidfVectorizer(**TFIDF_PARAMS)
    X_tr = vec.fit_transform(X_train)
    X_te = vec.transform(X_test)
    print(f"  Feature matrix shape: {X_tr.shape}")
    return vec, X_tr, X_te


def compute_metrics(model, X_te, y_te) -> dict:
    y_pred = model.predict(X_te)
    return {
        "accuracy":  round(float(accuracy_score(y_te, y_pred)),  4),
        "precision": round(float(precision_score(y_te, y_pred, zero_division=0)), 4),
        "recall":    round(float(recall_score(y_te, y_pred, zero_division=0)),    4),
        "f1_score":  round(float(f1_score(y_te, y_pred, zero_division=0)),        4),
    }


def save_confusion_matrix_png(model, X_te, y_te, name: str, run_dir: str) -> str:
    """Save a confusion matrix PNG as an MLflow artifact."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return ""

    y_pred = model.predict(X_te)
    cm = confusion_matrix(y_te, y_pred)
    fig, ax = plt.subplots(figsize=(5, 4))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm,
                                  display_labels=["Benign", "SQLi"])
    disp.plot(ax=ax, colorbar=True)
    ax.set_title(f"Confusion Matrix — {name}")
    fig.tight_layout()

    os.makedirs(run_dir, exist_ok=True)
    png_path = os.path.join(run_dir, "confusion_matrix.png")
    fig.savefig(png_path, dpi=120, bbox_inches="tight")
    plt.close(fig)
    return png_path


# ──────────────────────────────────────────────────────────────────────────────
# MLFLOW RUNS  (3 required runs)
# ──────────────────────────────────────────────────────────────────────────────

def mlflow_run(
    name: str,
    clf,
    vec: TfidfVectorizer,
    X_tr, X_te, y_tr, y_te,
    extra_params: dict | None = None,
) -> dict:
    """
    Train `clf`, log params/metrics/artifact to MLflow, return a result dict.
    The vectorizer is fitted externally so all runs share the same split & features.
    """
    with mlflow.start_run(run_name=name) as run:
        # ── params
        params = {"model_type": name, **TFIDF_PARAMS}
        if extra_params:
            params.update(extra_params)
        # convert tuples to strings for mlflow
        params["ngram_range"] = str(TFIDF_PARAMS["ngram_range"])
        mlflow.log_params(params)

        # ── train
        t0 = time.time()
        clf.fit(X_tr, y_tr)
        elapsed = time.time() - t0

        # ── metrics
        m = compute_metrics(clf, X_te, y_te)
        mlflow.log_metrics({**m, "train_time_s": round(elapsed, 2)})

        # ── confusion matrix artifact
        tmp_dir = os.path.join("mlruns", "_tmp", run.info.run_id)
        png = save_confusion_matrix_png(clf, X_te, y_te, name, tmp_dir)
        if png and os.path.exists(png):
            mlflow.log_artifact(png, artifact_path="plots")

        run_id = run.info.run_id

    result = {
        "name":      name,
        "run_id":    run_id,
        "is_best":   False,
        "_model":    clf,
        **m,
    }
    print(f"  [{name}] F1={m['f1_score']:.4f} | Acc={m['accuracy']:.4f} | "
          f"Time={elapsed:.1f}s | run_id={run_id[:8]}…")
    return result


def run_mlflow_experiments(vec, X_tr, X_te, y_tr, y_te) -> list[dict]:
    """
    Log the 3 required MLflow runs and return their result dicts.
    All use the SAME train/test split (random_state=42, stratified).
    """
    print(f"\n[3/6] MLflow experiment: '{MLFLOW_EXPERIMENT}'")
    shutil.rmtree("mlruns/_tmp", ignore_errors=True)
    mlflow.set_experiment(MLFLOW_EXPERIMENT)

    runs = []

    # Run 1 — Random Forest (original hyperparameters)
    rf1 = RandomForestClassifier(
        n_estimators=200, max_depth=None, min_samples_split=2,
        random_state=RANDOM_STATE, n_jobs=-1,
    )
    runs.append(mlflow_run(
        "Random Forest (n=200, depth=None)", rf1, vec, X_tr, X_te, y_tr, y_te,
        extra_params={"n_estimators": 200, "max_depth": "None", "min_samples_split": 2},
    ))

    # Run 2 — Random Forest (second hyperparameter set)
    rf2 = RandomForestClassifier(
        n_estimators=100, max_depth=10, min_samples_split=5,
        random_state=RANDOM_STATE, n_jobs=-1,
    )
    runs.append(mlflow_run(
        "Random Forest (n=100, depth=10)", rf2, vec, X_tr, X_te, y_tr, y_te,
        extra_params={"n_estimators": 100, "max_depth": 10, "min_samples_split": 5},
    ))

    # Run 3 — Logistic Regression
    lr = LogisticRegression(
        max_iter=1000, C=1.0, solver="lbfgs",
        random_state=RANDOM_STATE, n_jobs=-1,
    )
    runs.append(mlflow_run(
        "Logistic Regression (C=1.0)", lr, vec, X_tr, X_te, y_tr, y_te,
        extra_params={"C": 1.0, "solver": "lbfgs", "max_iter": 1000},
    ))

    return runs


# ──────────────────────────────────────────────────────────────────────────────
# FULL MODEL SET  (for UI dashboard JSON — unchanged from original train.py)
# ──────────────────────────────────────────────────────────────────────────────

def build_full_models():
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


def train_full_set(models, X_tr, X_te, y_tr, y_te) -> list[dict]:
    """Train the full model set for the UI dashboard (unchanged logic)."""
    print("\n[4/6] Training full model set for UI dashboard…\n")
    results = []
    for name, model in models.items():
        print(f"  Training: {name}")
        t0 = time.time()
        model.fit(X_tr, y_tr)
        elapsed = time.time() - t0

        m = compute_metrics(model, X_te, y_te)
        print(f"     F1={m['f1_score']:.4f} | Time={elapsed:.1f}s")

        results.append({
            "name":    name,
            "is_best": False,
            "_model":  model,
            **m,
        })
    return results


# ──────────────────────────────────────────────────────────────────────────────
# SAVE ARTIFACTS
# ──────────────────────────────────────────────────────────────────────────────

def select_best_mlflow_run(mlflow_runs: list[dict]) -> dict:
    best = max(mlflow_runs, key=lambda r: r["f1_score"])
    best["is_best"] = True
    print(f"\n[5/6] Best MLflow run: '{best['name']}'  (F1={best['f1_score']:.4f})")
    return best


def save_artifacts(
    vec: TfidfVectorizer,
    best_mlflow: dict,
    full_results: list[dict],
    total: int,
    benign: int,
    sqli: int,
):
    os.makedirs(MODELS_DIR, exist_ok=True)

    # ── New pipeline (vectorizer + best model wrapped together)
    pipeline = Pipeline([
        ("tfidf", vec),
        ("clf",   best_mlflow["_model"]),
    ])
    # Stash the model name so app/main.py can read it
    pipeline.model_name_ = best_mlflow["name"]

    joblib.dump(pipeline, PIPELINE_PATH)
    print(f"\n[6/6] Saved pipeline     -> {PIPELINE_PATH}")

    # ── Legacy separate files (kept for backward compatibility)
    joblib.dump(vec,                    VECTORIZER_PATH)
    joblib.dump(best_mlflow["_model"],  MODEL_PATH)
    print(f"      Saved vectorizer   -> {VECTORIZER_PATH}  (legacy)")
    print(f"      Saved model        -> {MODEL_PATH}  (legacy)")

    # ── Determine best across the full set for the dashboard JSON
    best_full = max(full_results, key=lambda r: r["f1_score"])
    for r in full_results:
        r["is_best"] = (r["name"] == best_full["name"])

    clean_results = [
        {k: v for k, v in r.items() if k != "_model"}
        for r in full_results
    ]

    payload = {
        "models": clean_results,
        "best_model": best_full["name"],
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
        "mlflow_experiment": MLFLOW_EXPERIMENT,
    }

    with open(RESULTS_PATH, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"      Saved results      -> {RESULTS_PATH}")


# ──────────────────────────────────────────────────────────────────────────────
# EVALUATION PLOTS  (unchanged from original train.py)
# ──────────────────────────────────────────────────────────────────────────────

def generate_evaluation_plots(best_model, X_te, y_te, best_name):
    """
    Generate confusion matrix and ROC curve for the best model.
    Saved to static/img/ at 150 DPI with dark_background style.
    """
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.ticker as mticker
    except ImportError:
        print("  [WARN] matplotlib not installed — skipping evaluation plots.")
        return

    os.makedirs(IMG_DIR, exist_ok=True)
    plt.style.use("dark_background")

    ACCENT_BLUE  = "#58a6ff"
    BG_CARD      = "#161b22"
    BG_TERTIARY  = "#21262d"
    BORDER       = "#30363d"
    TEXT_SEC     = "#8b949e"
    TEXT_PRI     = "#e6edf3"

    y_pred = best_model.predict(X_te)

    # Confusion Matrix
    cm = confusion_matrix(y_te, y_pred)
    fig, ax = plt.subplots(figsize=(5.5, 4.5), facecolor=BG_CARD)
    ax.set_facecolor(BG_CARD)
    im = ax.imshow(cm, interpolation="nearest", cmap="Blues", vmin=0)
    fig.colorbar(im, ax=ax, fraction=.04, pad=.03)

    classes = ["Benign", "SQL Injection"]
    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
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

    # ROC Curve
    try:
        y_prob = best_model.predict_proba(X_te)[:, 1]
    except AttributeError:
        return
    fpr, tpr, _ = roc_curve(y_te, y_prob)
    roc_auc     = auc(fpr, tpr)
    fig, ax = plt.subplots(figsize=(5.5, 4.5), facecolor=BG_CARD)
    ax.set_facecolor(BG_CARD)
    ax.plot(fpr, tpr, color=ACCENT_BLUE, lw=2.2, label=f"AUC = {roc_auc:.4f}")
    ax.fill_between(fpr, tpr, alpha=0.10, color=ACCENT_BLUE)
    ax.plot([0, 1], [0, 1], color=BORDER, lw=1, linestyle="--", label="Random")
    ax.set_xlim([0.0, 1.0]); ax.set_ylim([0.0, 1.02])
    ax.set_xlabel("False Positive Rate", color=TEXT_SEC, fontsize=11, labelpad=10)
    ax.set_ylabel("True Positive Rate",  color=TEXT_SEC, fontsize=11, labelpad=10)
    ax.set_title(f"ROC Curve — {best_name}",
                 color=TEXT_PRI, fontsize=12, fontweight="bold", pad=14)
    ax.tick_params(colors=TEXT_SEC)
    ax.spines[:].set_color(BORDER)
    ax.xaxis.set_major_formatter(mticker.PercentFormatter(xmax=1))
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1))
    ax.legend(loc="lower right", fontsize=11,
              facecolor=BG_TERTIARY, edgecolor=BORDER, labelcolor=TEXT_PRI)
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

    # ── Load data (same preprocessing as before)
    X, y, total, benign, sqli = load_data(DATA_PATH)

    # ── Single train/test split shared by ALL runs (random_state=42, stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y,
    )
    print(f"\n  Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # ── Vectorise (same TF-IDF for all runs)
    vectorizer, X_tr, X_te = vectorize(X_train, X_test)

    # ── MLflow: 3 required runs
    mlflow_runs = run_mlflow_experiments(vectorizer, X_tr, X_te, y_train, y_test)
    best_mlflow = select_best_mlflow_run(mlflow_runs)

    # ── Full model set for the UI dashboard
    full_models  = build_full_models()
    full_results = train_full_set(full_models, X_tr, X_te, y_train, y_test)

    # ── Save all artifacts
    save_artifacts(vectorizer, best_mlflow, full_results, total, benign, sqli)

    # ── Print summary table
    print("\n" + "=" * 65)
    print("  MLflow RUNS SUMMARY")
    print("=" * 65)
    print(f"{'Run':<38} {'Accuracy':>9} {'F1-Score':>9}")
    print("-" * 65)
    for r in mlflow_runs:
        tag = " <- BEST" if r["is_best"] else ""
        print(f"{r['name']:<38} {r['accuracy']:>9.4f} {r['f1_score']:>9.4f}{tag}")
    print("=" * 65)
    print(f"\nMLflow UI: mlflow ui  (then open http://localhost:5000)")
    print(f"Artifacts written to ./{MODELS_DIR}/\n")

    # ── Evaluation plots (unchanged)
    print("[+] Generating evaluation plots…")
    # Use the best MLflow model for the plots
    generate_evaluation_plots(best_mlflow["_model"], X_te, y_test, best_mlflow["name"])
    print("    Done.\n")

    print("Training complete.")


if __name__ == "__main__":
    main()
