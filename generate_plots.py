"""
generate_plots.py — Regenerate evaluation plots from saved model artifacts.
Reads models/sqli_model.pkl + models/tfidf_vectorizer.pkl, scores them on the
same holdout slice as train.py, and writes:
  static/img/confusion_matrix.png
  static/img/roc_curve.png
"""

import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, roc_curve, auc

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

DATA_PATH       = os.path.join("data", "Modified_SQL_Dataset.csv")
MODEL_PATH      = os.path.join("models", "sqli_model.pkl")
VECTORIZER_PATH = os.path.join("models", "tfidf_vectorizer.pkl")
IMG_DIR         = os.path.join("static", "img")

RANDOM_STATE = 42
TEST_SIZE    = 0.20

ACCENT_BLUE = "#58a6ff"
BG_CARD     = "#161b22"
BG_TERTIARY = "#21262d"
BORDER      = "#30363d"
TEXT_SEC    = "#8b949e"
TEXT_PRI    = "#e6edf3"

print("Loading model and vectorizer...")
model      = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

print("Loading dataset...")
df = pd.read_csv(DATA_PATH).dropna(subset=["Query", "Label"])
df["Query"] = df["Query"].astype(str).str.strip()
df["Label"] = df["Label"].astype(int)

_, X_test_raw, _, y_test = train_test_split(
    df["Query"].values, df["Label"].values,
    test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=df["Label"].values,
)
print(f"Test set: {len(y_test):,} rows")

X_test = vectorizer.transform(X_test_raw)
y_pred = model.predict(X_test)

os.makedirs(IMG_DIR, exist_ok=True)
plt.style.use("dark_background")

# ── Confusion Matrix ─────────────────────────────────────────────────────────
print("Generating confusion matrix...")
cm = confusion_matrix(y_test, y_pred)

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
ax.set_title("Confusion Matrix — Random Forest",
             color=TEXT_PRI, fontsize=12, fontweight="bold", pad=14)
ax.spines[:].set_color(BORDER)
ax.tick_params(colors=TEXT_SEC)

cm_path = os.path.join(IMG_DIR, "confusion_matrix.png")
fig.tight_layout()
fig.savefig(cm_path, dpi=150, bbox_inches="tight", facecolor=BG_CARD)
plt.close(fig)
print(f"  Saved -> {cm_path}")

# ── ROC Curve ────────────────────────────────────────────────────────────────
print("Generating ROC curve...")
y_prob = model.predict_proba(X_test)[:, 1]
fpr, tpr, _ = roc_curve(y_test, y_prob)
roc_auc = auc(fpr, tpr)

fig, ax = plt.subplots(figsize=(5.5, 4.5), facecolor=BG_CARD)
ax.set_facecolor(BG_CARD)

ax.plot(fpr, tpr, color=ACCENT_BLUE, lw=2.2, label=f"AUC = {roc_auc:.4f}")
ax.fill_between(fpr, tpr, alpha=0.10, color=ACCENT_BLUE)
ax.plot([0, 1], [0, 1], color=BORDER, lw=1, linestyle="--", label="Random")

ax.set_xlim([0.0, 1.0]); ax.set_ylim([0.0, 1.02])
ax.set_xlabel("False Positive Rate", color=TEXT_SEC, fontsize=11, labelpad=10)
ax.set_ylabel("True Positive Rate",  color=TEXT_SEC, fontsize=11, labelpad=10)
ax.set_title("ROC Curve — Random Forest",
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
print(f"  Saved -> {roc_path}")

print("\nDone! Both evaluation plots generated successfully.")
