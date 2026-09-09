# ARCHITECTURE.md — System Architecture
## AI-Powered SQL Injection Detection System

---

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER                         │
│              Browser (HTML + CSS + Vanilla JS)              │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP Requests
┌────────────────────────▼────────────────────────────────────┐
│                      FLASK BACKEND                          │
│                                                             │
│   ┌─────────────┐   ┌──────────────┐   ┌───────────────┐   │
│   │  Web Routes  │   │  REST API    │   │  Model Layer  │   │
│   │  GET /       │   │  POST        │   │               │   │
│   │  POST /      │   │  /api/predict│   │  TF-IDF Vec   │   │
│   └─────────────┘   └──────────────┘   │  Best Model   │   │
│                                        │  Attack Clf   │   │
│                                        └───────────────┘   │
└────────────────────────┬────────────────────────────────────┘
                         │ joblib.load()
┌────────────────────────▼────────────────────────────────────┐
│                     MODEL ARTIFACTS                         │
│                                                             │
│   sqli_model.pkl          tfidf_vectorizer.pkl              │
│   model_results.json      label_encoder.pkl                 │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Component Breakdown

### 2.1 Frontend (Client Layer)
- **Technology:** HTML5, CSS3, Vanilla JavaScript
- **Single page** with 4 sections: Input, Result, History, Model Comparison
- No frontend framework — keeps it lightweight and portable
- Communicates with backend via `fetch()` API calls

### 2.2 Backend (Flask)
- **Technology:** Python 3.10+, Flask 3.x
- Serves HTML templates via Jinja2
- Exposes REST API at `/api/predict`
- Loads ML model and vectorizer at startup (not per-request)
- Handles input validation and error responses

### 2.3 ML Pipeline
```
Raw Query String
      │
      ▼
TF-IDF Vectorizer (char_wb, ngram_range=(2,4), max_features=5000)
      │
      ▼
Best Trained Model (Random Forest / Gradient Boosting)
      │
      ▼
┌─────────────────────────┐
│  predict()  → Label     │  0 = Benign, 1 = SQLi
│  predict_proba() → Conf │  e.g. [0.03, 0.97]
└─────────────────────────┘
      │
      ▼
Attack Type Classifier (rule-based on keywords)
      │
      ▼
JSON Response
```

### 2.4 Attack Type Classifier
Rule-based keyword matcher running after ML prediction:

```python
ATTACK_PATTERNS = {
    "UNION-based":    ["union", "union select", "union all"],
    "Boolean-based":  ["or 1=1", "and 1=1", "or 'a'='a'"],
    "Time-based":     ["sleep(", "waitfor delay", "pg_sleep", "benchmark("],
    "Error-based":    ["@@version", "extractvalue", "utl_inaddr", "updatexml"],
    "Stacked Query":  [";drop", ";insert", ";update", ";delete"],
    "Comment-based":  ["--", "#", "/*", "*/"],
}
```

### 2.5 Model Artifacts (Saved Files)
| File | Contents |
|---|---|
| `sqli_model.pkl` | Best trained sklearn model |
| `tfidf_vectorizer.pkl` | Fitted TF-IDF vectorizer |
| `model_results.json` | Accuracy, Precision, Recall, F1 for all 4 models |

---

## 3. Folder Structure

```
sqli-detector/
│
├── app.py                    # Flask app entry point
├── train.py                  # Model training script
├── requirements.txt
├── README.md
│
├── models/
│   ├── sqli_model.pkl
│   ├── tfidf_vectorizer.pkl
│   └── model_results.json
│
├── data/
│   └── Modified_SQL_Dataset.csv
│
├── notebooks/
│   └── EDA_and_Training.ipynb
│
├── templates/
│   └── index.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── main.js
│
└── docs/
    ├── PRD.md
    ├── ARCHITECTURE.md
    ├── UI_UX_SPEC.md
    ├── DATABASE_SCHEMA.md
    └── SECURITY.md
```

---

## 4. Data Flow — Prediction Request

```
User types query → clicks Analyse
        │
        ▼
JS fetch() → POST /api/predict { "query": "..." }
        │
        ▼
Flask validates input (length, type)
        │
        ▼
vectorizer.transform([query])
        │
        ▼
model.predict() + model.predict_proba()
        │
        ▼
attack_type_classifier(query)
        │
        ▼
JSON response → { label, confidence, attack_type, timestamp }
        │
        ▼
UI updates result card + appends to history table
```

---

## 5. Deployment Architecture

```
GitHub Repo
    │
    ▼
Render / HuggingFace Spaces
    │
    ├── Build: pip install -r requirements.txt
    ├── Start: python app.py
    └── Public URL: https://sqlshield.onrender.com
```

---

## 6. Technology Decisions

| Decision | Choice | Reason |
|---|---|---|
| ML Framework | scikit-learn | Industry standard, well-documented |
| Vectorizer | TF-IDF char n-gram | Better than word tokens for SQLi patterns |
| Web Framework | Flask | Lightweight, easy to deploy |
| Serialization | joblib | Faster than pickle for numpy arrays |
| Frontend | Vanilla JS | No build step, faster load |
| Deployment | Render (free) | Simple GitHub integration |
