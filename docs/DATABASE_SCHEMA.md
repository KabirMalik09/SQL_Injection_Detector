# DATABASE_SCHEMA.md — Data Model & Schema
## AI-Powered SQL Injection Detection System

---

## 1. Overview

SQLShield v1.0 does **not use a persistent database** by design — predictions are stateless and session history is stored in-memory (Python list, max 20 entries). This keeps deployment simple and dependency-free.

The "data model" for this project covers:
1. Training dataset schema
2. In-memory session store schema
3. Model artifact schema
4. API request/response schema

---

## 2. Training Dataset Schema

**File:** `data/Modified_SQL_Dataset.csv`

| Column | Type | Values | Description |
|---|---|---|---|
| `Query` | string | Any text | Raw SQL query or web input string |
| `Label` | integer | `0`, `1` | 0 = Benign, 1 = SQL Injection |

**Dataset Statistics:**
| Property | Value |
|---|---|
| Total rows | 30,919 |
| Benign (Label=0) | 19,537 (63.2%) |
| SQLi (Label=1) | 11,382 (36.8%) |
| Null values | 0 |
| Avg query length (Benign) | ~15 chars |
| Avg query length (SQLi) | ~85 chars |

**Data Quality Rules:**
- No null values allowed in either column
- Label must be binary (0 or 1)
- Query must be a non-empty string
- Duplicates are acceptable (natural in SQLi payloads)

---

## 3. Cleaned / Processed Data Schema

After preprocessing in `train.py`:

```python
df columns after cleaning:
- Query        : str   — original query (stripped whitespace)
- Label        : int   — 0 or 1
- query_length : int   — len(Query), used in EDA only
- query_lower  : str   — Query.lower(), used for attack classification
```

**Train/Test Split:**
```
Total: 30,919 rows
Train: 24,735 rows (80%)
Test:   6,184 rows (20%)
random_state = 42
stratify = y  ← preserves class ratio in both splits
```

---

## 4. TF-IDF Feature Matrix Schema

Output of `TfidfVectorizer.fit_transform()`:

```
Shape: (30919, 5000)
Type:  scipy.sparse.csr_matrix
Dtype: float64

Parameters:
  analyzer     = 'char_wb'
  ngram_range  = (2, 4)
  max_features = 5000
  sublinear_tf = True
```

Each row = one query represented as 5000-dimensional sparse vector.

---

## 5. Model Artifacts Schema

### 5.1 `models/sqli_model.pkl`
Serialized scikit-learn model object.
```python
# On load:
model = joblib.load('models/sqli_model.pkl')
model.predict(X)          # → array([0, 1, 0, ...])
model.predict_proba(X)    # → array([[0.97, 0.03], ...])
```

### 5.2 `models/tfidf_vectorizer.pkl`
Serialized fitted TfidfVectorizer.
```python
vectorizer = joblib.load('models/tfidf_vectorizer.pkl')
X = vectorizer.transform(["SELECT * FROM users"])  # → sparse matrix
```

### 5.3 `models/model_results.json`
```json
{
  "models": [
    {
      "name": "Logistic Regression",
      "accuracy": 0.9712,
      "precision": 0.9689,
      "recall": 0.9601,
      "f1_score": 0.9644,
      "is_best": false
    },
    {
      "name": "Random Forest",
      "accuracy": 0.9891,
      "precision": 0.9876,
      "recall": 0.9834,
      "f1_score": 0.9855,
      "is_best": true
    },
    {
      "name": "Gradient Boosting",
      "accuracy": 0.9843,
      "precision": 0.9821,
      "recall": 0.9798,
      "f1_score": 0.9809,
      "is_best": false
    },
    {
      "name": "Linear SVM",
      "accuracy": 0.9756,
      "precision": 0.9711,
      "recall": 0.9698,
      "f1_score": 0.9704,
      "is_best": false
    }
  ],
  "best_model": "Random Forest",
  "vectorizer_params": {
    "analyzer": "char_wb",
    "ngram_range": [2, 4],
    "max_features": 5000
  },
  "dataset": {
    "total_rows": 30919,
    "train_rows": 24735,
    "test_rows": 6184,
    "benign_count": 19537,
    "sqli_count": 11382
  }
}
```

---

## 6. In-Memory Session Store Schema

Stored as a Python list in `app.py` (max 20 entries, FIFO):

```python
detection_history = []  # global list, max 20 items

# Each entry:
{
    "id":          int,      # auto-increment
    "query":       str,      # original input (max 2000 chars)
    "label":       str,      # "Benign" or "SQL Injection"
    "confidence":  float,    # e.g. 97.3 (percentage)
    "attack_type": str,      # e.g. "UNION-based" or "—"
    "timestamp":   str,      # ISO format: "2024-01-15T14:32:01"
    "response_ms": int       # prediction time in milliseconds
}
```

**Constraints:**
- Max 20 entries (pop oldest when exceeded)
- Session-scoped — cleared on server restart
- Not persisted to disk

---

## 7. Attack Type Classification Schema

Rule-based classifier output:

```python
ATTACK_TYPES = [
    "UNION-based",
    "Boolean-based",
    "Time-based",
    "Error-based",
    "Stacked Query",
    "Comment-based",
    "Multiple Types",   # when >1 pattern matches
    "Unknown SQLi"      # SQLi detected but no pattern matched
]

# For benign queries: attack_type = "—"
```

**Priority order** (when multiple patterns match, first match wins unless 2+ match → "Multiple Types"):
1. Time-based (most dangerous, flag first)
2. UNION-based
3. Error-based
4. Stacked Query
5. Boolean-based
6. Comment-based

---

## 8. Future Database Schema (v2.0 roadmap)

If persistent storage is added in future versions:

```sql
-- predictions table
CREATE TABLE predictions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    query        TEXT NOT NULL,
    label        TEXT NOT NULL CHECK(label IN ('Benign', 'SQL Injection')),
    confidence   REAL NOT NULL,
    attack_type  TEXT,
    timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP,
    response_ms  INTEGER,
    api_key_id   INTEGER REFERENCES api_keys(id)
);

-- api_keys table (for future API authentication)
CREATE TABLE api_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash     TEXT NOT NULL UNIQUE,
    label        TEXT,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active    BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_predictions_timestamp ON predictions(timestamp DESC);
CREATE INDEX idx_predictions_label ON predictions(label);
```
