# SQLShield — AI-Powered SQL Injection Detector

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4-orange)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

> **Author:** Kabir Malik (24CSU089) · B.Tech CSE (Cybersecurity) · The NorthCap University

---

## Overview

SQLShield is a machine-learning-powered web application that classifies SQL queries or web inputs as **Benign** or **SQL Injection** in real time. It compares 4 ML models, provides confidence scores, classifies attack subtypes, and exposes a REST API.

## Features

| Feature | Description |
|---|---|
| 🔍 Query Analysis | Real-time prediction with confidence % |
| 🏷️ Attack Classification | UNION, Boolean, Time-based, Error-based, Stacked, Comment |
| 🤖 Model Comparison | Accuracy / Precision / Recall / F1 for 4 models |
| 📜 Detection History | Last 20 predictions (session-scoped) |
| 🔌 REST API | `POST /api/predict` for third-party integration |

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Train the model (takes ~3-8 min depending on hardware)
python train.py

# 3. Start the web app
python app.py

# 4. Open in browser
# http://localhost:5000
```

## Project Structure

```
sqli-detector/
├── app.py                  # Flask backend
├── train.py                # ML training pipeline
├── requirements.txt
├── .env                    # Local config (never commit)
├── data/
│   └── Modified_SQL_Dataset.csv
├── models/
│   ├── sqli_model.pkl
│   ├── tfidf_vectorizer.pkl
│   └── model_results.json
├── templates/
│   └── index.html
└── static/
    ├── css/style.css
    └── js/main.js
```

## API Usage

```bash
curl -X POST http://localhost:5000/api/predict \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT * FROM users WHERE id=1 OR 1=1--"}'
```

**Response:**
```json
{
  "label": "SQL Injection",
  "confidence": 98.7,
  "attack_type": "Boolean-based",
  "timestamp": "2024-01-15T14:32:01",
  "response_ms": 12
}
```

## Dataset

- **File:** `data/Modified_SQL_Dataset.csv`
- **Rows:** 30,919 (19,537 Benign + 11,382 SQLi)
- **Columns:** `Query`, `Label` (0=Benign, 1=SQLi)

## ML Pipeline

- **Vectorizer:** TF-IDF char n-gram (`char_wb`, ngram 2–4, max 5000 features)
- **Models:** Logistic Regression, Random Forest, Gradient Boosting, Linear SVM (calibrated)
- **Best Model:** Selected by F1-Score on 20% holdout test set
