# PRD.md — Product Requirements Document
## AI-Powered SQL Injection Detection System

---

## 1. Product Overview

**Product Name:** SQLShield — AI-Powered SQL Injection Detector  
**Version:** 1.0.0  
**Author:** Kabir Malik (24CSU089), The NorthCap University  
**Type:** Cybersecurity Web Application with ML Backend

### Summary
SQLShield is a machine learning-powered web application that analyzes SQL queries or web inputs and classifies them as Benign or SQL Injection attempts. It compares multiple ML models, provides confidence scores, classifies attack types, and exposes a REST API for integration.

---

## 2. Problem Statement

SQL Injection remains in the OWASP Top 10 most critical web vulnerabilities. Traditional rule-based WAFs miss novel injection patterns. A machine learning approach learns from patterns and generalizes better to unseen attacks.

---

## 3. Goals

- Detect SQL injection attempts with F1-score ≥ 95%
- Provide real-time prediction with confidence score
- Classify the type of SQL injection attack
- Compare performance of 4 ML models
- Expose a REST API for third-party integration
- Deploy as a live, accessible web application

---

## 4. Target Users

| User | Use Case |
|---|---|
| Security Analyst | Test queries manually via UI |
| Developer | Integrate detection via REST API |
| Recruiter/Evaluator | View live demo and model comparison |
| Student/Researcher | Understand ML approach to cybersecurity |

---

## 5. Core Features

### F1 — Query Input & Prediction
- Text input field accepting any SQL query or web input string
- On submission: returns label (Benign / SQL Injection)
- Displays confidence percentage (e.g. 94.7%)
- Response time < 500ms

### F2 — Attack Type Classification
Classify SQLi into subtypes:
- UNION-based (`UNION SELECT`)
- Boolean-based (`OR 1=1`, `AND 1=1`)
- Time-based (`SLEEP()`, `WAITFOR DELAY`, `pg_sleep`)
- Error-based (`@@version`, `utl_inaddr`, `extractvalue`)
- Stacked queries (`; DROP TABLE`)
- Comment-based (`--`, `#`, `/**/`)

### F3 — Model Comparison Dashboard
- Table showing Accuracy, Precision, Recall, F1-Score for:
  - Logistic Regression
  - Random Forest
  - Gradient Boosting
  - Linear SVM
- Visual bar chart of model performance
- Highlight best model

### F4 — Detection History Log
- Table of last 20 predictions in session
- Columns: Query (truncated), Label, Confidence, Attack Type, Timestamp
- Clear history button

### F5 — REST API
- `POST /api/predict` endpoint
- Accepts JSON input, returns prediction + confidence + attack type
- Returns proper HTTP status codes

### F6 — Live Deployment
- Hosted on Render or HuggingFace Spaces
- Publicly accessible via URL

---

## 6. Non-Functional Requirements

| Requirement | Target |
|---|---|
| Prediction latency | < 500ms |
| Model F1-Score | ≥ 95% |
| UI responsiveness | Mobile + Desktop |
| Uptime (deployed) | ≥ 99% on free tier |
| Input max length | 2000 characters |

---

## 7. Out of Scope (v1.0)

- User authentication / login system
- Real database integration
- IP blocking / firewall middleware
- Multi-language support
- Paid deployment infrastructure

---

## 8. Success Criteria

- [ ] All 4 models trained and compared
- [ ] Best model selected and saved
- [ ] Web UI functional with confidence + attack type
- [ ] REST API returns correct JSON responses
- [ ] App deployed with public URL
- [ ] GitHub repo with clean README and screenshots
