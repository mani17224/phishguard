# 🛡 PhishGuard Pro

**ML-powered phishing URL detection. Everything in one folder.**

---

## Project Layout

```
phishguard/
│
├── app.py           ← Flask API server  (START HERE to run)
├── features.py      ← 35-feature extraction engine
├── train.py         ← Model training pipeline
├── predictor.py     ← PhishingPredictor class
├── dataset.py       ← Synthetic training data generator
├── db.py            ← SQLite feedback + analytics store
├── retrain.py       ← Incremental retraining with feedback
├── cli.py           ← Command-line URL analyzer
├── tests.py         ← All 44 tests in one file
├── dashboard.html   ← Interactive web dashboard (open in browser)
│
├── extension/       ← Chrome/Edge browser extension
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── popup.html
│   ├── options.html
│   └── icons/
│
├── models/          ← Auto-created on first train
│   ├── model.pkl
│   ├── metadata.json
│   └── backups/
│
├── data/            ← Auto-created
│   ├── dataset.json
│   ├── sample_urls.txt
│   └── phishguard.db
│
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── Procfile         ← Railway / Render / Heroku
└── Makefile
```

---

## Quick Start (3 commands)

```bash
pip install -r requirements.txt   # 1. Install
python train.py                    # 2. Train model
python app.py                      # 3. Start API → http://localhost:5050
```

Then open `dashboard.html` in your browser.

---

## All Commands

| Command | What it does |
|---|---|
| `python train.py` | Generate data + train RF+GBT ensemble |
| `python app.py` | Start Flask API on port 5050 |
| `python tests.py` | Run all 44 tests |
| `python cli.py --url "http://..."` | Analyze a URL in terminal |
| `python cli.py --file data/sample_urls.txt` | Batch analyze |
| `python retrain.py` | Retrain using user feedback |
| `python retrain.py --force` | Force retrain |
| `python retrain.py --check` | Check drift status |

Or with `make`:
```bash
make setup       # generate data + train
make run         # start server
make test        # run all tests
make cli URL=http://paypal-secure.xyz/login
make batch
make retrain
```

---

## API Reference

Base URL: `http://localhost:5050`

### Single prediction
```bash
curl -X POST http://localhost:5050/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-secure.xyz/login"}'
```

Response:
```json
{
  "url": "http://paypal-secure.xyz/login",
  "verdict": "Phishing Detected",
  "risk_tier": "HIGH",
  "probability": 0.9641,
  "signals": [
    {"type": "danger",  "msg": "High-risk TLD detected (.xyz)"},
    {"type": "warning", "msg": "2 sensitive keywords in URL"}
  ],
  "top_features": [...],
  "all_features": {"url_length": 38, ...},
  "latency_ms": 14.3
}
```

### Batch
```bash
curl -X POST http://localhost:5050/predict/batch \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://google.com", "http://evil.xyz/login"]}'
```

### Feedback (improves model)
```bash
curl -X POST http://localhost:5050/feedback \
  -H "Content-Type: application/json" \
  -d '{"url": "http://...", "model_label": 1, "true_label": 0}'
```

### Other endpoints
| Endpoint | Description |
|---|---|
| `GET /health` | Server status |
| `GET /model/info` | ROC-AUC, feature importances |
| `GET /features` | All 35 feature names |
| `GET /stats?days=7` | Analytics dashboard data |
| `GET /drift` | Model drift check |

---

## The 35 Features

| Group | Features |
|---|---|
| URL lexical | length, entropy, dots, hyphens, @, ?, =, &, %, digit ratio, longest word |
| Host | length, entropy, vowel ratio, subdomain depth, IP detection, TLD risk |
| Semantic | sensitive keywords, brand in subdomain/domain/path, known-legit match |
| Path/Query | path length, query length, param count, encoded chars, HTTPS |
| Typosquat | similarity score, detected flag (Levenshtein + Jaro-Winkler + n-gram) |

---

## Browser Extension

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → select `extension/` folder

The extension scans every page you visit, shows a badge (✓/⚠/?), and injects a red banner on HIGH-risk pages.

---

## Deployment

### Docker (recommended)
```bash
docker-compose up --build -d
# API running at http://localhost:5050
```

### Gunicorn (production)
```bash
pip install gunicorn
python train.py
gunicorn -w 4 -b 0.0.0.0:5050 app:app
```

### Railway / Render / Heroku
```bash
# Procfile is included — just connect your GitHub repo and deploy
# Set PORT environment variable if needed
```

### Environment Variables
```bash
PORT=5050       # API port (default 5050)
HOST=0.0.0.0    # Bind address
DEBUG=false     # Flask debug mode
```

---

## Model Performance

| Metric | Value |
|---|---|
| ROC-AUC | 1.0000 |
| Avg Precision | 1.0000 |
| 5-fold CV AUC | 1.0000 ± 0.0000 |
| False Positives | 0 |
| False Negatives | 0 |
| Ensemble | RF (200 trees) + GBT (150 trees) |
| Features | 35 |

---

## Python Client

```python
import requests

def scan(url, api="http://localhost:5050"):
    r = requests.post(f"{api}/predict", json={"url": url})
    r.raise_for_status()
    return r.json()

result = scan("http://paypal-secure.xyz/login")
print(result["verdict"], result["probability"])
# → Phishing Detected  0.9641
```
