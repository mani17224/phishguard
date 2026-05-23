"""
app.py  —  PhishGuard Pro
Single-file Flask API. All routes in one place.

Endpoints:
  GET  /              API index
  GET  /health        Health check
  GET  /model/info    Model metadata
  GET  /features      Feature list (35)
  POST /predict       Single URL
  POST /predict/batch Batch (max 50)
  POST /feedback      User correction
  GET  /stats         Analytics (last N days)
  GET  /drift         Drift check

Run:
  python app.py
  OR
  gunicorn -w 4 -b 0.0.0.0:5050 app:app
"""
import os, sys, json, time, traceback
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify, g

import db
from features import FEATURE_NAMES
from predictor import PhishingPredictor

app = Flask(__name__)

# ── Load model once at startup ───────────────────────────────────
_predictor = None

def _load():
    global _predictor
    try:
        _predictor = PhishingPredictor()
        print(f"[PhishGuard] Model loaded — {len(FEATURE_NAMES)} features")
    except FileNotFoundError:
        print("[PhishGuard] WARNING: model not found. Run: python train.py")

# ── Rate limiter (in-memory) ─────────────────────────────────────
_rate: dict = {}

@app.before_request
def _before():
    g.t0 = time.time()
    ip   = request.remote_addr or "unknown"
    now  = time.time()
    _rate[ip] = [t for t in _rate.get(ip, []) if now-t < 60]
    if len(_rate[ip]) >= 120:
        return jsonify({"error": "Rate limit exceeded — 120 req/min"}), 429
    _rate[ip].append(now)

@app.after_request
def _after(r):
    r.headers["Access-Control-Allow-Origin"]  = "*"
    r.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    r.headers["Access-Control-Allow-Headers"] = "Content-Type"
    r.headers["X-Response-Time"] = f"{(time.time()-g.t0)*1000:.1f}ms"
    r.headers["X-Powered-By"]   = "PhishGuard Pro v2.3"
    return r

# ── Routes ───────────────────────────────────────────────────────
@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "name": "PhishGuard Pro API", "version": "2.3.0",
        "model_loaded": _predictor is not None,
        "endpoints": {
            "GET  /health":         "Health check",
            "GET  /model/info":     "Model metadata & performance",
            "GET  /features":       "All 35 feature names",
            "POST /predict":        "Single URL prediction",
            "POST /predict/batch":  "Batch (max 50 URLs)",
            "POST /feedback":       "Submit correction",
            "GET  /stats":          "Analytics (?days=7)",
            "GET  /drift":          "Model drift status",
        }
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status":"ok","model_loaded":_predictor is not None,
                    "n_features":len(FEATURE_NAMES)})

@app.route("/model/info", methods=["GET"])
def model_info():
    if not _predictor:
        return jsonify({"error":"Model not loaded"}), 503
    return jsonify(_predictor.metadata)

@app.route("/features", methods=["GET"])
def features():
    return jsonify({"features":FEATURE_NAMES,"count":len(FEATURE_NAMES)})

@app.route("/predict", methods=["POST","OPTIONS"])
def predict():
    if request.method == "OPTIONS": return "", 200
    if not _predictor: return jsonify({"error":"Model not loaded — run train.py"}), 503
    body = request.get_json(force=True, silent=True) or {}
    url  = body.get("url","").strip()
    if not url:         return jsonify({"error":"Missing 'url'"}), 400
    if len(url) > 2000: return jsonify({"error":"URL too long (max 2000)"}), 400
    try:
        result = _predictor.predict(url)
        pid    = db.log_prediction(url, result, source="api")
        result["prediction_id"] = pid
        return jsonify(result)
    except Exception as e:
        return jsonify({"error":str(e),"trace":traceback.format_exc()}), 500

@app.route("/predict/batch", methods=["POST","OPTIONS"])
def predict_batch():
    if request.method == "OPTIONS": return "", 200
    if not _predictor: return jsonify({"error":"Model not loaded"}), 503
    body = request.get_json(force=True, silent=True) or {}
    urls = body.get("urls", [])
    if not urls or not isinstance(urls, list):
        return jsonify({"error":"Missing 'urls' list"}), 400
    if len(urls) > 50:
        return jsonify({"error":"Max 50 URLs per batch"}), 400
    batch = _predictor.predict_batch(urls)
    for r in batch["results"]:
        if "error" not in r:
            db.log_prediction(r["url"], r, source="batch")
    return jsonify(batch)

@app.route("/feedback", methods=["POST","OPTIONS"])
def feedback():
    if request.method == "OPTIONS": return "", 200
    body = request.get_json(force=True, silent=True) or {}
    url         = body.get("url","").strip()
    model_label = body.get("model_label")
    true_label  = body.get("true_label")
    comment     = body.get("comment","")
    pred_id     = body.get("prediction_id")
    if not url or model_label is None or true_label is None:
        return jsonify({"error":"url, model_label, true_label required"}), 400
    fid = db.log_feedback(url, int(model_label), int(true_label),
                          prediction_id=pred_id, comment=comment)
    fb_type = ("false_positive" if model_label==1 and true_label==0
               else "false_negative" if model_label==0 and true_label==1
               else "correct")
    return jsonify({"ok":True,"feedback_id":fid,"type":fb_type})

@app.route("/stats", methods=["GET"])
def stats():
    days = int(request.args.get("days", 7))
    return jsonify(db.get_stats(days=days))

@app.route("/drift", methods=["GET"])
def drift():
    return jsonify(db.detect_drift())

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error":"Not found","path":request.path}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error":"Internal server error"}), 500

if __name__ == "__main__":
    db.init()
    _load()
    port = int(os.getenv("PORT", 5050))
    host = os.getenv("HOST", "0.0.0.0")
    print(f"[PhishGuard] Starting on http://{host}:{port}")
    app.run(host=host, port=port, debug=os.getenv("DEBUG","false").lower()=="true")
