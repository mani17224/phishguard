"""
db.py  —  PhishGuard Pro
SQLite feedback store: log predictions, user corrections, drift detection.
"""
import sqlite3, json, time, os
from datetime import datetime, timezone, timedelta

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "phishguard.db")

def _conn(path=DB_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c

def init(path=DB_PATH):
    c = _conn(path)
    c.executescript("""
        CREATE TABLE IF NOT EXISTS predictions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT NOT NULL,
            verdict     TEXT NOT NULL,
            risk_tier   TEXT NOT NULL,
            probability REAL NOT NULL,
            prediction  INTEGER NOT NULL,
            features    TEXT,
            signals     TEXT,
            latency_ms  REAL,
            source      TEXT DEFAULT 'api',
            created_at  TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS feedback (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            prediction_id INTEGER REFERENCES predictions(id),
            url           TEXT NOT NULL,
            model_label   INTEGER NOT NULL,
            true_label    INTEGER NOT NULL,
            feedback_type TEXT NOT NULL,
            comment       TEXT,
            created_at    TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS retrain_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            n_samples  INTEGER, n_feedback INTEGER,
            roc_auc    REAL,    avg_precision REAL,
            trigger    TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_pred_url  ON predictions(url);
        CREATE INDEX IF NOT EXISTS idx_pred_tier ON predictions(risk_tier);
        CREATE INDEX IF NOT EXISTS idx_fb_type   ON feedback(feedback_type);
    """)
    c.commit(); c.close()

def log_prediction(url, result, source="api", path=DB_PATH):
    c = _conn(path)
    cur = c.execute(
        "INSERT INTO predictions (url,verdict,risk_tier,probability,prediction,features,signals,latency_ms,source) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (url, result.get("verdict",""), result.get("risk_tier",""),
         result.get("probability",0), result.get("prediction",0),
         json.dumps(result.get("all_features",{})),
         json.dumps(result.get("signals",[])),
         result.get("latency_ms",0), source)
    )
    pid = cur.lastrowid; c.commit(); c.close()
    return pid

def log_feedback(url, model_label, true_label, prediction_id=None, comment=None, path=DB_PATH):
    fb_type = ("correct" if model_label==true_label
               else "false_positive" if model_label==1
               else "false_negative")
    c = _conn(path)
    cur = c.execute(
        "INSERT INTO feedback (prediction_id,url,model_label,true_label,feedback_type,comment) "
        "VALUES (?,?,?,?,?,?)",
        (prediction_id, url, model_label, true_label, fb_type, comment)
    )
    fid = cur.lastrowid; c.commit(); c.close()
    return fid

def get_stats(days=7, path=DB_PATH):
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    c = _conn(path)
    total   = c.execute("SELECT COUNT(*) FROM predictions WHERE created_at>=?",(since,)).fetchone()[0]
    phish   = c.execute("SELECT COUNT(*) FROM predictions WHERE prediction=1 AND created_at>=?",(since,)).fetchone()[0]
    legit   = c.execute("SELECT COUNT(*) FROM predictions WHERE prediction=0 AND created_at>=?",(since,)).fetchone()[0]
    fp      = c.execute("SELECT COUNT(*) FROM feedback WHERE feedback_type='false_positive' AND created_at>=?",(since,)).fetchone()[0]
    fn      = c.execute("SELECT COUNT(*) FROM feedback WHERE feedback_type='false_negative' AND created_at>=?",(since,)).fetchone()[0]
    tiers   = dict(c.execute("SELECT risk_tier,COUNT(*) FROM predictions WHERE created_at>=? GROUP BY risk_tier",(since,)).fetchall())
    recent  = [dict(r) for r in c.execute("SELECT url,risk_tier,probability,created_at FROM predictions ORDER BY id DESC LIMIT 10").fetchall()]
    flagged = [dict(r) for r in c.execute(
        "SELECT url,COUNT(*) as cnt,AVG(probability) as avg_prob FROM predictions "
        "WHERE prediction=1 AND created_at>=? GROUP BY url ORDER BY cnt DESC LIMIT 10",(since,)).fetchall()]
    c.close()
    return {"period_days":days,"total_scans":total,"phishing_detected":phish,
            "legitimate":legit,"false_positives":fp,"false_negatives":fn,
            "tier_breakdown":tiers,"recent_scans":recent,"top_flagged_urls":flagged}

def get_feedback_samples(path=DB_PATH):
    c = _conn(path)
    rows = [dict(r) for r in c.execute(
        "SELECT url, true_label as label FROM feedback WHERE feedback_type!='correct' ORDER BY created_at DESC"
    ).fetchall()]
    c.close()
    return rows

def detect_drift(threshold=0.15, window_days=7, path=DB_PATH):
    since = (datetime.now(timezone.utc) - timedelta(days=window_days)).isoformat()
    c = _conn(path)
    total  = c.execute("SELECT COUNT(*) FROM feedback WHERE created_at>=?",(since,)).fetchone()[0]
    errors = c.execute("SELECT COUNT(*) FROM feedback WHERE feedback_type!='correct' AND created_at>=?",(since,)).fetchone()[0]
    c.close()
    if total < 10:
        return {"drift_detected":False,"reason":"insufficient_feedback","total_feedback":total}
    rate = errors/total
    return {"drift_detected":rate>threshold,"error_rate":round(rate,4),
            "threshold":threshold,"total_feedback":total,"errors":errors,
            "window_days":window_days,"recommendation":"retrain" if rate>threshold else "monitor"}

def log_retrain(n_samples, n_feedback, roc_auc, avg_precision, trigger="manual", path=DB_PATH):
    c = _conn(path)
    c.execute("INSERT INTO retrain_log (n_samples,n_feedback,roc_auc,avg_precision,trigger) VALUES (?,?,?,?,?)",
              (n_samples,n_feedback,roc_auc,avg_precision,trigger))
    c.commit(); c.close()
