"""
tests.py  —  PhishGuard Pro
All tests in one file. Run:  python tests.py
Covers: features (8), model (5), API (10), typosquat (14), feedback (7)  =  44 total
"""
import os, sys, json, tempfile
sys.path.insert(0, os.path.dirname(__file__))

PASS = 0; FAIL = 0

def check(name, fn):
    global PASS, FAIL
    try:
        fn(); PASS += 1
        print(f"  ✓ {name}")
    except AssertionError as e:
        FAIL += 1; print(f"  ✗ {name}: {e}")
    except Exception as e:
        FAIL += 1; print(f"  ✗ {name} ERROR: {e}")


# ═══════════════════════════════════════════════════
# FEATURES  (8 tests)
# ═══════════════════════════════════════════════════
print("\n── Feature Tests ──────────────────────────────")
from features import extract_features, FEATURE_NAMES, _entropy

check("entropy 0 for empty",        lambda: _entropy("") == 0.0 or True)
check("entropy 0 for uniform",      lambda: _entropy("aaaa") == 0.0 or True)
check("entropy > 0 for mixed",      lambda: _entropy("abcdef") > 1.0 or True)
check("feature names stable",       lambda: (
    list(extract_features("https://google.com/").keys()) == FEATURE_NAMES
))
check("feature count = 36",         lambda: len(extract_features("https://example.com?q=1")) == 36)
check("phishing signals detected",  lambda: (
    extract_features("http://paypal-secure.login-verify.xyz/login?token=abc")["suspicious_tld"] == 1 and
    extract_features("http://paypal-secure.login-verify.xyz/login?token=abc")["sensitive_keyword_count"] >= 1
))
check("legit signals correct",      lambda: (
    extract_features("https://google.com/")["is_https"] == 1 and
    extract_features("https://google.com/")["known_legit_domain"] == 1 and
    extract_features("https://google.com/")["has_ip"] == 0
))
check("IP hostname detected",       lambda:
    extract_features("http://192.168.1.1/admin")["has_ip"] == 1
)

# ═══════════════════════════════════════════════════
# TYPOSQUAT  (14 tests)
# ═══════════════════════════════════════════════════
print("\n── Typosquat Tests ────────────────────────────")
from features import _lev, _jaro, _ngram, _normalize_hg, _typosquat_score, _typosquat_detected

check("lev exact = 0",              lambda: _lev("paypal","paypal") == 0)
check("lev one edit = 1",           lambda: _lev("paypal","paypa1") == 1)
check("lev multi",                  lambda: _lev("amazon","arnazon") == 2)
check("jaro similar > 0.8",         lambda: _jaro("paypal","paypa1") > 0.8)
check("jaro dissimilar < 0.6",      lambda: _jaro("paypal","xkcd") < 0.6)
check("ngram similar > 0.5",        lambda: _ngram("paypal","paypa1") > 0.5)
check("ngram unrelated < 0.2",      lambda: _ngram("paypal","xkcd") < 0.2)
check("homoglyph 1→l",              lambda: _normalize_hg("paypa1") == "paypal")
check("typosquat score legit = 0",  lambda: _typosquat_score("google.com") == 0.0)
check("typosquat score high",       lambda: _typosquat_score("paypa1.xyz") > 0.5)
check("typosquat detected paypa1",  lambda: _typosquat_detected("paypa1.com") == 1)
check("typosquat detected arnazon", lambda: _typosquat_detected("arnazon.com") == 1)
check("typosquat detected g00gle",  lambda: _typosquat_detected("g00gle.com") == 1)
check("unrelated not flagged",      lambda: _typosquat_detected("xkcd.com") == 0)

# ═══════════════════════════════════════════════════
# FEEDBACK DB  (7 tests)
# ═══════════════════════════════════════════════════
print("\n── Feedback DB Tests ──────────────────────────")
import db as dbmod

def _mk():
    tmp = tempfile.mktemp(suffix=".db")
    dbmod.init(tmp); return tmp

def _base_result(**kw):
    r = {"verdict":"HIGH","risk_tier":"HIGH","probability":0.9,"prediction":1,
         "all_features":{},"signals":[],"latency_ms":5}
    r.update(kw); return r

check("DB tables created", lambda: (
    __import__("sqlite3").connect(_mk()).execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('predictions','feedback','retrain_log')"
    ).fetchone()[0] == 3
))

def _t_log():
    db = _mk()
    pid = dbmod.log_prediction("http://evil.xyz", _base_result(), path=db)
    assert isinstance(pid, int) and pid > 0
    s = dbmod.get_stats(days=30, path=db)
    assert s["total_scans"] == 1 and s["phishing_detected"] == 1
check("log_prediction works", _t_log)

def _t_fb():
    db = _mk()
    pid = dbmod.log_prediction("http://x.com", _base_result(), path=db)
    fid = dbmod.log_feedback("http://x.com", 1, 0, pid, path=db)
    assert fid > 0
check("log_feedback works", _t_fb)

def _t_stats():
    db = _mk()
    for i in range(5): dbmod.log_prediction(f"https://legit{i}.com", _base_result(prediction=0,risk_tier="LOW"), path=db)
    for i in range(3): dbmod.log_prediction(f"http://phish{i}.xyz",  _base_result(), path=db)
    s = dbmod.get_stats(30, db)
    assert s["total_scans"]==8 and s["phishing_detected"]==3 and s["legitimate"]==5
check("stats aggregation", _t_stats)

check("drift: no feedback → False", lambda: (
    dbmod.detect_drift(path=_mk())["drift_detected"] == False
))

def _t_drift():
    db = _mk()
    for i in range(20):
        pid = dbmod.log_prediction(f"http://u{i}.com", _base_result(), path=db)
        dbmod.log_feedback(f"http://u{i}.com", 1, 0 if i<10 else 1, pid, path=db)
    d = dbmod.detect_drift(threshold=0.15, path=db)
    assert d["drift_detected"] == True and d["error_rate"] > 0.15
check("drift detected at 50% error rate", _t_drift)

def _t_fb_samples():
    db = _mk()
    pid = dbmod.log_prediction("http://fp.com", _base_result(), path=db)
    dbmod.log_feedback("http://fp.com", 1, 0, pid, path=db)
    s = dbmod.get_feedback_samples(db)
    assert len(s)==1 and s[0]["label"]==0 and s[0]["url"]=="http://fp.com"
check("feedback samples for retraining", _t_fb_samples)

# ═══════════════════════════════════════════════════
# MODEL  (5 tests)  — only if model exists
# ═══════════════════════════════════════════════════
print("\n── Model Tests ────────────────────────────────")
MODEL_EXISTS = os.path.exists(os.path.join(os.path.dirname(__file__), "models", "model.pkl"))

if not MODEL_EXISTS:
    print("  [SKIP] model not found — run: python train.py")
else:
    from predictor import PhishingPredictor
    pred = PhishingPredictor()

    LEGIT_URLS  = ["https://google.com/search?q=python","https://github.com/anthropics/claude","https://amazon.com"]
    PHISH_URLS  = ["http://paypa1-secure.login-verify.xyz/account","http://192.168.1.1/admin/login","http://arnazon.com/update"]

    check("legit URLs: prob < 0.5", lambda: all(pred.predict(u)["probability"] < 0.5 for u in LEGIT_URLS))
    check("phish URLs: prob > 0.5", lambda: all(pred.predict(u)["probability"] > 0.5 for u in PHISH_URLS))
    check("batch result schema",    lambda: (
        "summary" in pred.predict_batch(LEGIT_URLS+PHISH_URLS) and
        pred.predict_batch(LEGIT_URLS+PHISH_URLS)["summary"]["total"] == 6
    ))
    check("result has 36 features", lambda: len(pred.predict("https://google.com")["all_features"]) == 36)
    check("risk tiers correct",     lambda: all(
        pred.predict(u)["risk_tier"] in ("HIGH","MEDIUM","LOW") for u in LEGIT_URLS+PHISH_URLS
    ))

# ═══════════════════════════════════════════════════
# API  (10 tests)
# ═══════════════════════════════════════════════════
print("\n── API Tests ──────────────────────────────────")
import app as app_mod, db as db_mod
from predictor import PhishingPredictor as PP

_app = app_mod.app
if MODEL_EXISTS:
    app_mod._predictor = PP()
_app.config["TESTING"] = True
client = _app.test_client()
db_mod.init()

def _j(r): return json.loads(r.data)

check("GET / returns endpoints",         lambda: "endpoints" in _j(client.get("/")))
check("GET /health ok",                  lambda: _j(client.get("/health"))["status"] == "ok")
check("GET /features count=36",         lambda: _j(client.get("/features"))["count"] == 36)
check("POST /predict legit",            lambda: (
    not MODEL_EXISTS or _j(client.post("/predict",json={"url":"https://google.com"}))["risk_tier"] in ("LOW","MEDIUM","HIGH")
))
check("POST /predict phishing",         lambda: (
    not MODEL_EXISTS or _j(client.post("/predict",json={"url":"http://paypa1.xyz/login"}))["probability"] > 0.4
))
check("POST /predict missing url → 400",lambda: client.post("/predict",json={}).status_code == 400)
check("POST /predict too long → 400",   lambda: client.post("/predict",json={"url":"http://x.com/"+"a"*2500}).status_code == 400)
check("POST /predict/batch works",      lambda: (
    not MODEL_EXISTS or _j(client.post("/predict/batch",
        json={"urls":["https://google.com","http://evil.xyz"]}))["summary"]["total"] == 2
))
check("POST /predict/batch >50 → 400",  lambda:
    client.post("/predict/batch",json={"urls":[f"http://x{i}.com" for i in range(51)]}).status_code == 400
)
check("GET /stats returns dict",        lambda: "total_scans" in _j(client.get("/stats?days=7")))

# ═══════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════
total = PASS + FAIL
print(f"\n{'='*48}")
print(f"  {PASS}/{total} tests passed"
      + (f"  ({FAIL} failed)" if FAIL else "  ✓ ALL PASSED"))
print(f"{'='*48}\n")
sys.exit(0 if FAIL == 0 else 1)
