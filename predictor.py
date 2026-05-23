"""
predictor.py  —  PhishGuard Pro
PhishingPredictor class: wraps model + feature extraction into one clean interface.
"""
import os, sys, json, time
import numpy as np
sys.path.insert(0, os.path.dirname(__file__))

import joblib
from features import extract_features, FEATURE_NAMES, BRANDS, LEGIT_DOMAINS, SUSPICIOUS_TLDS

KEYWORDS = {
    "login","signin","verify","secure","account","update","confirm","banking",
    "payment","credential","password","auth","recover","reset","unlock","validate",
}

class PhishingPredictor:
    def __init__(self, model_path=None, meta_path=None):
        base = os.path.dirname(__file__)
        model_path = model_path or os.path.join(base, "models", "model.pkl")
        meta_path  = meta_path  or os.path.join(base, "models", "metadata.json")
        self.model    = joblib.load(model_path)
        self.metadata = {}
        if meta_path and os.path.exists(meta_path):
            with open(meta_path) as f:
                self.metadata = json.load(f)

    def predict(self, url: str) -> dict:
        t0  = time.time()
        url = url.strip()
        if "://" not in url: url = "http://" + url

        feats = extract_features(url)
        X     = np.array([list(feats.values())], dtype=float)
        prob  = float(self.model.predict_proba(X)[0][1])
        pred  = int(self.model.predict(X)[0])

        tier    = "HIGH" if prob >= 0.75 else "MEDIUM" if prob >= 0.45 else "LOW"
        verdict = "Phishing Detected" if tier=="HIGH" else \
                  "Suspicious URL"    if tier=="MEDIUM" else "Likely Legitimate"

        signals      = self._signals(url, feats, prob)
        top_features = self._top_features(feats)

        return {
            "url":          url,
            "verdict":      verdict,
            "risk_tier":    tier,
            "probability":  round(prob, 4),
            "prediction":   pred,
            "signals":      signals,
            "top_features": top_features,
            "all_features": {k: round(float(v), 4) for k, v in feats.items()},
            "latency_ms":   round((time.time()-t0)*1000, 2),
        }

    def predict_batch(self, urls: list) -> dict:
        results = []
        for url in urls:
            try:    results.append(self.predict(url.strip()))
            except Exception as e: results.append({"url": url, "error": str(e)})
        phish  = sum(1 for r in results if r.get("prediction")==1)
        errors = sum(1 for r in results if "error" in r)
        return {"results": results,
                "summary": {"total":len(results),"phishing":phish,
                             "legitimate":len(results)-phish-errors,
                             "high_risk":sum(1 for r in results if r.get("risk_tier")=="HIGH"),
                             "errors":errors}}

    def _signals(self, url, f, prob):
        s = []
        if f.get("has_ip"):             s.append({"type":"danger",  "msg":"IP address used as hostname"})
        if f.get("brand_in_subdomain"): s.append({"type":"danger",  "msg":"Brand name in subdomain (impersonation)"})
        if f.get("suspicious_tld"):     s.append({"type":"danger",  "msg":"High-risk TLD detected"})
        if f.get("num_subdomains",0)>=3:s.append({"type":"danger",  "msg":f"{int(f['num_subdomains'])} subdomain levels"})
        if f.get("num_at",0)>0:         s.append({"type":"danger",  "msg":"@ in URL — may redirect to attacker"})
        if f.get("typosquat_detected"): s.append({"type":"danger",  "msg":"Typosquatting detected — resembles known brand"})
        if f.get("sensitive_keyword_count",0)>=2: s.append({"type":"warning","msg":f"{int(f['sensitive_keyword_count'])} sensitive keywords"})
        if f.get("url_entropy",0)>4.2:  s.append({"type":"warning", "msg":f"High entropy ({f['url_entropy']:.2f}) — possibly obfuscated"})
        if f.get("has_encoded_chars"):  s.append({"type":"warning", "msg":"URL-encoded chars may hide destination"})
        if f.get("known_legit_domain"): s.append({"type":"safe",    "msg":"Domain matches known legitimate site"})
        if not s: s.append({"type":"safe","msg":"No major phishing indicators detected"})
        return s

    def _top_features(self, feats):
        imp = self.metadata.get("feature_importances", {})
        if not imp: return []
        return sorted(
            [{"name":k,"importance":round(v,4),"value":round(float(feats.get(k,0)),4)}
             for k,v in imp.items()],
            key=lambda x: x["importance"], reverse=True)[:5]
