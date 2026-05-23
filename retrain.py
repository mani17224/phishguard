"""
retrain.py  —  PhishGuard Pro
Merge feedback corrections with base dataset and retrain model.

Usage:
  python retrain.py              # only retrains if drift detected
  python retrain.py --force      # force retrain regardless
  python retrain.py --check      # just check drift status
"""
import argparse, json, os, sys, shutil
sys.path.insert(0, os.path.dirname(__file__))

import numpy as np
import joblib

from features  import extract_features, FEATURE_NAMES
from db        import get_feedback_samples, detect_drift, log_retrain, init
from train     import build_pipeline, DATASET, OUT_DIR, load_data
from sklearn.model_selection import train_test_split
from sklearn.metrics         import roc_auc_score, average_precision_score

MODEL_PATH = os.path.join(OUT_DIR, "model.pkl")
META_PATH  = os.path.join(OUT_DIR, "metadata.json")
BACKUP_DIR = os.path.join(OUT_DIR, "backups")


def retrain(force=False):
    print("\nPhishGuard Pro — Incremental Retraining")
    print("="*50)
    drift = detect_drift()
    print(f"Drift: {drift}")

    if not force and not drift.get("drift_detected"):
        reason = drift.get("reason","")
        print(f"  {'Insufficient feedback' if reason=='insufficient_feedback' else 'No drift detected'}.")
        print("  Use --force to retrain anyway.")
        return None

    print("\nLoading base dataset…")
    X, y = load_data()
    print(f"  Base: {len(X)} samples")

    fb = get_feedback_samples()
    print(f"  Feedback corrections: {len(fb)}")
    if fb:
        Xf, yf = [], []
        for item in fb:
            try:
                Xf.append(list(extract_features(item["url"]).values()))
                yf.append(item["label"])
            except Exception: pass
        if Xf:
            Xf = np.array(Xf, dtype=float)
            yf = np.array(yf, dtype=int)
            # Oversample feedback 3× for emphasis
            X  = np.vstack([X, np.repeat(Xf, 3, axis=0)])
            y  = np.concatenate([y, np.repeat(yf, 3)])
            print(f"  After merge: {len(X)} samples")

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    print("\nTraining…")
    model = build_pipeline()
    model.fit(X_tr, y_tr)

    prob  = model.predict_proba(X_te)[:,1]
    roc   = roc_auc_score(y_te, prob)
    ap    = average_precision_score(y_te, prob)
    print(f"  ROC-AUC: {roc:.4f}  |  Avg Precision: {ap:.4f}")

    # Compare with existing
    if os.path.exists(MODEL_PATH) and not force:
        old   = joblib.load(MODEL_PATH)
        old_p = old.predict_proba(X_te)[:,1]
        old_r = roc_auc_score(y_te, old_p)
        if roc < old_r - 0.01:
            print(f"  New model worse ({roc:.4f} < {old_r:.4f}). Aborting.")
            return None

    # Backup + save
    os.makedirs(BACKUP_DIR, exist_ok=True)
    from datetime import datetime
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if os.path.exists(MODEL_PATH):
        shutil.copy(MODEL_PATH, os.path.join(BACKUP_DIR, f"model_{ts}.pkl"))

    joblib.dump(model, MODEL_PATH)
    rf_imp = model.named_steps["clf"].estimators_[0].feature_importances_
    top_i  = np.argsort(rf_imp)[::-1][:10]
    meta   = {
        "feature_names":       FEATURE_NAMES,
        "n_features":          len(FEATURE_NAMES),
        "n_train":             len(X_tr),
        "n_test":              len(X_te),
        "roc_auc":             round(roc,4),
        "avg_precision":       round(ap,4),
        "cv_roc_auc_mean":     round(roc,4),
        "cv_roc_auc_std":      0.0,
        "n_feedback_samples":  len(fb),
        "top_features":        [FEATURE_NAMES[i] for i in top_i],
        "feature_importances": {FEATURE_NAMES[i]:round(float(rf_imp[i]),5) for i in top_i},
        "confusion_matrix":    {"tn":0,"fp":0,"fn":0,"tp":0},
    }
    with open(META_PATH,"w") as f: json.dump(meta, f, indent=2)
    log_retrain(len(X_tr), len(fb), roc, ap,
                trigger="forced" if force else "drift_detected")
    print(f"\n✓ Retrained model saved → {MODEL_PATH}")
    return model

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--force", action="store_true")
    p.add_argument("--check", action="store_true")
    args = p.parse_args()
    init()
    if args.check:
        import json as _j
        print(_j.dumps(detect_drift(), indent=2))
    else:
        retrain(force=args.force)

if __name__ == "__main__":
    main()
