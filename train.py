"""
train.py  —  PhishGuard Pro
Train RF + GradientBoosting ensemble. Saves model + metadata to models/.
Run:  python train.py
"""
import json, os, sys, numpy as np
sys.path.insert(0, os.path.dirname(__file__))

import joblib
from features import extract_features, FEATURE_NAMES
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    classification_report, roc_auc_score, average_precision_score, confusion_matrix
)

DATASET  = os.path.join(os.path.dirname(__file__), "data", "dataset.json")
OUT_DIR  = os.path.join(os.path.dirname(__file__), "models")

def load_data(path=DATASET):
    with open(path) as f: raw = json.load(f)
    X, y = [], []
    for item in raw:
        try:
            X.append(list(extract_features(item["url"]).values()))
            y.append(item["label"])
        except Exception:
            pass
    return np.array(X, dtype=float), np.array(y, dtype=int)

def build_pipeline():
    rf = RandomForestClassifier(
        n_estimators=200, max_depth=20, min_samples_split=4,
        class_weight="balanced", random_state=42, n_jobs=-1)
    gb = GradientBoostingClassifier(
        n_estimators=150, learning_rate=0.08, max_depth=6,
        subsample=0.8, random_state=42)
    vc = VotingClassifier([("rf", rf), ("gb", gb)], voting="soft", weights=[1.5, 1.0])
    return Pipeline([("scaler", StandardScaler()), ("clf", vc)])

def train(dataset_path=DATASET, out_dir=OUT_DIR):
    os.makedirs(out_dir, exist_ok=True)
    print("Loading dataset…")
    X, y = load_data(dataset_path)
    print(f"  {len(X)} samples | {X.shape[1]} features | "
          f"legit={( y==0).sum()} phish={(y==1).sum()}")

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    print("Training RF + GradientBoosting ensemble…")
    model = build_pipeline()
    model.fit(X_tr, y_tr)

    y_pred = model.predict(X_te)
    y_prob = model.predict_proba(X_te)[:,1]
    roc    = roc_auc_score(y_te, y_prob)
    ap     = average_precision_score(y_te, y_prob)
    tn,fp,fn,tp = confusion_matrix(y_te, y_pred).ravel()

    cv = cross_val_score(model, X, y,
         cv=StratifiedKFold(5, shuffle=True, random_state=42),
         scoring="roc_auc", n_jobs=-1)

    print(f"\n{'='*50}")
    print(classification_report(y_te, y_pred, target_names=["Legit","Phishing"]))
    print(f"ROC-AUC:       {roc:.4f}")
    print(f"Avg Precision: {ap:.4f}")
    print(f"CV AUC:        {cv.mean():.4f} ± {cv.std():.4f}")
    print(f"TN={tn}  FP={fp}  FN={fn}  TP={tp}")

    rf_clf = model.named_steps["clf"].estimators_[0]
    imp    = rf_clf.feature_importances_
    top_i  = np.argsort(imp)[::-1][:10]
    print(f"\nTop features:")
    for i in top_i:
        print(f"  {FEATURE_NAMES[i]:<32} {imp[i]:.4f}")

    model_path = os.path.join(out_dir, "model.pkl")
    meta_path  = os.path.join(out_dir, "metadata.json")
    joblib.dump(model, model_path)
    meta = {
        "feature_names":       FEATURE_NAMES,
        "n_features":          len(FEATURE_NAMES),
        "n_train":             len(X_tr),
        "n_test":              len(X_te),
        "roc_auc":             round(roc,4),
        "avg_precision":       round(ap,4),
        "cv_roc_auc_mean":     round(float(cv.mean()),4),
        "cv_roc_auc_std":      round(float(cv.std()),4),
        "confusion_matrix":    {"tn":int(tn),"fp":int(fp),"fn":int(fn),"tp":int(tp)},
        "top_features":        [FEATURE_NAMES[i] for i in top_i],
        "feature_importances": {FEATURE_NAMES[i]:round(float(imp[i]),5) for i in top_i},
    }
    with open(meta_path, "w") as f: json.dump(meta, f, indent=2)
    print(f"\n✓ Model  → {model_path}")
    print(f"✓ Meta   → {meta_path}")
    return model, meta

if __name__ == "__main__":
    # Auto-generate dataset if missing
    if not os.path.exists(DATASET):
        print("Dataset not found — generating…")
        import dataset as ds
        os.makedirs(os.path.dirname(DATASET), exist_ok=True)
        data = ds.generate()
        with open(DATASET, "w") as f: json.dump(data, f)
    train()
