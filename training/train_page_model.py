"""
Train the page-content model used by the Deep check.

Data: the PhiUSIIL Phishing URL Dataset (Prasad & Chandra, 2024), which records
features of each site's HTML. In PhiUSIIL, label 1 means legitimate and 0 means
phishing; here it is flipped so that 1 means phishing, as in the rest of the project.

Only 15 behaviour features are used. The size features (lines of code, number of
links, images and so on) are left out on purpose: in PhiUSIIL most phishing pages
were tiny when crawled, so those features mainly teach the model "small page means
phishing", which does not hold for live phishing kits.

Usage: python training/train_page_model.py path/to/PhiUSIIL_Phishing_URL_Dataset.csv
"""
import hashlib
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from pagefeatures import FEATURES  # noqa: E402
from compactforest import compact  # noqa: E402

SEED = 42
MODELS = os.path.join(HERE, "models")


def models():
    return {
        "Random Forest": RandomForestClassifier(n_estimators=150, max_depth=16, min_samples_leaf=2, n_jobs=-1, random_state=SEED),
        "XGBoost": XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1, subsample=0.8,
                                 eval_metric="logloss", n_jobs=-1, random_state=SEED),
        "Naive Bayes": GaussianNB(),
        "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000)),
    }


def main(path):
    d = pd.read_csv(path, usecols=FEATURES + ["label"])
    X = d[FEATURES].values.astype(np.float32)
    y = (d["label"] == 0).astype(int).values
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=SEED)
    print(f"rows {len(d):,} | train {len(Xtr):,} | test {len(Xte):,} | phishing share {y.mean():.1%}")

    P = {}
    for name, m in models().items():
        P[name] = m.fit(Xtr, ytr).predict_proba(Xte)[:, 1]
    P["Equal-weight vote (RF + XGBoost + NB)"] = (P["Random Forest"] + P["XGBoost"] + P["Naive Bayes"]) / 3
    P["Deployed ensemble (RF + XGBoost + LR)"] = (P["Random Forest"] + P["XGBoost"] + P["Logistic Regression"]) / 3
    rows = []
    for name, p in P.items():
        pred = (p >= 0.5).astype(int)
        rows.append({"Model": name, "Accuracy": accuracy_score(yte, pred), "Precision": precision_score(yte, pred),
                     "Recall": recall_score(yte, pred), "F1": f1_score(yte, pred), "AUC": roc_auc_score(yte, p)})
    res = pd.DataFrame(rows).set_index("Model")
    print(res.round(4).to_string())
    p = P["Deployed ensemble (RF + XGBoost + LR)"]
    for lab, nm in [(1, "phishing pages"), (0, "legitimate pages")]:
        s = p[yte == lab]
        print(f"bands, {nm}: legitimate {np.mean(s < .35):.3f} | not clear cut {np.mean((s >= .35) & (s < .65)):.3f} | phishing {np.mean(s >= .65):.3f}")
    res.to_csv(os.path.join(HERE, "training", "page_model_results.csv"))

    # final models on all the data
    final = models()
    rf = final["Random Forest"].fit(X, y)
    xgb = final["XGBoost"].fit(X, y)
    lr = final["Logistic Regression"].fit(X, y)
    compact(rf, os.path.join(MODELS, "page_rf_forest.npz"))
    xgb.get_booster().save_model(os.path.join(MODELS, "page_xgb.ubj"))
    joblib.dump({"lr": lr, "features": FEATURES, "low": 0.35, "high": 0.65}, os.path.join(MODELS, "page_parts.joblib"), compress=3)

    info_path = os.path.join(MODELS, "build_info.json")
    info = json.load(open(info_path))
    for n in ["page_rf_forest.npz", "page_xgb.ubj", "page_parts.joblib"]:
        fp = os.path.join(MODELS, n)
        info["files"][n] = {"bytes": os.path.getsize(fp), "sha256": hashlib.sha256(open(fp, "rb").read()).hexdigest()}
    json.dump(info, open(info_path, "w"), indent=2)
    print("saved page models")


if __name__ == "__main__":
    main(sys.argv[1])
