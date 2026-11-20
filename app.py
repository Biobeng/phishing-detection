"""
Intelligent Phishing Detection System for Emails and Websites.

Flask back end. It loads the two saved models once at start up, then scores
whatever the user pastes in. The system reads text only. It never opens or
visits a submitted link.
"""
import os
import re
import sys

import joblib
import pandas as pd
import xgboost
from flask import Flask, jsonify, render_template, request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import urlfeatures as uf          # noqa: E402
import urlprep as up              # noqa: E402
from compactforest import CompactForest  # noqa: E402

MODELS = os.environ.get("MODEL_DIR", os.path.join(HERE, "models"))

app = Flask(__name__)

def fail(filename, problem):
    import sklearn
    line = "=" * 72
    print(f"\n{line}\nCould not load {filename}.\n")
    print(f"  {type(problem).__name__}: {problem}\n")
    try:
        import json
        with open(os.path.join(MODELS, "build_info.json")) as fh:
            built = json.load(fh)["must_match"]["sklearn"]
        print(f"The scikit-learn parts were saved with version {built}.")
        print(f"This python has version {sklearn.__version__}.")
    except Exception:
        pass
    print("\nRun check_setup.py first. It says exactly what is wrong:\n")
    print(f'  "{sys.executable}" check_setup.py')
    print(f"\n{line}\n")
    sys.exit(1)


def booster(filename):
    """XGBoost's own format, which travels between machines unlike a pickle."""
    model = xgboost.Booster()
    model.load_model(os.path.join(MODELS, filename))
    return model


try:
    url_parts = joblib.load(os.path.join(MODELS, "url_parts.joblib"))
except Exception as problem:
    fail("url_parts.joblib", problem)
try:
    url_rf = CompactForest(os.path.join(MODELS, "url_rf_forest.npz"))
except Exception as problem:
    fail("url_rf_forest.npz", problem)
try:
    email_parts = joblib.load(os.path.join(MODELS, "email_parts.joblib"))
except Exception as problem:
    fail("email_parts.joblib", problem)

# If a booster will not load the app still runs, scoring with the models that
# did load, and the interface shows which ones those were.
url_xgb, email_xgb = None, None
try:
    url_xgb = booster("url_xgb.ubj")
    email_xgb = booster("email_xgb.ubj")
except Exception as problem:
    print(f"\nXGBoost did not load ({type(problem).__name__}: {problem}).")
    print("The app will run on the remaining models and say so on screen.\n")

# cut points for the three bands. The link numbers are the ones measured on the
# held out test set; the email model is sharper so its lower cut sits higher.
URL_LOW, URL_HIGH = url_parts.get("low", 0.35), url_parts.get("high", 0.65)
EMAIL_LOW, EMAIL_HIGH = 0.40, 0.70

MIN_EMAIL_WORDS = 5


def band(score, low, high):
    if score >= high:
        return "phishing"
    if score >= low:
        return "suspicious"
    return "legitimate"


def score_link(text):
    """Returns the ensemble score and what each model said on its own."""
    frame = pd.DataFrame([uf.features(text)])
    parts = []
    if url_xgb is not None:
        matrix = xgboost.DMatrix(url_parts["pre_xgb"].transform(frame))
        parts.append({"name": "XGBoost", "score": float(url_xgb.predict(matrix)[0])})
    parts.append({"name": "Random Forest", "score": float(url_rf.predict_proba(url_parts["rf_pre"].transform(frame))[0, 1])})
    parts.append({"name": "Logistic Regression",
                  "score": float(url_parts["lr"].predict_proba(url_parts["tfidf"].transform([text]))[0, 1])})
    return sum(p["score"] for p in parts) / len(parts), parts, frame.iloc[0]


def score_email(document):
    vector = email_parts["tfidf"].transform([document])
    parts = [
        {"name": "Random Forest", "score": float(email_parts["rf"].predict_proba(vector)[0, 1])},
    ]
    if email_xgb is not None:
        parts.append({"name": "XGBoost", "score": float(email_xgb.predict(xgboost.DMatrix(vector))[0])})
    parts.append({"name": "Naive Bayes", "score": float(email_parts["nb"].predict_proba(vector)[0, 1])})
    return sum(p["score"] for p in parts) / len(parts), parts


def link_signals(row, form):
    """A short, readable account of what the model was looking at."""
    out = [
        {"label": "Address form",
         "value": "Full link with a path" if form == "path" else "Website address only"},
        {"label": "Length", "value": f"{int(row['url_len'])} characters"},
        {"label": "Subdomains", "value": int(row["n_subdomains"]),
         "flag": bool(row["n_subdomains"] >= 3)},
        {"label": "Words linked to phishing", "value": int(row["keyword_hits"]),
         "flag": bool(row["keyword_hits"] >= 1)},
    ]
    extras = [
        (bool(row["has_ip"] == 1), "Address is a raw IP, not a domain name"),
        (bool(row["has_at"] == 1), "Contains an @ sign"),
        (bool(row["has_embedded_url"] == 1), "Another web address is buried inside it"),
        (bool(row["n_hyphens_host"] >= 2), f"{int(row['n_hyphens_host'])} hyphens in the domain name"),
        (bool(row["n_digits_host"] >= 3), f"{int(row['n_digits_host'])} digits in the domain name"),
    ]
    for present, note in extras:
        if present:
            out.append({"label": "Also noted", "value": note, "flag": True})
    return out


@app.get("/")
def home():
    return render_template("index.html")


@app.post("/api/check")
def check():
    payload = request.get_json(silent=True) or {}
    mode = payload.get("mode", "link")
    raw = (payload.get("text") or "").strip()
    subject = (payload.get("subject") or "").strip()

    if mode == "link":
        if not raw:
            return jsonify(error="Paste a web address to check."), 400
        if re.search(r"\s", raw):
            return jsonify(error="That looks like more than one address. Check them one at a time."), 400
        text, form = up.prepare(raw)
        if form is None:
            reason = ("Type the address in full, for example shop.example.com."
                      if text == "empty" else
                      "That address has no usable domain name. Raw IP addresses and unknown endings cannot be read.")
            return jsonify(error=reason), 400
        score, models, row = score_link(text)
        signals = link_signals(row, form)
        read_as = text
        low, high = URL_LOW, URL_HIGH
    else:
        words = len(raw.split())
        if not raw:
            return jsonify(error="Paste the body of the email you want checked."), 400
        if words < MIN_EMAIL_WORDS:
            return jsonify(error=f"Only {words} word{'s' if words != 1 else ''} to read. Paste more of the message."), 400
        document = f"{subject} {raw}".strip()
        score, models = score_email(document)
        signals = [
            {"label": "Words read", "value": words},
            {"label": "Subject line", "value": "Included" if subject else "Not given"},
        ]
        read_as = subject or raw[:70]
        low, high = EMAIL_LOW, EMAIL_HIGH

    return jsonify(
        verdict=band(score, low, high),
        score=round(score * 100, 1),
        models=[{"name": m["name"], "score": round(m["score"] * 100, 1)} for m in models],
        signals=signals,
        read_as=read_as,
        marks={"low": low * 100, "high": high * 100},
        mode=mode,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
