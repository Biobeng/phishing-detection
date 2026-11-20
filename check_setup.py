"""
Run this before app.py. It checks the model files are intact, checks the one
library version that has to match, then loads everything and scores a test
link and a test email.

    python check_setup.py
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

print(f"python {sys.version.split()[0]}")
print(f"running from {sys.executable}\n")

info_path = os.path.join(HERE, "models", "build_info.json")
if not os.path.exists(info_path):
    print("models/build_info.json is missing. Unzip the folder again.")
    sys.exit(1)
BUILD = json.load(open(info_path))


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---- 1. are the model files whole? a half finished download lands here
broken = []
for name, want in BUILD["files"].items():
    path = os.path.join(HERE, "models", name)
    if not os.path.exists(path):
        print(f"  {name:<22} missing")
        broken.append(name)
        continue
    size = os.path.getsize(path)
    if size != want["bytes"]:
        print(f"  {name:<22} {size:,} bytes, expected {want['bytes']:,}   INCOMPLETE")
        broken.append(name)
    elif digest(path) != want["sha256"]:
        print(f"  {name:<22} right size but the contents differ   DAMAGED")
        broken.append(name)
    else:
        print(f"  {name:<22} {size:,} bytes   ok")

if broken:
    print("\nThose files did not arrive intact. Delete the folder, download the")
    print("zip again, and unzip it with Extract All rather than dragging files out.")
    sys.exit(1)

# ---- 2. the one version that must match
# The XGBoost models are stored in XGBoost's own .ubj format, which any
# version can read, so only scikit-learn is pinned.
print()
wrong = False
try:
    import sklearn
    found = sklearn.__version__
except ImportError:
    found = "not installed"
needed = BUILD["must_match"]["sklearn"]
ok = found == needed
print(f"  scikit-learn  {found:<14} must be {needed:<9} {'ok' if ok else 'WRONG VERSION'}")
wrong = not ok

for name, used in BUILD["also_used"].items():
    try:
        found = __import__(name).__version__
    except ImportError:
        found = "not installed"
        wrong = True
    print(f"  {name:<13} {found:<14} built with {used}")

if wrong:
    print("\nInstall the requirements using the python printed at the top:\n")
    print(f'  "{sys.executable}" -m pip install -r requirements.txt')
    print("\nThen run this again.")
    sys.exit(1)

# ---- 3. load everything and score something
print("\nLoading the models. The link model is large, so give it a few seconds.")
import joblib  # noqa: E402
import pandas as pd  # noqa: E402
import xgboost  # noqa: E402

import urlfeatures as uf  # noqa: E402

try:
    url = joblib.load(os.path.join(HERE, "models", "url_parts.joblib"))
    email = joblib.load(os.path.join(HERE, "models", "email_parts.joblib"))
    url_xgb = xgboost.Booster(); url_xgb.load_model(os.path.join(HERE, "models", "url_xgb.ubj"))
    email_xgb = xgboost.Booster(); email_xgb.load_model(os.path.join(HERE, "models", "email_xgb.ubj"))
except Exception as problem:
    print(f"\n  {type(problem).__name__}: {problem}")
    print("\nInstall the requirements with the python printed at the top, then")
    print("run this again.")
    sys.exit(1)

link = "paypal-secure-login.verify-account.xyz/signin.php"
frame = pd.DataFrame([uf.features(link)])
link_score = (float(url_xgb.predict(xgboost.DMatrix(url["pre_xgb"].transform(frame)))[0])
              + float(url["rf"].predict_proba(frame)[0, 1])
              + float(url["lr"].predict_proba(url["tfidf"].transform([link]))[0, 1])) / 3

text = "Your account has been suspended. Verify your password immediately."
vector = email["tfidf"].transform([text])
mail_score = (float(email["rf"].predict_proba(vector)[0, 1])
              + float(email_xgb.predict(xgboost.DMatrix(vector))[0])
              + float(email["nb"].predict_proba(vector)[0, 1])) / 3

print(f"\n  test link  scored {link_score * 100:.0f} out of 100")
print(f"  test email scored {mail_score * 100:.0f} out of 100")
print("\nEverything works. Start the app with:  python app.py")
print("Then open http://127.0.0.1:5000 in your browser.")
