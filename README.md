# Intelligent Phishing Detection System for Emails and Websites

A machine learning system that checks emails and website links for phishing.
Final year project, Department of Computer Science, University of Ibadan.

- Email model: Random Forest, XGBoost and Naive Bayes on TF-IDF text, averaged
- Link model: XGBoost and Random Forest on 29 lexical features, plus Logistic
  Regression on character n-grams, averaged
- Each check returns a score from 0 to 100 and a band: legitimate, not clear
  cut, or phishing
- Links can be checked two ways. The Quick check reads only the address. The
  Deep check also downloads the page as plain text (no scripts run, nothing
  rendered) and scores what it contains with a second model trained on the
  PhiUSIIL page features. Private and reserved network addresses are never
  visited.

## Running it on your laptop

1. Put this folder anywhere, for example C:\Users\USER\Downloads\phishing_app
2. Open the folder in PyCharm, then in the Terminal tab install what it needs:

       pip install -r requirements.txt

3. Check that everything lines up before you start the server:

       python check_setup.py

4. Start it:

       python app.py

5. Open http://127.0.0.1:5000 in your browser.

The two saved models live in the models folder and are loaded once when the
server starts. The first start takes a few seconds because of that.

## How the models are stored

The two XGBoost models are saved as .ubj files through XGBoost's own
save_model, which is a documented format that travels between machines and
between versions. They are not pickled. A pickled XGBoost model carries a raw
memory buffer that is only valid on the build that wrote it, which is what
caused this error even when the version numbers agreed:

    xgboost._c_api.XGBoostError: input stream corrupted

The scikit-learn parts are still joblib files, and those do need the same
scikit-learn version that wrote them. That version is recorded in
models/build_info.json, and check_setup.py reads it from there, so the check
always describes the files that shipped beside it. build_info.json also holds
the size and SHA256 of every model file, so an incomplete download is reported
as such instead of surfacing later as a strange error.

If scikit-learn is ever wrong, install with the full path to the interpreter
PyCharm runs, not a bare pip, because the terminal often uses a different one:

    C:\Users\USER\PycharmProjects\pythonProject\.venv\Scripts\python.exe -m pip install -r requirements.txt

check_setup.py prints that path at the top for you to copy.

If XGBoost itself fails for any reason, the app still starts and scores with
the models that did load, and the interface shows which models were used.

If port 5000 is already taken on your laptop, start it on another port:

    set PORT=5050
    python app.py

## What is in here

    app.py            the Flask back end, routing and validation
    urlprep.py        cleans a link and decides if it is a full link or just an address
    urlfeatures.py    the 29 lexical features, copied from the training script
    templates/        the page
    static/           styles and the small bit of browser code
    models/           email_model.joblib and url_model.joblib

## How a check is scored

Links go through three models (XGBoost, Random Forest, Logistic Regression) and
their scores are averaged. Emails go through a soft vote of Random Forest,
XGBoost and Naive Bayes.

The result is placed in one of three bands instead of a plain yes or no:

    links   legitimate below 35, not clear cut 35 to 65, phishing from 65
    emails  legitimate below 40, not clear cut 40 to 70, phishing from 70

Those cut points were set on held out data the models never trained on.

## Deploying it

The repo is ready for Render or Railway. Both read the files in this folder:

- requirements.txt lists the packages, including gunicorn for the server
- Procfile and render.yaml give the start command
- .python-version pins Python 3.13, which the saved models were built with
