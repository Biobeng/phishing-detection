"""Integration tests: the Flask app, models and feature code working together."""
import os
import sys
import time

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import app as phish  # noqa: E402


@pytest.fixture(scope="module")
def client():
    return phish.app.test_client()


def check(client, **body):
    return client.post("/api/check", json=body)


# ---------------------------------------------------------------- banding
@pytest.mark.parametrize("score,band", [(0.10, "legitimate"), (0.35, "suspicious"), (0.64, "suspicious"), (0.65, "phishing")])
def test_band_cut_points(score, band):
    assert phish.band(score, 0.35, 0.65) == band


# ---------------------------------------------------------------- pages
def test_home_page_loads(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"Scanlock" in r.data


# ---------------------------------------------------------------- link channel
def test_phishing_link_is_flagged(client):
    r = check(client, mode="link", text="paypal-secure-login.verify-account.xyz/signin.php")
    d = r.get_json()
    assert r.status_code == 200 and d["verdict"] == "phishing"
    assert [m["name"] for m in d["models"]] == ["XGBoost", "Random Forest", "Logistic Regression"]


def test_ordinary_link_reads_as_legitimate(client):
    d = check(client, mode="link", text="https://www.wikipedia.org").get_json()
    assert d["verdict"] == "legitimate"


def test_link_score_is_the_average_of_the_three_models(client):
    d = check(client, mode="link", text="leuie.5gbfree.com/index.html").get_json()
    mean = sum(m["score"] for m in d["models"]) / 3
    assert abs(d["score"] - mean) < 0.1


# ---------------------------------------------------------------- email channel
def test_phishing_email_is_flagged(client):
    d = check(client, mode="email", subject="Unlock Your Account",
              text="Your account has been suspended. Click here to verify your password immediately or lose access to your bank account.").get_json()
    assert d["verdict"] == "phishing"
    assert [m["name"] for m in d["models"]] == ["Random Forest", "XGBoost", "Naive Bayes"]


def test_ordinary_email_reads_as_legitimate(client):
    d = check(client, mode="email", subject="Minutes from Tuesday",
              text="Hi all, attached are the notes from Tuesday's project meeting. We agreed to move the review to next Thursday at 2pm. Let me know if that clashes with anything.").get_json()
    assert d["verdict"] == "legitimate"


# ---------------------------------------------------------------- validation
@pytest.mark.parametrize("body,status", [
    ({"mode": "link", "text": ""}, 400),
    ({"mode": "link", "text": "a.com b.com"}, 400),
    ({"mode": "link", "text": "10.0.0.1"}, 400),
    ({"mode": "email", "text": ""}, 400),
    ({"mode": "email", "text": "click here now"}, 400),
])
def test_bad_input_is_refused_with_a_message(client, body, status):
    r = check(client, **body)
    assert r.status_code == status and r.get_json()["error"]


def test_malformed_request_body_is_refused(client):
    r = client.post("/api/check", data="not json", content_type="text/plain")
    assert r.status_code == 400


# ---------------------------------------------------------------- speed
def test_a_check_returns_within_one_second(client):
    t = time.perf_counter()
    check(client, mode="link", text="leuie.5gbfree.com/index.html")
    assert time.perf_counter() - t < 1.0
