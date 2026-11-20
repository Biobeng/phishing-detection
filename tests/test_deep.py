"""Tests for the Deep check: page features, the safe fetch guard, and the endpoint."""
import os
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import pagefeatures as pf   # noqa: E402
import pagefetch            # noqa: E402
import app as phish         # noqa: E402

KIT = """<html><head><title>Sign in - Online Banking</title><link rel="icon" href="f.ico"></head><body>
<p>Your account has been temporarily limited. Please sign in to verify your identity and restore full access to your bank account today.</p>
<form action="https://collect-data-panel.xyz/post.php"><input type="hidden" name="t"><input name="u"><input type="password" name="p"><button>Sign in</button></form>
</body></html>"""
BLOG = """<html><head><title>Ada's Kitchen</title><meta name="description" content="Recipes"><link rel="icon" href="/f.png"></head><body>
<p>This is the jollof rice my mother made for every party. Blend tomatoes, peppers and onions, fry the paste, add stock and rice, and cook on low heat.</p>
<a href="https://instagram.com/ada">Instagram</a><footer>© 2026 Ada's Kitchen</footer></body></html>"""


# ---------------------------------------------------------------- unit: page features
def test_page_features_spot_a_login_kit():
    f, info = pf.extract(KIT, "https://good-site.com/login")
    assert f["HasPasswordField"] == 1 and f["HasHiddenFields"] == 1 and f["HasSubmitButton"] == 1
    assert f["HasExternalFormSubmit"] == 1 and info["external_forms"] == ["collect-data-panel.xyz"]
    assert f["Bank"] == 1 and info["readable"]


def test_page_features_of_an_ordinary_page():
    f, info = pf.extract(BLOG, "https://adaskitchen.com/")
    assert f["HasDescription"] == 1 and f["HasCopyrightInfo"] == 1 and f["HasSocialNet"] == 1
    assert f["HasPasswordField"] == 0 and f["HasExternalFormSubmit"] == 0


def test_script_only_page_is_not_readable():
    f, info = pf.extract('<html><head><script src="a.js"></script></head><body><div id="root"></div></body></html>', "https://x.com/")
    assert not info["readable"]


def test_feature_list_has_15_entries():
    assert len(pf.FEATURES) == 15


# ---------------------------------------------------------------- unit: the safety guard
@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://10.0.0.5/", "http://169.254.169.254/latest/meta-data", "http://192.168.1.1/admin"])
def test_private_addresses_are_never_visited(url, monkeypatch):
    monkeypatch.setattr(pagefetch, "ALLOW_PRIVATE", False)
    with pytest.raises(pagefetch.FetchError):
        pagefetch.check_address(url)


@pytest.mark.parametrize("url", ["ftp://example.com/file", "http://example.com:8080/", "file:///etc/passwd"])
def test_odd_schemes_and_ports_are_refused(url):
    with pytest.raises(pagefetch.FetchError):
        pagefetch.check_address(url)


# ---------------------------------------------------------------- integration: endpoint
@pytest.fixture
def client(monkeypatch):
    pages = {"kit.example": KIT, "blog.example": BLOG}

    def fake_fetch(text):
        host = text.split("/")[0]
        if host not in pages:
            raise pagefetch.FetchError("The website could not be reached.")
        return {"url": "https://" + text, "status": 200, "redirects": [], "html": pages[host]}

    monkeypatch.setattr(pagefetch, "fetch", fake_fetch)
    return phish.app.test_client()


def test_quick_check_does_not_visit(client):
    d = client.post("/api/check", json={"mode": "link", "text": "kit.example/login"}).get_json()
    assert d["page"] is None


def test_deep_check_flags_a_login_kit(client):
    d = client.post("/api/check", json={"mode": "link", "text": "kit.example/login", "deep": True}).get_json()
    assert d["page"]["ok"] and d["page"]["verdict"] == "phishing"
    assert [m["name"] for m in d["page"]["models"]] == ["Random Forest", "XGBoost", "Logistic Regression"]


def test_deep_check_passes_an_ordinary_page(client):
    d = client.post("/api/check", json={"mode": "link", "text": "blog.example/jollof", "deep": True}).get_json()
    assert d["page"]["ok"] and d["page"]["verdict"] == "legitimate"


def test_unreachable_page_still_returns_the_quick_result(client):
    r = client.post("/api/check", json={"mode": "link", "text": "gone.example/x", "deep": True})
    d = r.get_json()
    assert r.status_code == 200 and d["verdict"] in ("legitimate", "suspicious", "phishing")
    assert d["page"]["ok"] is False and d["page"]["reason"]
