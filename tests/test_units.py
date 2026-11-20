"""Unit tests: each piece checked on its own, without the web layer."""
import os
import sys

import numpy as np
import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

import urlprep as up                     # noqa: E402
import urlfeatures as uf                 # noqa: E402
from compactforest import CompactForest  # noqa: E402


# ---------------------------------------------------------------- urlprep
def test_clean_strips_scheme_www_and_trailing_slash():
    assert up.clean("https://www.Example.com/") == "Example.com"


def test_prepare_bare_address_keeps_registered_domain_only():
    assert up.prepare("http://mail.google.com") == ("google.com", "bare")


def test_prepare_link_with_path_is_read_in_full():
    assert up.prepare("https://shop.example.com/cart?id=4") == ("shop.example.com/cart?id=4", "path")


def test_prepare_rejects_raw_ip_address():
    text, form = up.prepare("192.168.0.1")
    assert form is None


def test_prepare_rejects_empty_input():
    assert up.prepare("  ") == ("empty", None)


# ---------------------------------------------------------------- urlfeatures
def test_feature_set_has_29_entries():
    assert len(uf.features("example.com")) == 29


def test_features_flag_suspicious_link():
    f = uf.features("secure-login.paypal.verify-account.xyz/signin.php")
    assert f["keyword_hits"] >= 4
    assert f["ext_php"] == 1
    assert f["n_hyphens_host"] == 2
    assert f["suffix"] == "xyz"


def test_features_spot_at_sign_and_embedded_link():
    f = uf.features("bank.com@evil.ru/redirect?to=http://x.com")
    assert f["has_at"] == 1
    assert f["has_embedded_url"] == 1


def test_entropy_of_repeated_character_is_zero():
    assert uf.entropy("aaaa") == 0


def test_longest_digit_run():
    assert uf.longest_digit_run("ab12cd34567") == 5


# ---------------------------------------------------------------- compact forest
@pytest.fixture(scope="module")
def forest():
    return CompactForest(os.path.join(HERE, "models", "url_rf_forest.npz"))


def test_forest_has_150_trees(forest):
    assert len(forest.roots) == 150


def test_forest_output_is_a_probability(forest):
    X = np.zeros((3, 408))
    out = forest.predict_proba(X)
    assert out.shape == (3, 2)
    assert np.allclose(out.sum(axis=1), 1.0)
    assert ((out >= 0) & (out <= 1)).all()
