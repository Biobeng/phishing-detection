"""Lexical features for a link. Copied unchanged from the training script so the
web app hands the saved models exactly the columns they were trained on."""
import math
import re
import collections
from collections import Counter
from urllib.parse import urlparse

import numpy as np

import urlprep as up

ext = up.ext


KEYWORDS = ["login", "secure", "verify", "account", "update", "bank", "paypal", "signin", "confirm",
            "wallet", "service", "webmail", "auth", "billing", "invoice", "password", "support", "ebay",
            "apple", "microsoft", "amazon", "google", "netflix", "free", "bonus", "claim"]
VOWELS = set("aeiou")


def clean(u):
    u = str(u).strip()
    u = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", u)
    u = re.sub(r"^www\.", "", u, flags=re.I)
    return u.rstrip("/")


def entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(s).values())


def longest_digit_run(s):
    return max([len(m) for m in re.findall(r"\d+", s)] or [0])


def features(u):
    try:
        p = urlparse("http://" + u)
        host = (p.hostname or "").lower()
        path, query = p.path, p.query
    except ValueError:
        host, path, query = u.split("/")[0].lower(), "", ""
    parts = ext(host)
    name = parts.domain
    low = u.lower()
    letters = sum(c.isalpha() for c in name)
    return {
        "url_len": len(u), "host_len": len(host), "path_len": len(path), "query_len": len(query),
        "n_subdomains": 0 if not parts.subdomain else parts.subdomain.count(".") + 1,
        "n_dots_host": host.count("."),
        "n_hyphens_host": host.count("-"), "n_hyphens_url": u.count("-"),
        "n_digits_url": sum(c.isdigit() for c in u), "digit_ratio": sum(c.isdigit() for c in u) / max(len(u), 1),
        "n_digits_host": sum(c.isdigit() for c in host), "longest_digit_run_host": longest_digit_run(host),
        "n_special": sum(not c.isalnum() and c not in "./" for c in u),
        "path_depth": path.count("/"),
        "n_params": (query.count("&") + 1) if query else 0,
        "has_at": int("@" in u), "n_percent": u.count("%"),
        "has_ip": int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))),
        "entropy_url": entropy(u), "entropy_host": entropy(host),
        "vowel_ratio_name": sum(c in VOWELS for c in name) / letters if letters else 0,
        "keyword_hits": sum(k in low for k in KEYWORDS),
        "ext_php": int(path.lower().endswith(".php")), "ext_html": int(path.lower().endswith((".html", ".htm"))),
        "ext_exe_zip": int(path.lower().endswith((".exe", ".zip", ".rar", ".apk"))),
        "has_embedded_url": int("http" in (path + "?" + query).lower()),
        "suffix_len": len(parts.suffix), "suffix": parts.suffix, "url": u,
    }
