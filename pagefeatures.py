"""
Page-content features for the Deep check.

The names and meanings follow the PhiUSIIL dataset the page model was trained on.
Everything here reads the HTML as text. No script on the page is ever run.
"""
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

import urlprep as up

FEATURES = ["HasTitle", "HasFavicon", "IsResponsive", "HasDescription", "NoOfPopup", "NoOfiFrame",
            "HasExternalFormSubmit", "HasSocialNet", "HasSubmitButton", "HasHiddenFields",
            "HasPasswordField", "Bank", "Pay", "Crypto", "HasCopyrightInfo"]

SOCIAL = ("facebook.com", "twitter.com", "x.com", "instagram.com", "linkedin.com", "youtube.com",
          "tiktok.com", "pinterest.com", "wa.me", "t.me")
MIN_WORDS = 20   # below this there is too little on the page to judge


def site(url):
    host = (urlparse(url).hostname or "").lower()
    return up.registered_domain(host) or host


def extract(html, page_url):
    """Returns (features, details). details["readable"] is False when the page is too bare to judge."""
    soup = BeautifulSoup(html, "html.parser")
    home = site(page_url)

    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    metas = {(m.get("name") or "").lower(): (m.get("content") or "") for m in soup.find_all("meta")}
    icon = any("icon" in " ".join(l.get("rel") or []).lower() for l in soup.find_all("link"))

    external_forms = []
    for f in soup.find_all("form"):
        action = (f.get("action") or "").strip()
        if action.lower().startswith(("http://", "https://", "//")):
            target = site(urljoin(page_url, action))
            if target and target != home:
                external_forms.append(target)

    inputs = soup.find_all("input")
    types = [(i.get("type") or "text").lower() for i in inputs]
    submit = any(t in ("submit", "image") for t in types) or any(
        (b.get("type") or "submit").lower() == "submit" for b in soup.find_all("button"))
    links = [a.get("href") or "" for a in soup.find_all("a")]
    social = any(any(s in (urlparse(h).hostname or "") for s in SOCIAL) for h in links if h.startswith("http"))

    scripts = len(soup.find_all("script"))
    popups = len(re.findall(r"window\.open\s*\(", html))
    for t in soup(["script", "style", "noscript", "template"]):
        t.decompose()
    text = soup.get_text(" ", strip=True)
    low = text.lower()
    words = len(text.split())

    f = {
        "HasTitle": int(bool(title)),
        "HasFavicon": int(icon),
        "IsResponsive": int("viewport" in metas),
        "HasDescription": int(bool(metas.get("description", "").strip())),
        "NoOfPopup": popups,
        "NoOfiFrame": len(soup.find_all("iframe")) if soup else 0,
        "HasExternalFormSubmit": int(bool(external_forms)),
        "HasSocialNet": int(social),
        "HasSubmitButton": int(submit),
        "HasHiddenFields": int("hidden" in types),
        "HasPasswordField": int("password" in types),
        "Bank": int("bank" in low),
        "Pay": int("pay" in low),
        "Crypto": int("crypto" in low),
        "HasCopyrightInfo": int("©" in text or "copyright" in low),
    }
    details = {"title": title[:120], "words": words, "scripts": scripts, "external_forms": sorted(set(external_forms)),
               "readable": words >= MIN_WORDS}
    return f, details
