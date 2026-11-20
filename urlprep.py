"""
Shared URL preparation. The training scripts AND the web app use this, so they treat links identically.

prepare(raw_link) -> (text, form)
    form "path": the link has a path or query, so the model reads the whole cleaned link
    form "bare": just a website address, so only its registered domain is kept (subdomains dropped)
    form None  : cannot be classified (empty, IP address, unknown ending); text holds the reason
"""
import re
import tldextract

# the 'private' list keeps hosting platforms apart: evil.pages.dev is its own site, not the platform pages.dev
ext = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
ext_icann = tldextract.TLDExtract(suffix_list_urls=())   # stricter grouping, used only to keep sites apart in splits


def clean(raw):
    u = str(raw).strip()
    u = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", u)
    u = re.sub(r"^www\.", "", u, flags=re.I)
    return u.rstrip("/")


def has_path(cleaned):
    return bool(re.search(r"[/?#]", cleaned))


def registered_domain(host):
    p = ext(host)
    return f"{p.domain}.{p.suffix}".lower() if p.domain and p.suffix else None


def group_domain(text):
    p = ext_icann("http://" + text)
    return (f"{p.domain}.{p.suffix}" if p.domain and p.suffix else text).lower()


def prepare(raw):
    u = clean(raw)
    if len(u) < 3:
        return "empty", None
    if has_path(u):
        return u, "path"
    d = registered_domain(u.split(":")[0].lower())
    if d is None:
        return "no usable domain (IP address or unknown ending)", None
    return d, "bare"
