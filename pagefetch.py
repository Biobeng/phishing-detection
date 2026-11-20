"""
Safe page fetch for the Deep check.

The page is downloaded as text only. Nothing on it is run or rendered: no
JavaScript, no images, no style sheets, no downloads. To stop the server being
used to reach machines it should not, every address (including each redirect)
is checked before it is contacted, and only public internet addresses on the
normal web ports are allowed.
"""
import ipaddress
import os
import socket
from urllib.parse import urljoin, urlparse

import requests

TIMEOUT = (4, 6)              # seconds to connect, seconds to wait for data
MAX_BYTES = 1_500_000         # stop reading after 1.5 MB
MAX_REDIRECTS = 5
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ScanlockDeepCheck/1.0; text-only fetch)",
           "Accept": "text/html,application/xhtml+xml"}
ALLOW_PRIVATE = os.environ.get("PAGEFETCH_ALLOW_PRIVATE") == "1"   # tests only


class FetchError(Exception):
    """A page could not be fetched; the message is written for the user."""


def check_address(url):
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise FetchError("Only web addresses starting with http or https can be visited.")
    if p.port not in (None, 80, 443):
        raise FetchError("That address uses an unusual port, so it was not visited.")
    host = p.hostname
    if not host:
        raise FetchError("That address has no host name to visit.")
    try:
        infos = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise FetchError("That website could not be found. It may have been taken down already.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ALLOW_PRIVATE and not ip.is_global:
            raise FetchError("That address points to a private or reserved network, so it was not visited.")


def fetch(text):
    """Returns dict(url, status, redirects, html). Raises FetchError with a readable reason."""
    url = text if "://" in text else "https://" + text
    redirects = []
    for attempt in range(MAX_REDIRECTS + 1):
        check_address(url)
        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=False, stream=True)
        except requests.exceptions.SSLError:
            if url.startswith("https://") and not redirects and "://" not in text:
                url = "http://" + text          # some sites only answer on plain http
                continue
            raise FetchError("The website's security certificate is not valid.")
        except requests.exceptions.Timeout:
            raise FetchError("The website took too long to answer.")
        except requests.exceptions.RequestException:
            if url.startswith("https://") and not redirects and "://" not in text:
                url = "http://" + text
                continue
            raise FetchError("The website could not be reached.")
        if r.is_redirect or r.status_code in (301, 302, 303, 307, 308):
            nxt = r.headers.get("Location")
            r.close()
            if not nxt:
                raise FetchError("The website sent a broken redirect.")
            url = urljoin(url, nxt)
            redirects.append(url)
            continue
        if r.status_code >= 400:
            r.close()
            raise FetchError(f"The website answered with error {r.status_code}, so there was no page to read.")
        ctype = r.headers.get("Content-Type", "").lower()
        if "html" not in ctype:
            r.close()
            raise FetchError("That address does not lead to a web page (it may be a file download), so it was not read.")
        body = b""
        for chunk in r.iter_content(65536):
            body += chunk
            if len(body) >= MAX_BYTES:
                break
        r.close()
        enc = r.encoding or "utf-8"
        return {"url": url, "status": r.status_code, "redirects": redirects, "html": body.decode(enc, errors="replace")}
    raise FetchError("The website redirected too many times.")
