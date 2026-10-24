"""Shared HTTP session."""
from __future__ import annotations

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def session(user_agent: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": user_agent})
    return s


def fetch(s: requests.Session, url: str, timeout: float, **kw):
    """GET that never raises; returns Response or None."""
    try:
        return s.get(url, timeout=timeout, verify=False, **kw)
    except requests.RequestException:
        return None
