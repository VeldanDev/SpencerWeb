"""
Spencer — Utility Crawler
Mengekstrak form, input fields, dan URL parameters dari halaman target.
Digunakan oleh module SQLi, XSS, dan CSRF.
"""

import requests
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup


HEADERS = {"User-Agent": "Spencer/1.0 (Security Audit - Educational Purpose)"}


def fetch_page(url: str, timeout: int = 10) -> tuple:
    """Fetch halaman dan return (response, soup)."""
    try:
        resp = requests.get(url, timeout=timeout, headers=HEADERS, allow_redirects=True)
        soup = BeautifulSoup(resp.text, "html.parser")
        return resp, soup
    except Exception as e:
        return None, None


def extract_forms(url: str, soup: BeautifulSoup) -> list[dict]:
    """
    Ekstrak semua form dari halaman.
    
    Returns list of:
    {
        "action": str (full URL),
        "method": str (GET/POST),
        "inputs": [{"name": str, "type": str, "value": str}, ...]
    }
    """
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        action = urljoin(url, action) if action else url
        method = form.get("method", "GET").upper()

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            input_name = inp.get("name")
            if not input_name:
                continue
            input_type = inp.get("type", "text")
            input_value = inp.get("value", "")
            inputs.append({
                "name": input_name,
                "type": input_type,
                "value": input_value
            })

        if inputs:
            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs
            })

    return forms


def extract_links_with_params(url: str, soup: BeautifulSoup) -> list[dict]:
    """
    Ekstrak semua link yang memiliki URL parameters.
    
    Returns list of:
    {
        "url": str,
        "params": {"key": "value", ...}
    }
    """
    links = []
    seen = set()

    for a in soup.find_all("a", href=True):
        href = urljoin(url, a["href"])
        parsed = urlparse(href)
        
        # Hanya yang sama domain dan punya query params
        if parsed.netloc == urlparse(url).netloc and parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            # Flatten: ambil value pertama dari tiap param
            flat_params = {k: v[0] if v else "" for k, v in params.items()}
            
            param_key = f"{parsed.path}|{'|'.join(sorted(flat_params.keys()))}"
            if param_key not in seen:
                seen.add(param_key)
                links.append({
                    "url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    "params": flat_params
                })

    return links


def get_url_params(url: str) -> dict:
    """Ekstrak parameters dari URL yang diberikan user."""
    parsed = urlparse(url)
    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        return {k: v[0] if v else "" for k, v in params.items()}
    return {}
