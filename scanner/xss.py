"""
Spencer — Modul XSS (Cross-Site Scripting) Scanner
Mendeteksi kerentanan Reflected XSS pada form input dan URL parameters.
Menggunakan teknik reflection detection — mengirim payload unik dan
mengecek apakah payload ter-reflect di response tanpa sanitasi.

Semua payload dan logika deteksi ditulis original.
"""

import requests
import random
import string
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from utils.crawler import fetch_page, extract_forms, extract_links_with_params, get_url_params, HEADERS


def _random_marker() -> str:
    """Generate random string unik untuk tracking reflection."""
    return "spncr" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))


# Payload XSS dengan marker unik untuk detection
# Setiap payload punya marker yang bisa dicari di response
XSS_PAYLOADS = [
    # Basic script injection
    {
        "payload": '<script>alert("{marker}")</script>',
        "check": '<script>alert("{marker}")</script>',
        "type": "Script Tag Injection"
    },
    # IMG tag with onerror
    {
        "payload": '<img src=x onerror=alert("{marker}")>',
        "check": 'onerror=alert("{marker}")',
        "type": "Event Handler Injection"
    },
    # SVG onload
    {
        "payload": '<svg onload=alert("{marker}")>',
        "check": 'onload=alert("{marker}")',
        "type": "SVG Onload Injection"
    },
    # Simple reflection test (no HTML)
    {
        "payload": '"><{marker}>',
        "check": '<{marker}>',
        "type": "HTML Tag Injection"
    },
    # Attribute escape
    {
        "payload": '" onfocus="alert(\'{marker}\')" autofocus="',
        "check": "onfocus=\"alert('{marker}')",
        "type": "Attribute Escape"
    },
    # JavaScript protocol
    {
        "payload": 'javascript:alert("{marker}")',
        "check": 'javascript:alert("{marker}")',
        "type": "JavaScript Protocol"
    },
]


def scan_xss(url: str, timeout: int = 10) -> dict:
    """
    Scan target URL untuk kerentanan Reflected XSS.
    
    Proses:
    1. Fetch halaman target
    2. Ekstrak form dan URL parameters
    3. Untuk setiap injection point, kirim payload XSS dengan marker unik
    4. Cek apakah marker/payload ter-reflect di response
    5. Laporkan temuan
    """
    findings = []
    passed = 0
    failed = 0
    injection_points_tested = 0

    resp, soup = fetch_page(url, timeout)
    if not resp or not soup:
        return {
            "target": url,
            "error": "Tidak dapat mengakses halaman target",
            "findings": [], "passed": 0, "failed": 0, "total_checks": 0
        }

    forms = extract_forms(url, soup)
    url_params = get_url_params(url)
    param_links = extract_links_with_params(url, soup)

    # === TEST 1: Form-based XSS ===
    for form in forms:
        for xss in XSS_PAYLOADS[:4]:
            marker = _random_marker()
            payload = xss["payload"].replace("{marker}", marker)
            check = xss["check"].replace("{marker}", marker)
            
            reflected = _test_form_xss(form, payload, check, timeout)
            injection_points_tested += 1
            
            if reflected:
                failed += 1
                findings.append({
                    "check": f"XSS: Form ({form['method']} {_short_path(form['action'])})",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "detail": f"Reflected XSS ({xss['type']}) — payload ter-reflect tanpa sanitasi",
                    "recommendation": "Sanitasi semua output menggunakan HTML encoding. "
                                     "Implementasikan Content-Security-Policy header."
                })
                break

    # === TEST 2: URL parameter XSS ===
    if url_params:
        for param_name in url_params:
            for xss in XSS_PAYLOADS[:4]:
                marker = _random_marker()
                payload = xss["payload"].replace("{marker}", marker)
                check = xss["check"].replace("{marker}", marker)
                
                reflected = _test_param_xss(url, param_name, payload, check, timeout)
                injection_points_tested += 1
                
                if reflected:
                    failed += 1
                    findings.append({
                        "check": f"XSS: URL param '{param_name}'",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "detail": f"Reflected XSS ({xss['type']}) pada parameter '{param_name}'",
                        "recommendation": "Encode semua user input sebelum output ke HTML. "
                                         "Gunakan framework template yang auto-escape."
                    })
                    break

    # === TEST 3: Link parameter XSS ===
    for link in param_links[:8]:
        for param_name in link["params"]:
            for xss in XSS_PAYLOADS[:3]:
                marker = _random_marker()
                payload = xss["payload"].replace("{marker}", marker)
                check = xss["check"].replace("{marker}", marker)
                
                full_url = link["url"] + "?" + urlencode(link["params"])
                reflected = _test_param_xss(full_url, param_name, payload, check, timeout)
                injection_points_tested += 1
                
                if reflected:
                    failed += 1
                    findings.append({
                        "check": f"XSS: {_short_path(link['url'])} '{param_name}'",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "detail": f"Reflected XSS ({xss['type']})",
                        "recommendation": "Sanitasi output dan implementasikan CSP header."
                    })
                    break

    if failed == 0:
        passed = 1
        findings.append({
            "check": "XSS (Cross-Site Scripting) Scan",
            "status": "PASS",
            "severity": "INFO",
            "detail": f"Tidak ditemukan kerentanan XSS ({injection_points_tested} tests)",
            "recommendation": "-"
        })

    return {
        "target": url,
        "findings": findings,
        "injection_points_tested": injection_points_tested,
        "forms_found": len(forms),
        "passed": passed,
        "failed": failed,
        "total_checks": max(passed + failed, 1)
    }


def _test_form_xss(form: dict, payload: str, check: str, timeout: int) -> bool:
    """Test form dengan payload XSS. Returns True jika reflected."""
    data = {}
    for inp in form["inputs"]:
        if inp["type"] in ("text", "search", "email", "tel", "url", "number", ""):
            data[inp["name"]] = payload
        elif inp["type"] == "hidden":
            data[inp["name"]] = inp["value"]
        else:
            data[inp["name"]] = inp.get("value", "test")

    try:
        if form["method"] == "POST":
            resp = requests.post(form["action"], data=data, timeout=timeout,
                                headers=HEADERS, allow_redirects=True)
        else:
            resp = requests.get(form["action"], params=data, timeout=timeout,
                               headers=HEADERS, allow_redirects=True)
        return check.lower() in resp.text.lower()
    except Exception:
        return False


def _test_param_xss(base_url: str, param_name: str, payload: str, check: str, timeout: int) -> bool:
    """Test URL parameter dengan payload XSS. Returns True jika reflected."""
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param_name] = [payload]
    flat = {k: v[0] for k, v in params.items()}
    new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                          parsed.params, urlencode(flat), parsed.fragment))
    try:
        resp = requests.get(new_url, timeout=timeout, headers=HEADERS, allow_redirects=True)
        return check.lower() in resp.text.lower()
    except Exception:
        return False


def _short_path(url: str, max_len: int = 30) -> str:
    path = urlparse(url).path
    return ("..." + path[-(max_len-3):]) if len(path) > max_len else path
