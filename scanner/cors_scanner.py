"""
SpencerWeb — Module 12: CORS Misconfiguration Scanner
Deteksi konfigurasi CORS yang tidak aman.

CORS (Cross-Origin Resource Sharing) yang salah konfigurasi bisa
memungkinkan website lain mengakses data sensitif dari target.
"""

import requests
from urllib.parse import urlparse
from utils.crawler import HEADERS


def scan_cors(url: str, all_urls: list = None, timeout: int = 10) -> dict:
    findings = []
    passed = 0
    failed = 0
    tests = 0

    all_urls = all_urls or [url]
    test_urls = all_urls[:10]
    checked = set()

    for page_url in test_urls:
        path = urlparse(page_url).path or "/"
        if path in checked:
            continue
        checked.add(path)

        # Test 1: Wildcard origin (Access-Control-Allow-Origin: *)
        tests += 1
        result = _test_cors(page_url, "https://evil-attacker.com", timeout)

        if result["reflects_origin"]:
            failed += 1
            findings.append({
                "check": f"CORS: Origin Reflection [{path}]",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": f"Server merefleksi Origin header dari attacker — "
                         f"website mana saja bisa mengakses data dari endpoint ini. "
                         f"ACAO: {result['acao']}",
                "recommendation": "Jangan merefleksikan Origin header secara langsung. "
                                 "Gunakan allowlist domain yang diizinkan."
            })
        elif result["wildcard"]:
            failed += 1
            findings.append({
                "check": f"CORS: Wildcard Origin [{path}]",
                "status": "FAIL",
                "severity": "MEDIUM",
                "detail": f"Access-Control-Allow-Origin: * — semua domain diizinkan akses.",
                "recommendation": "Ganti wildcard (*) dengan domain spesifik yang diizinkan."
            })
        elif result["null_allowed"]:
            failed += 1
            findings.append({
                "check": f"CORS: Null Origin Allowed [{path}]",
                "status": "FAIL",
                "severity": "MEDIUM",
                "detail": "Server menerima Origin: null — bisa dieksploitasi via sandboxed iframe.",
                "recommendation": "Jangan izinkan null origin."
            })

        # Test 2: Credentials with wildcard
        if result["credentials_with_wildcard"]:
            findings.append({
                "check": f"CORS: Credentials + Wildcard [{path}]",
                "status": "FAIL",
                "severity": "CRITICAL",
                "detail": "Access-Control-Allow-Credentials: true dengan Origin reflection — "
                         "attacker bisa mencuri cookies dan session data.",
                "recommendation": "JANGAN kombinasikan Allow-Credentials: true dengan reflected origin."
            })

    # Test 3: Null origin
    tests += 1
    null_result = _test_cors(url, None, timeout, use_null=True)
    if null_result["null_allowed"]:
        if not any("Null Origin" in f.get("check", "") for f in findings):
            failed += 1
            findings.append({
                "check": "CORS: Null Origin Accepted",
                "status": "FAIL",
                "severity": "MEDIUM",
                "detail": "Server menerima Origin: null.",
                "recommendation": "Blokir null origin di konfigurasi CORS."
            })

    if failed == 0:
        passed = 1
        findings.append({
            "check": "CORS Configuration Scan",
            "status": "PASS",
            "severity": "INFO",
            "detail": f"Tidak ditemukan CORS misconfiguration ({tests} tests pada {len(checked)} halaman)",
            "recommendation": "-"
        })

    return {
        "target": url,
        "findings": findings,
        "tests_performed": tests,
        "pages_checked": len(checked),
        "passed": passed,
        "failed": failed,
        "total_checks": max(passed + failed, 1)
    }


def _test_cors(url: str, origin: str, timeout: int, use_null: bool = False) -> dict:
    result = {
        "reflects_origin": False,
        "wildcard": False,
        "null_allowed": False,
        "credentials_with_wildcard": False,
        "acao": None
    }

    headers = dict(HEADERS)
    if use_null:
        headers["Origin"] = "null"
    elif origin:
        headers["Origin"] = origin

    try:
        resp = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        result["acao"] = acao

        if acao == "*":
            result["wildcard"] = True
            if acac == "true":
                result["credentials_with_wildcard"] = True

        elif origin and origin in acao:
            result["reflects_origin"] = True
            if acac == "true":
                result["credentials_with_wildcard"] = True

        elif acao == "null" and use_null:
            result["null_allowed"] = True

    except Exception:
        pass

    return result
