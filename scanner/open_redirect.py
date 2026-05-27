"""
SpencerWeb — Module 11: Open Redirect Scanner
Deteksi kerentanan Open Redirect pada URL parameters.

Open Redirect = attacker bisa memanipulasi URL parameter untuk
mengarahkan korban ke website phishing/malicious.

Contoh: https://target.com/login?redirect=https://evil.com
"""

import requests
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin
from utils.crawler import HEADERS


REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "returnTo", "return_to", "next", "next_url", "goto", "go", "to", "target",
    "destination", "dest", "redir", "redirect_to", "out", "view", "login_url",
    "callback", "cb", "continue", "link", "forward", "ref", "site", "html",
    "reference", "file", "load", "uri", "referrer",
]

EVIL_PAYLOADS = [
    "https://evil.spencerweb-test.com",
    "//evil.spencerweb-test.com",
    "https://evil.spencerweb-test.com/%2f..",
    "/\\evil.spencerweb-test.com",
    "https:evil.spencerweb-test.com",
]


def scan_open_redirect(url: str, all_urls: list = None, param_links: list = None,
                       timeout: int = 10) -> dict:
    findings = []
    passed = 0
    failed = 0
    tests = 0

    all_urls = all_urls or [url]
    param_links = param_links or []

    # Strategy 1: Test known redirect parameter names on all URLs
    for page_url in all_urls[:10]:
        for param in REDIRECT_PARAMS:
            for payload in EVIL_PAYLOADS[:2]:
                tests += 1
                if _test_redirect(page_url, param, payload, timeout):
                    failed += 1
                    path = urlparse(page_url).path or "/"
                    findings.append({
                        "check": f"Open Redirect: ?{param}= [{path}]",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "detail": f"Parameter '{param}' menerima URL eksternal sebagai redirect destination. "
                                 f"Attacker bisa mengarahkan korban ke situs phishing.",
                        "recommendation": "Validasi redirect URL — hanya izinkan redirect ke domain sendiri. "
                                         "Gunakan allowlist untuk URL redirect yang diizinkan."
                    })
                    break  # 1 payload cukup per param
            if failed > 0:
                break  # Stop setelah menemukan 1 per page

    # Strategy 2: Test existing param links yang punya redirect-like params
    for link in param_links[:15]:
        for param_name in link.get("params", {}):
            if param_name.lower() in REDIRECT_PARAMS:
                for payload in EVIL_PAYLOADS[:2]:
                    tests += 1
                    test_url = link["url"] + "?" + urlencode({**link["params"], param_name: payload})
                    if _check_redirect_response(test_url, payload, timeout):
                        failed += 1
                        findings.append({
                            "check": f"Open Redirect: {param_name} ({urlparse(link['url']).path})",
                            "status": "FAIL",
                            "severity": "HIGH",
                            "detail": f"Existing parameter '{param_name}' menerima URL eksternal.",
                            "recommendation": "Validasi redirect URL dengan allowlist."
                        })
                        break

    if failed == 0:
        passed = 1
        findings.append({
            "check": "Open Redirect Scan",
            "status": "PASS",
            "severity": "INFO",
            "detail": f"Tidak ditemukan Open Redirect ({tests} tests pada {len(all_urls[:10])} halaman)",
            "recommendation": "-"
        })

    return {
        "target": url,
        "findings": findings,
        "tests_performed": tests,
        "passed": passed,
        "failed": failed,
        "total_checks": max(passed + failed, 1)
    }


def _test_redirect(base_url: str, param: str, payload: str, timeout: int) -> bool:
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    flat = {k: v[0] for k, v in params.items()}
    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                           parsed.params, urlencode(flat), ""))
    return _check_redirect_response(test_url, payload, timeout)


def _check_redirect_response(test_url: str, payload: str, timeout: int) -> bool:
    try:
        resp = requests.get(test_url, timeout=timeout, headers=HEADERS,
                           allow_redirects=False)
        # Check redirect in Location header
        location = resp.headers.get("Location", "")
        if "evil.spencerweb-test.com" in location:
            return True
        # Check redirect in response body (meta refresh, JS redirect)
        if resp.status_code == 200 and "evil.spencerweb-test.com" in resp.text[:5000]:
            return True
        # Check 3xx redirect
        if resp.status_code in (301, 302, 303, 307, 308):
            if "evil.spencerweb-test.com" in location:
                return True
    except Exception:
        pass
    return False
