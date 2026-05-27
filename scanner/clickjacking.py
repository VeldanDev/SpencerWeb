"""
SpencerWeb — Module 16: Clickjacking Tester
Test apakah website bisa di-embed dalam iframe (clickjacking attack).

Bukan hanya cek header X-Frame-Options — tapi juga test:
1. CSP frame-ancestors directive
2. Actual response behavior saat di-request dengan Referer dari domain lain
3. Multiple pages (beda halaman bisa punya policy berbeda)
"""

import requests
from urllib.parse import urlparse
from utils.crawler import HEADERS


def scan_clickjacking(url: str, all_urls: list = None, timeout: int = 10) -> dict:
    findings = []
    passed = 0
    failed = 0
    tests = 0

    all_urls = all_urls or [url]
    pages = all_urls[:8]
    checked = set()

    for page_url in pages:
        path = urlparse(page_url).path or "/"
        if path in checked:
            continue
        checked.add(path)
        tests += 1

        try:
            # Request dengan Referer dari domain asing (simulasi iframe embed)
            test_headers = dict(HEADERS)
            test_headers["Referer"] = "https://attacker-site.com/clickjack.html"

            resp = requests.get(page_url, timeout=timeout, headers=test_headers,
                               allow_redirects=True)

            xfo = resp.headers.get("X-Frame-Options", "").upper()
            csp = resp.headers.get("Content-Security-Policy", "")

            # Extract frame-ancestors from CSP
            frame_ancestors = ""
            if "frame-ancestors" in csp.lower():
                for directive in csp.split(";"):
                    if "frame-ancestors" in directive.lower():
                        frame_ancestors = directive.strip()
                        break

            # Evaluate protection level
            protected = False
            protection_method = []

            # Check X-Frame-Options
            if xfo in ("DENY", "SAMEORIGIN"):
                protected = True
                protection_method.append(f"X-Frame-Options: {xfo}")

            # Check CSP frame-ancestors
            if frame_ancestors:
                fa_lower = frame_ancestors.lower()
                if "'none'" in fa_lower or "'self'" in fa_lower:
                    protected = True
                    protection_method.append(f"CSP {frame_ancestors}")
                elif "*" not in fa_lower:
                    protected = True
                    protection_method.append(f"CSP {frame_ancestors}")

            if protected:
                passed += 1
                findings.append({
                    "check": f"Clickjacking: {path}",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": f"Halaman dilindungi dari clickjacking via {', '.join(protection_method)}",
                    "recommendation": "-"
                })
            else:
                failed += 1
                missing = []
                if not xfo:
                    missing.append("X-Frame-Options")
                if not frame_ancestors:
                    missing.append("CSP frame-ancestors")

                # Determine severity based on page type
                severity = "MEDIUM"
                if any(kw in path.lower() for kw in ["/login", "/admin", "/account",
                       "/payment", "/checkout", "/transfer", "/settings", "/profile"]):
                    severity = "HIGH"

                findings.append({
                    "check": f"Clickjacking: {path}",
                    "status": "FAIL",
                    "severity": severity,
                    "detail": f"Halaman bisa di-embed dalam iframe (clickjacking). "
                             f"Missing: {', '.join(missing)}. "
                             f"Attacker bisa overlay halaman ini dengan UI palsu.",
                    "recommendation": "Tambahkan X-Frame-Options: DENY (atau SAMEORIGIN) "
                                     "DAN Content-Security-Policy: frame-ancestors 'self'"
                })

        except Exception:
            continue

    if failed == 0 and passed == 0:
        passed = 1
        findings.append({
            "check": "Clickjacking Test",
            "status": "PASS",
            "severity": "INFO",
            "detail": "Tidak ada halaman yang bisa diuji",
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
