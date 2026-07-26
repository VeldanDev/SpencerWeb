"""
SpencerWeb — Module 13: HTTP Method Testing
Cek apakah server menerima HTTP method berbahaya.

Method seperti PUT, DELETE, TRACE, CONNECT seharusnya dinonaktifkan
di production server. TRACE bisa digunakan untuk Cross-Site Tracing (XST),
PUT/DELETE bisa digunakan untuk modifikasi file.
"""

import requests
import random
import string
from urllib.parse import urlparse
from utils.crawler import HEADERS


DANGEROUS_METHODS = [
    {
        "method": "TRACE",
        "severity": "HIGH",
        "risk": "Cross-Site Tracing (XST) — attacker bisa mencuri cookies HttpOnly via TRACE request",
        "recommendation": "Disable TRACE method di web server configuration"
    },
    {
        "method": "PUT",
        "severity": "HIGH",
        "risk": "File upload/overwrite — attacker bisa upload webshell atau overwrite file",
        "recommendation": "Disable PUT method kecuali diperlukan untuk API (dan lindungi dengan autentikasi)"
    },
    {
        "method": "DELETE",
        "severity": "HIGH",
        "risk": "File deletion — attacker bisa menghapus file di server",
        "recommendation": "Disable DELETE method kecuali diperlukan untuk API"
    },
    {
        "method": "CONNECT",
        "severity": "MEDIUM",
        "risk": "Proxy tunneling — server bisa disalahgunakan sebagai proxy",
        "recommendation": "Disable CONNECT method"
    },
    {
        "method": "PATCH",
        "severity": "LOW",
        "risk": "Partial resource modification — pastikan dilindungi autentikasi",
        "recommendation": "Disable PATCH jika tidak digunakan, atau lindungi dengan auth"
    },
]


def scan_http_methods(url: str, all_urls: list = None, timeout: int = 8) -> dict:
    findings = []
    passed = 0
    failed = 0
    tests = 0

    all_urls = all_urls or [url]
    test_urls = all_urls[:5]

    # === FIX FALSE POSITIVE: deteksi server soft-200 (SPA / catch-all) ===
    # Banyak SPA/framework membalas HTTP 200 untuk SEMUA path & method, termasuk
    # PUT/DELETE, tanpa benar-benar mengeksekusinya. Pada server seperti ini,
    # status 200 BUKAN bukti method aktif. Dideteksi sekali via path acak.
    soft_200 = _is_soft_200(url, timeout)

    # Step 1: OPTIONS request untuk lihat allowed methods
    for page_url in test_urls[:2]:
        try:
            resp = requests.options(page_url, timeout=timeout, headers=HEADERS,
                                   allow_redirects=False)
            allow = resp.headers.get("Allow", "")
            if allow:
                path = urlparse(page_url).path or "/"
                findings.append({
                    "check": f"HTTP Methods: OPTIONS [{path}]",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": f"Allowed methods: {allow}",
                    "recommendation": "-"
                })
                passed += 1
        except Exception:
            pass

    # Step 2: Test each dangerous method
    for method_info in DANGEROUS_METHODS:
        method = method_info["method"]
        tests += 1

        accepted = False
        for page_url in test_urls[:3]:
            try:
                resp = requests.request(
                    method, page_url, timeout=timeout,
                    headers=HEADERS, allow_redirects=False
                )
                # Method diterima jika bukan 405 (Method Not Allowed) atau 501 (Not Implemented)
                if resp.status_code not in (405, 501, 400, 403, 404):
                    accepted = True
                    path = urlparse(page_url).path or "/"

                    # TRACE special check: server harus echo back request
                    if method == "TRACE" and resp.status_code == 200:
                        if "TRACE" in resp.text[:500] or "trace" in resp.text[:500].lower():
                            failed += 1
                            findings.append({
                                "check": f"HTTP Method: {method}",
                                "status": "FAIL",
                                "severity": method_info["severity"],
                                "detail": f"{method} method aktif dan berfungsi — {method_info['risk']}",
                                "recommendation": method_info["recommendation"]
                            })
                        break

                    # PUT/DELETE: 200 saja BUKAN bukti. Verifikasi efek nyata.
                    elif method in ("PUT", "DELETE") and resp.status_code in (200, 201, 204):
                        verified = _verify_put_write(page_url, timeout) if method == "PUT" else False
                        if verified:
                            # Terbukti menulis file → finding NYATA, valid.
                            failed += 1
                            findings.append({
                                "check": f"HTTP Method: {method}",
                                "status": "FAIL",
                                "severity": method_info["severity"],
                                "detail": f"{method} TERVERIFIKASI dapat menulis file ke server "
                                          f"(canary write+read berhasil) — {method_info['risk']}",
                                "recommendation": method_info["recommendation"]
                            })
                            break
                        if soft_200:
                            # Server membalas 2xx untuk semua method (SPA/catch-all).
                            # 200 untuk PUT/DELETE di sini = false positive → diabaikan.
                            accepted = False
                            break
                        # Bukan catch-all, tapi efek nyata tidak terverifikasi.
                        findings.append({
                            "check": f"HTTP Method: {method}",
                            "status": "INFO",
                            "severity": "LOW",
                            "detail": f"{method} mengembalikan HTTP {resp.status_code}, tetapi efek "
                                      f"nyata (penulisan/penghapusan) TIDAK terverifikasi. Perlu "
                                      f"verifikasi manual sebelum dianggap kerentanan.",
                            "recommendation": f"Verifikasi apakah {method} benar-benar memodifikasi "
                                              f"resource. Jika tidak diperlukan, nonaktifkan."
                        })
                        break

                    elif method == "CONNECT" and resp.status_code == 200 and not soft_200:
                        failed += 1
                        findings.append({
                            "check": f"HTTP Method: {method}",
                            "status": "FAIL",
                            "severity": method_info["severity"],
                            "detail": f"{method} method aktif — {method_info['risk']}",
                            "recommendation": method_info["recommendation"]
                        })
                        break

            except Exception:
                continue

        if not accepted:
            passed += 1

    if failed == 0 and passed > 0:
        findings.insert(0, {
            "check": "HTTP Method Security",
            "status": "PASS",
            "severity": "INFO",
            "detail": f"Tidak ada HTTP method berbahaya yang aktif ({tests} methods tested)",
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


def _is_soft_200(url: str, timeout: int = 8) -> bool:
    """FIX FALSE POSITIVE: cek apakah server membalas 200 untuk path acak yang
    pasti tidak ada (SPA / catch-all soft-200). Jika ya, status 200 tidak bisa
    dijadikan bukti apa pun."""
    try:
        parsed = urlparse(url)
        token = "spencerweb-404-" + "".join(random.choices(string.ascii_lowercase, k=12))
        canary = f"{parsed.scheme}://{parsed.netloc}/{token}"
        r = requests.get(canary, timeout=timeout, headers=HEADERS, allow_redirects=True)
        return r.status_code == 200
    except Exception:
        return False


def _verify_put_write(page_url: str, timeout: int = 8) -> bool:
    """FIX FALSE POSITIVE: verifikasi PUT benar-benar menulis resource.
    PUT body unik ke path canary, lalu GET kembali. True HANYA jika body unik
    muncul lagi (bukti penulisan nyata). Canary bersifat tidak berbahaya."""
    try:
        parsed = urlparse(page_url)
        token = "spencerweb-put-" + "".join(random.choices(string.ascii_letters + string.digits, k=16))
        canary_url = f"{parsed.scheme}://{parsed.netloc}/{token}.txt"
        body = "spencerweb-canary-" + token
        put = requests.put(canary_url, data=body, timeout=timeout, headers=HEADERS,
                           allow_redirects=False)
        if put.status_code not in (200, 201, 204):
            return False
        got = requests.get(canary_url, timeout=timeout, headers=HEADERS, allow_redirects=False)
        return got.status_code == 200 and body in got.text
    except Exception:
        return False
