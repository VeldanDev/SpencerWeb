"""
WebAudit — Modul Audit HTTP Security Headers
Mengecek keberadaan dan konfigurasi header keamanan HTTP
sesuai standar OWASP Secure Headers Project
"""

import requests
from urllib.parse import urlparse


# Header rules: (header_name, severity_if_missing, description, recommendation)
SECURITY_HEADERS = [
    {
        "name": "Strict-Transport-Security",
        "severity": "HIGH",
        "description": "Memaksa browser selalu menggunakan HTTPS",
        "recommendation": "Tambahkan header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    {
        "name": "Content-Security-Policy",
        "severity": "HIGH", 
        "description": "Mencegah XSS dan injeksi konten berbahaya",
        "recommendation": "Tambahkan header CSP yang sesuai. Minimal: Content-Security-Policy: default-src 'self'"
    },
    {
        "name": "X-Frame-Options",
        "severity": "MEDIUM",
        "description": "Mencegah clickjacking via iframe",
        "recommendation": "Tambahkan header: X-Frame-Options: DENY atau SAMEORIGIN"
    },
    {
        "name": "X-Content-Type-Options",
        "severity": "MEDIUM",
        "description": "Mencegah MIME-type sniffing",
        "recommendation": "Tambahkan header: X-Content-Type-Options: nosniff"
    },
    {
        "name": "X-XSS-Protection",
        "severity": "LOW",
        "description": "Mengaktifkan filter XSS bawaan browser (legacy)",
        "recommendation": "Tambahkan header: X-XSS-Protection: 1; mode=block (atau gunakan CSP sebagai pengganti)"
    },
    {
        "name": "Referrer-Policy",
        "severity": "LOW",
        "description": "Mengontrol informasi referrer yang dikirim browser",
        "recommendation": "Tambahkan header: Referrer-Policy: strict-origin-when-cross-origin"
    },
    {
        "name": "Permissions-Policy",
        "severity": "LOW",
        "description": "Mengontrol akses fitur browser (kamera, mikrofon, geolokasi)",
        "recommendation": "Tambahkan header: Permissions-Policy: geolocation=(), camera=(), microphone=()"
    },
]

# Headers that SHOULD NOT be present (information leakage)
LEAKY_HEADERS = [
    {
        "name": "Server",
        "severity": "LOW",
        "description": "Membocorkan versi web server (misal: Apache/2.4.41)",
        "recommendation": "Sembunyikan atau hapus header Server dari response"
    },
    {
        "name": "X-Powered-By",
        "severity": "LOW",
        "description": "Membocorkan teknologi backend (misal: PHP/7.4, Express)",
        "recommendation": "Hapus header X-Powered-By dari response"
    },
]


def audit_headers(url: str, timeout: int = 10) -> dict:
    """
    Audit HTTP security headers pada target URL.
    
    Returns:
        dict: {
            "target": str,
            "status_code": int,
            "findings": list[dict],
            "raw_headers": dict,
            "passed": int,
            "failed": int,
            "total_checks": int
        }
    """
    # Pastikan URL punya scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    findings = []
    passed = 0
    failed = 0

    try:
        response = requests.get(
            url, 
            timeout=timeout, 
            allow_redirects=True,
            headers={"User-Agent": "WebAudit/1.0 (Security Scanner - Educational Purpose)"}
        )
    except requests.exceptions.SSLError:
        findings.append({
            "check": "SSL Connection",
            "status": "FAIL",
            "severity": "CRITICAL",
            "detail": "Koneksi SSL gagal — sertifikat tidak valid atau expired",
            "recommendation": "Periksa dan perbarui sertifikat SSL"
        })
        # Retry tanpa SSL verification
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=True, verify=False,
                                     headers={"User-Agent": "WebAudit/1.0"})
        except Exception as e:
            return {"target": url, "error": str(e), "findings": findings}
    except requests.exceptions.ConnectionError as e:
        return {"target": url, "error": f"Tidak dapat terhubung: {e}", "findings": findings}
    except requests.exceptions.Timeout:
        return {"target": url, "error": "Koneksi timeout", "findings": findings}
    except Exception as e:
        return {"target": url, "error": str(e), "findings": findings}

    headers = response.headers

    # === CHECK 1: Security headers yang HARUS ada ===
    for rule in SECURITY_HEADERS:
        header_name = rule["name"]
        header_value = headers.get(header_name)

        if header_value:
            passed += 1
            findings.append({
                "check": header_name,
                "status": "PASS",
                "severity": "INFO",
                "detail": f"Ditemukan: {header_value[:80]}",
                "recommendation": "-"
            })
        else:
            failed += 1
            findings.append({
                "check": header_name,
                "status": "FAIL",
                "severity": rule["severity"],
                "detail": rule["description"],
                "recommendation": rule["recommendation"]
            })

    # === CHECK 2: Headers yang SEHARUSNYA TIDAK ada (info leak) ===
    for rule in LEAKY_HEADERS:
        header_name = rule["name"]
        header_value = headers.get(header_name)

        if header_value:
            failed += 1
            findings.append({
                "check": f"{header_name} (Info Leak)",
                "status": "FAIL",
                "severity": rule["severity"],
                "detail": f"Terdeteksi: {header_value} — {rule['description']}",
                "recommendation": rule["recommendation"]
            })
        else:
            passed += 1
            findings.append({
                "check": f"{header_name} (Info Leak)",
                "status": "PASS",
                "severity": "INFO",
                "detail": "Tidak ditemukan (bagus)",
                "recommendation": "-"
            })

    # === CHECK 3: Cookie security flags ===
    cookies = response.cookies
    for cookie in cookies:
        issues = []
        if not cookie.secure:
            issues.append("Missing 'Secure' flag")
        if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie).lower():
            issues.append("Missing 'HttpOnly' flag")

        if issues:
            failed += 1
            findings.append({
                "check": f"Cookie: {cookie.name}",
                "status": "FAIL",
                "severity": "MEDIUM",
                "detail": f"Cookie tidak aman: {', '.join(issues)}",
                "recommendation": "Set flag Secure dan HttpOnly pada semua cookie sensitif"
            })
        else:
            passed += 1
            findings.append({
                "check": f"Cookie: {cookie.name}",
                "status": "PASS",
                "severity": "INFO",
                "detail": "Cookie flags aman",
                "recommendation": "-"
            })

    # === CHECK 4: HTTPS redirect check ===
    parsed = urlparse(url)
    if parsed.scheme == "https":
        try:
            http_url = url.replace("https://", "http://", 1)
            http_resp = requests.get(http_url, timeout=timeout, allow_redirects=False,
                                      headers={"User-Agent": "WebAudit/1.0"})
            if http_resp.status_code in (301, 302, 307, 308):
                location = http_resp.headers.get("Location", "")
                if location.startswith("https://"):
                    passed += 1
                    findings.append({
                        "check": "HTTP → HTTPS Redirect",
                        "status": "PASS",
                        "severity": "INFO",
                        "detail": f"HTTP redirect ke HTTPS ({http_resp.status_code})",
                        "recommendation": "-"
                    })
                else:
                    failed += 1
                    findings.append({
                        "check": "HTTP → HTTPS Redirect",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "detail": "HTTP tidak redirect ke HTTPS",
                        "recommendation": "Konfigurasi server untuk redirect semua HTTP ke HTTPS"
                    })
            else:
                failed += 1
                findings.append({
                    "check": "HTTP → HTTPS Redirect",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "detail": f"HTTP merespon tanpa redirect (status: {http_resp.status_code})",
                    "recommendation": "Konfigurasi server untuk redirect semua HTTP ke HTTPS"
                })
        except Exception:
            findings.append({
                "check": "HTTP → HTTPS Redirect",
                "status": "INFO",
                "severity": "INFO",
                "detail": "Tidak dapat mengecek redirect HTTP",
                "recommendation": "Verifikasi manual redirect HTTP ke HTTPS"
            })

    return {
        "target": url,
        "status_code": response.status_code,
        "final_url": response.url,
        "findings": findings,
        "raw_headers": dict(headers),
        "passed": passed,
        "failed": failed,
        "total_checks": passed + failed
    }
