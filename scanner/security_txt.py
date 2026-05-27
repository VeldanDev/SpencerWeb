"""
SpencerWeb — Module 19: Security.txt & robots.txt Analyzer
Analisis file security.txt dan robots.txt untuk:
1. security.txt: apakah ada, apakah sesuai RFC 9116
2. robots.txt: apakah ada path sensitif yang di-disallow (info disclosure)
"""

import requests
from urllib.parse import urljoin
from utils.crawler import HEADERS


SENSITIVE_DISALLOW_PATTERNS = [
    "admin", "login", "dashboard", "cpanel", "config", "backup",
    "database", "secret", "private", "internal", "staging", "dev",
    "api", "upload", "file", "debug", "test", "tmp", "log",
    "password", "credential", "token", "key", "env",
]


def scan_security_files(url, timeout=10):
    findings = []
    passed = 0
    failed = 0

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # === SECURITY.TXT ===
    sec_urls = [
        urljoin(url, "/.well-known/security.txt"),
        urljoin(url, "/security.txt"),
    ]

    security_txt_found = False
    security_txt_content = ""

    for sec_url in sec_urls:
        try:
            r = requests.get(sec_url, timeout=timeout, headers=HEADERS, allow_redirects=True)
            if r.status_code == 200 and "contact:" in r.text.lower():
                security_txt_found = True
                security_txt_content = r.text
                break
        except Exception:
            continue

    if security_txt_found:
        # Validate RFC 9116 compliance
        has_contact = "contact:" in security_txt_content.lower()
        has_expires = "expires:" in security_txt_content.lower()
        has_encryption = "encryption:" in security_txt_content.lower()
        has_policy = "policy:" in security_txt_content.lower()

        if has_contact and has_expires:
            passed += 1
            extras = []
            if has_encryption: extras.append("Encryption")
            if has_policy: extras.append("Policy")
            findings.append({
                "check": "security.txt",
                "status": "PASS", "severity": "INFO",
                "detail": f"security.txt ditemukan dan sesuai RFC 9116 (Contact + Expires). "
                         f"Extra fields: {', '.join(extras) if extras else 'Tidak ada'}",
                "recommendation": "-"
            })
        elif has_contact:
            passed += 1
            findings.append({
                "check": "security.txt (incomplete)",
                "status": "PASS", "severity": "LOW",
                "detail": "security.txt ditemukan tapi tidak lengkap — missing Expires field (wajib per RFC 9116)",
                "recommendation": "Tambahkan field 'Expires:' ke security.txt sesuai RFC 9116"
            })
        else:
            passed += 1
            findings.append({
                "check": "security.txt", "status": "PASS", "severity": "INFO",
                "detail": "security.txt ditemukan", "recommendation": "-"
            })
    else:
        failed += 1
        findings.append({
            "check": "security.txt (missing)",
            "status": "FAIL", "severity": "LOW",
            "detail": "security.txt tidak ditemukan — best practice adalah menyediakan file ini "
                     "agar security researcher tahu cara melaporkan kerentanan",
            "recommendation": "Buat file /.well-known/security.txt sesuai RFC 9116. "
                             "Minimal berisi Contact: dan Expires: fields."
        })

    # === ROBOTS.TXT ===
    try:
        robots_url = urljoin(url, "/robots.txt")
        r = requests.get(robots_url, timeout=timeout, headers=HEADERS, allow_redirects=True)

        if r.status_code == 200 and ("user-agent" in r.text.lower() or "disallow" in r.text.lower()):
            # Parse disallow entries
            disallow_paths = []
            sensitive_paths = []

            for line in r.text.split("\n"):
                line = line.strip().lower()
                if line.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/":
                        disallow_paths.append(path)
                        # Check if path reveals sensitive info
                        for pattern in SENSITIVE_DISALLOW_PATTERNS:
                            if pattern in path.lower():
                                sensitive_paths.append(path)
                                break

            if sensitive_paths:
                failed += 1
                paths_display = ", ".join(sensitive_paths[:5])
                findings.append({
                    "check": "robots.txt (info disclosure)",
                    "status": "FAIL", "severity": "LOW",
                    "detail": f"robots.txt mengexpose {len(sensitive_paths)} path sensitif: {paths_display}. "
                             f"Attacker bisa menggunakan ini sebagai peta untuk menemukan halaman tersembunyi.",
                    "recommendation": "Pertimbangkan untuk tidak mendaftarkan path sensitif di robots.txt. "
                                     "Gunakan autentikasi sebagai proteksi utama, bukan security by obscurity."
                })
            else:
                passed += 1
                findings.append({
                    "check": "robots.txt",
                    "status": "PASS", "severity": "INFO",
                    "detail": f"robots.txt ditemukan dengan {len(disallow_paths)} disallow entries. "
                             f"Tidak ada path sensitif yang ter-expose.",
                    "recommendation": "-"
                })
        else:
            passed += 1
            findings.append({
                "check": "robots.txt (missing)",
                "status": "PASS", "severity": "INFO",
                "detail": "robots.txt tidak ditemukan atau kosong",
                "recommendation": "-"
            })

    except Exception:
        pass

    return {"target": url, "findings": findings,
            "passed": passed, "failed": failed,
            "total_checks": max(passed + failed, 1)}
