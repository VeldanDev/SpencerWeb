"""
SpencerWeb — Module 14: Information Leak Scanner
Scan HTML source code dari semua halaman yang di-crawl untuk menemukan
informasi sensitif yang tidak sengaja ter-expose.

Deteksi: email addresses, API keys, tokens, passwords, internal IPs,
database connection strings, AWS keys, private keys, dll.
"""

import re
import requests
from urllib.parse import urlparse
from utils.crawler import HEADERS


# Regex patterns untuk informasi sensitif
LEAK_PATTERNS = [
    {
        "name": "Email Address",
        "pattern": r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        "severity": "LOW",
        "exclude": ["example.com", "example.org", "test.com", "placeholder",
                    "email@", "user@", "name@", "your@", "wixpress.com",
                    "sentry.io", "gravatar.com", "w3.org", "schema.org",
                    "xmlns", "jquery", "wordpress"],
        "description": "Email address ditemukan di source code — bisa digunakan untuk phishing/spam",
        "recommendation": "Jangan hardcode email di HTML. Gunakan form kontak atau obfuscation."
    },
    {
        "name": "AWS Access Key",
        "pattern": r'AKIA[0-9A-Z]{16}',
        "severity": "CRITICAL",
        "exclude": [],
        "description": "AWS Access Key ter-expose — attacker bisa mengakses cloud resources",
        "recommendation": "SEGERA revoke key ini dan generate yang baru. Jangan simpan credentials di source code."
    },
    {
        "name": "AWS Secret Key",
        "pattern": r'(?i)aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})',
        "severity": "CRITICAL",
        "exclude": [],
        "description": "AWS Secret Key ter-expose",
        "recommendation": "SEGERA revoke dan regenerate. Gunakan environment variables."
    },
    {
        "name": "Generic API Key",
        "pattern": r'(?i)(api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*["\']([a-zA-Z0-9\-_]{20,})["\']',
        "severity": "HIGH",
        "exclude": ["YOUR_API_KEY", "your_api_key", "PLACEHOLDER", "xxx", "example"],
        "description": "API key ter-expose di source code",
        "recommendation": "Pindahkan API key ke environment variable atau server-side config."
    },
    {
        "name": "Generic Secret/Token",
        "pattern": r'(?i)(secret|token|password|passwd|pwd)\s*[=:]\s*["\']([a-zA-Z0-9\-_!@#$%^&*]{8,})["\']',
        "severity": "HIGH",
        "exclude": ["YOUR_", "your_", "PLACEHOLDER", "example", "xxx", "password",
                    "token", "secret", "change_me", "undefined", "null", "none",
                    "csrf", "nonce", "wp_nonce"],
        "description": "Secret/token/password ter-expose di source code",
        "recommendation": "JANGAN hardcode credentials di source code. Gunakan env vars."
    },
    {
        "name": "Private IP Address",
        "pattern": r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
        "severity": "LOW",
        "exclude": [],
        "description": "Internal/private IP address ter-expose — membocorkan struktur jaringan internal",
        "recommendation": "Hapus referensi IP internal dari source code yang di-serve ke publik."
    },
    {
        "name": "Database Connection String",
        "pattern": r'(?i)(mysql|postgres|mongodb|redis|sqlite):\/\/[^\s<>"\']+',
        "severity": "CRITICAL",
        "exclude": ["localhost", "127.0.0.1", "example"],
        "description": "Database connection string ter-expose — berisi hostname, username, dan mungkin password",
        "recommendation": "SEGERA ubah credentials database. Pindahkan ke server-side config."
    },
    {
        "name": "Google API Key",
        "pattern": r'AIza[0-9A-Za-z\-_]{35}',
        "severity": "MEDIUM",
        "exclude": [],
        "description": "Google API key ter-expose — bisa disalahgunakan untuk billing",
        "recommendation": "Batasi API key ke domain spesifik via Google Cloud Console."
    },
    {
        "name": "GitHub Token",
        "pattern": r'gh[pousr]_[A-Za-z0-9_]{36,}',
        "severity": "CRITICAL",
        "exclude": [],
        "description": "GitHub personal access token ter-expose",
        "recommendation": "SEGERA revoke token di GitHub Settings > Developer Settings."
    },
    {
        "name": "JWT Token",
        "pattern": r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
        "severity": "MEDIUM",
        "exclude": [],
        "description": "JWT token ditemukan di HTML source — bisa di-decode untuk melihat payload",
        "recommendation": "Jangan expose JWT di HTML. Simpan di HttpOnly cookie atau header saja."
    },
]


def scan_info_leak(url: str, all_urls: list = None, timeout: int = 10) -> dict:
    findings = []
    passed = 0
    failed = 0
    total_leaks = 0

    all_urls = all_urls or [url]
    pages_to_scan = all_urls[:15]
    seen_leaks = set()  # De-duplicate

    for page_url in pages_to_scan:
        try:
            resp = requests.get(page_url, timeout=timeout, headers=HEADERS,
                               allow_redirects=True)
            if resp.status_code != 200:
                continue

            html = resp.text
            path = urlparse(page_url).path or "/"

            for pattern_info in LEAK_PATTERNS:
                matches = re.findall(pattern_info["pattern"], html)

                for match in matches:
                    # Handle tuple results from regex groups
                    if isinstance(match, tuple):
                        match = match[-1]  # Take last group

                    match_str = str(match).strip()

                    # Skip excluded patterns
                    if any(ex.lower() in match_str.lower() for ex in pattern_info["exclude"]):
                        continue

                    # Skip very short matches
                    if len(match_str) < 5:
                        continue

                    # De-duplicate
                    leak_key = f"{pattern_info['name']}:{match_str[:30]}"
                    if leak_key in seen_leaks:
                        continue
                    seen_leaks.add(leak_key)

                    total_leaks += 1
                    failed += 1

                    # Mask sensitive value for display
                    masked = match_str[:4] + "****" + match_str[-4:] if len(match_str) > 12 else "****"

                    findings.append({
                        "check": f"Info Leak: {pattern_info['name']} [{path}]",
                        "status": "FAIL",
                        "severity": pattern_info["severity"],
                        "detail": f"{pattern_info['description']}. "
                                 f"Value (masked): {masked}",
                        "recommendation": pattern_info["recommendation"]
                    })

        except Exception:
            continue

    if failed == 0:
        passed = 1
        findings.append({
            "check": "Information Leak Scan",
            "status": "PASS",
            "severity": "INFO",
            "detail": f"Tidak ditemukan informasi sensitif di source code "
                     f"({len(pages_to_scan)} halaman di-scan, "
                     f"{len(LEAK_PATTERNS)} pattern types)",
            "recommendation": "-"
        })

    return {
        "target": url,
        "findings": findings,
        "pages_scanned": len(pages_to_scan),
        "total_leaks": total_leaks,
        "patterns_checked": len(LEAK_PATTERNS),
        "passed": passed,
        "failed": failed,
        "total_checks": max(passed + failed, 1)
    }
