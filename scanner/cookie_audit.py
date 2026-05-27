"""
SpencerWeb — Module 15: Cookie Deep Audit
Analisis keamanan cookie secara mendalam pada semua halaman.
"""

import requests
from urllib.parse import urlparse
from utils.crawler import HEADERS

SESSION_COOKIE_PATTERNS = [
    "session", "sess", "sid", "phpsessid", "jsessionid", "asp.net_sessionid",
    "cfid", "cftoken", "token", "auth", "jwt", "access_token", "login",
    "moodlesession", "wordpress_logged_in", "laravel_session", "django_session",
    "_identity", "remember_me", "remember", "credential",
]

def scan_cookies(url, all_urls=None, timeout=10):
    findings = []
    passed = 0
    failed = 0
    cookies_analyzed = 0

    all_urls = all_urls or [url]
    pages = all_urls[:8]
    seen = {}

    for page_url in pages:
        try:
            resp = requests.get(page_url, timeout=timeout, headers=HEADERS, allow_redirects=True)
            for raw in resp.headers.get("Set-Cookie", "").split("\n"):
                raw = raw.strip()
                if not raw or "=" not in raw:
                    continue
                ci = _parse(raw)
                if ci and ci["name"] not in seen:
                    ci["source"] = page_url
                    seen[ci["name"]] = ci
        except Exception:
            continue

    if not seen:
        return {"target": url, "findings": [{"check": "Cookie Security Audit", "status": "PASS",
                "severity": "INFO", "detail": f"Tidak ada cookie di-set pada {len(pages)} halaman",
                "recommendation": "-"}], "cookies_analyzed": 0, "passed": 1, "failed": 0, "total_checks": 1}

    for name, c in seen.items():
        cookies_analyzed += 1
        is_sess = _is_session(name)
        issues = []

        if not c.get("secure"):
            issues.append(("Missing Secure flag", "HIGH" if is_sess else "MEDIUM",
                          "Cookie bisa dikirim via HTTP plaintext"))
        if not c.get("httponly"):
            issues.append(("Missing HttpOnly flag", "HIGH" if is_sess else "LOW",
                          "Cookie bisa diakses via JavaScript (XSS risk)"))
        ss = c.get("samesite", "").lower()
        if not ss or ss == "none":
            issues.append((f"SameSite={'None' if ss == 'none' else 'Missing'}",
                          "MEDIUM" if is_sess else "LOW", "Cookie dikirim pada cross-site request (CSRF risk)"))

        if issues:
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            worst_sev = min(issues, key=lambda x: sev_order.get(x[1], 4))[1]
            failed += 1
            issue_names = "; ".join(i[0] for i in issues)
            rec_parts = []
            for i in issues:
                if "Secure" in i[0]: rec_parts.append("Secure")
                if "HttpOnly" in i[0]: rec_parts.append("HttpOnly")
                if "SameSite" in i[0]: rec_parts.append("SameSite=Lax")
            findings.append({
                "check": f"Cookie: {name}" + (" (session)" if is_sess else ""),
                "status": "FAIL", "severity": worst_sev,
                "detail": f"Cookie '{name}' memiliki {len(issues)} masalah: {issue_names}",
                "recommendation": f"Set flag: {', '.join(rec_parts)} pada cookie '{name}'"
            })
        else:
            passed += 1
            findings.append({
                "check": f"Cookie: {name}", "status": "PASS", "severity": "INFO",
                "detail": f"Cookie '{name}' konfigurasi keamanan baik (Secure, HttpOnly, SameSite)",
                "recommendation": "-"
            })

    return {"target": url, "findings": findings, "cookies_analyzed": cookies_analyzed,
            "pages_checked": len(pages), "passed": passed, "failed": failed,
            "total_checks": max(passed + failed, 1)}

def _parse(header):
    parts = header.split(";")
    nv = parts[0].strip()
    if "=" not in nv: return None
    idx = nv.index("=")
    name = nv[:idx].strip()
    if not name: return None
    c = {"name": name, "secure": False, "httponly": False, "samesite": "", "path": "", "domain": ""}
    for p in parts[1:]:
        p = p.strip().lower()
        if p == "secure": c["secure"] = True
        elif p == "httponly": c["httponly"] = True
        elif p.startswith("samesite="): c["samesite"] = p.split("=", 1)[1].strip()
        elif p.startswith("path="): c["path"] = p.split("=", 1)[1].strip()
        elif p.startswith("domain="): c["domain"] = p.split("=", 1)[1].strip()
    return c

def _is_session(name):
    return any(p in name.lower() for p in SESSION_COOKIE_PATTERNS)
