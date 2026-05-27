"""
SpencerWeb — Module 20: WAF (Web Application Firewall) Detection
Deteksi apakah target dilindungi oleh WAF dan identifikasi jenis WAF-nya.

Ini bukan vulnerability tapi intelligence — mengetahui WAF membantu:
1. Memahami postur keamanan target
2. Menjelaskan kenapa beberapa test mungkin di-block
3. Menilai investasi keamanan website
"""

import requests
from urllib.parse import urljoin
from utils.crawler import HEADERS


WAF_SIGNATURES = [
    {
        "name": "Cloudflare",
        "headers": {"Server": "cloudflare", "CF-RAY": ""},
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
        "body_patterns": ["cloudflare", "cf-browser-verification"],
    },
    {
        "name": "AWS WAF (CloudFront)",
        "headers": {"X-Amz-Cf-Id": "", "Via": "cloudfront", "X-Cache": ""},
        "cookies": ["awsalb", "awsalbcors"],
        "body_patterns": [],
    },
    {
        "name": "Akamai",
        "headers": {"X-Akamai-Transformed": "", "Server": "AkamaiGHost"},
        "cookies": ["akamai_"],
        "body_patterns": ["akamai"],
    },
    {
        "name": "Sucuri",
        "headers": {"X-Sucuri-ID": "", "Server": "Sucuri"},
        "cookies": ["sucuri_"],
        "body_patterns": ["sucuri", "access denied - sucuri"],
    },
    {
        "name": "ModSecurity",
        "headers": {"Server": "ModSecurity"},
        "cookies": [],
        "body_patterns": ["mod_security", "modsecurity", "not acceptable"],
    },
    {
        "name": "Imperva (Incapsula)",
        "headers": {"X-CDN": "Incapsula", "X-Iinfo": ""},
        "cookies": ["incap_ses", "visid_incap"],
        "body_patterns": ["incapsula", "imperva"],
    },
    {
        "name": "F5 BIG-IP",
        "headers": {"Server": "BIG-IP", "X-WA-Info": ""},
        "cookies": ["BIGipServer", "TS"],
        "body_patterns": ["the requested url was rejected"],
    },
    {
        "name": "Barracuda",
        "headers": {"Server": "Barracuda"},
        "cookies": ["barra_"],
        "body_patterns": ["barracuda"],
    },
    {
        "name": "Fastly",
        "headers": {"Via": "varnish", "X-Served-By": "", "X-Cache": ""},
        "cookies": [],
        "body_patterns": [],
    },
    {
        "name": "Vercel",
        "headers": {"Server": "Vercel", "X-Vercel-Id": ""},
        "cookies": [],
        "body_patterns": [],
    },
    {
        "name": "Netlify",
        "headers": {"Server": "Netlify", "X-NF-Request-ID": ""},
        "cookies": [],
        "body_patterns": [],
    },
    {
        "name": "DDoS-Guard",
        "headers": {"Server": "ddos-guard"},
        "cookies": ["__ddg"],
        "body_patterns": ["ddos-guard"],
    },
]


def scan_waf(url, timeout=10):
    findings = []
    passed = 0
    failed = 0
    detected_wafs = []

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Request 1: Normal request
    try:
        resp = requests.get(url, timeout=timeout, headers=HEADERS, allow_redirects=True)
        resp_headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        resp_cookies = [c.name.lower() for c in resp.cookies]
        resp_body = resp.text[:5000].lower()
    except Exception as e:
        return {"target": url, "error": str(e), "findings": [],
                "passed": 0, "failed": 0, "total_checks": 0}

    # Request 2: Malicious-looking request (trigger WAF)
    evil_headers = dict(HEADERS)
    evil_url = urljoin(url, "/?id=1' OR '1'='1' UNION SELECT * FROM users--")
    try:
        evil_resp = requests.get(evil_url, timeout=timeout, headers=evil_headers,
                                allow_redirects=True)
        evil_status = evil_resp.status_code
        evil_body = evil_resp.text[:5000].lower()
        evil_headers_resp = {k.lower(): v.lower() for k, v in evil_resp.headers.items()}
    except Exception:
        evil_status = 0
        evil_body = ""
        evil_headers_resp = {}

    # Detect WAF from signatures
    for waf in WAF_SIGNATURES:
        detected = False
        evidence = []

        # Check headers
        for header_name, header_pattern in waf["headers"].items():
            header_lower = header_name.lower()
            if header_lower in resp_headers:
                if not header_pattern or header_pattern in resp_headers[header_lower]:
                    detected = True
                    evidence.append(f"Header: {header_name}")

        # Check cookies
        for cookie_pattern in waf["cookies"]:
            for rc in resp_cookies:
                if cookie_pattern.lower() in rc:
                    detected = True
                    evidence.append(f"Cookie: {rc}")

        # Check body patterns
        for bp in waf["body_patterns"]:
            if bp in resp_body or bp in evil_body:
                detected = True
                evidence.append(f"Body pattern: {bp}")

        if detected:
            detected_wafs.append({
                "name": waf["name"],
                "evidence": evidence
            })

    # Check if WAF blocked malicious request
    waf_blocked = False
    if evil_status in (403, 406, 429, 503):
        waf_blocked = True

    # Generate findings
    if detected_wafs:
        for waf in detected_wafs:
            passed += 1
            findings.append({
                "check": f"WAF: {waf['name']} detected",
                "status": "PASS", "severity": "INFO",
                "detail": f"Website dilindungi oleh {waf['name']}. "
                         f"Evidence: {', '.join(waf['evidence'][:3])}",
                "recommendation": "-"
            })

        if waf_blocked:
            passed += 1
            findings.append({
                "check": "WAF: Active blocking",
                "status": "PASS", "severity": "INFO",
                "detail": f"WAF aktif memblokir malicious request (HTTP {evil_status} saat payload SQLi dikirim)",
                "recommendation": "-"
            })
    else:
        failed += 1
        findings.append({
            "check": "WAF Detection",
            "status": "FAIL", "severity": "LOW",
            "detail": "Tidak terdeteksi WAF (Web Application Firewall) — "
                     "website mungkin tidak menggunakan layer proteksi tambahan",
            "recommendation": "Pertimbangkan menggunakan WAF seperti Cloudflare, AWS WAF, atau ModSecurity "
                             "untuk proteksi tambahan terhadap serangan web"
        })

    return {"target": url, "findings": findings, "detected_wafs": detected_wafs,
            "waf_count": len(detected_wafs), "blocked_malicious": waf_blocked,
            "passed": passed, "failed": failed,
            "total_checks": max(passed + failed, 1)}
