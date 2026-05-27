"""
SpencerWeb — Module 18: Technology Fingerprinting
Deteksi teknologi yang digunakan website: framework, JS libraries,
server software, CDN, analytics, dan versinya.

Info ini berguna untuk:
1. Mengetahui attack surface (versi lama = CVE known)
2. Memahami tech stack target
3. Menemukan technology-specific vulnerabilities
"""

import re
import requests
from urllib.parse import urlparse
from utils.crawler import HEADERS


def scan_tech_fingerprint(url, all_urls=None, timeout=10):
    findings = []
    passed = 0
    failed = 0
    technologies = []

    all_urls = all_urls or [url]

    try:
        resp = requests.get(url, timeout=timeout, headers=HEADERS, allow_redirects=True)
        html = resp.text
        headers = resp.headers
    except Exception as e:
        return {"target": url, "error": str(e), "findings": [],
                "passed": 0, "failed": 0, "total_checks": 0}

    # === SERVER & INFRASTRUCTURE ===
    server = headers.get("Server", "")
    if server:
        technologies.append({"name": "Server", "value": server, "source": "HTTP Header"})

    powered = headers.get("X-Powered-By", "")
    if powered:
        technologies.append({"name": "X-Powered-By", "value": powered, "source": "HTTP Header"})
        failed += 1
        findings.append({
            "check": f"Tech: X-Powered-By: {powered}",
            "status": "FAIL", "severity": "LOW",
            "detail": f"Server mengexpose X-Powered-By: {powered} — membocorkan teknologi backend",
            "recommendation": "Hapus header X-Powered-By dari response server"
        })

    # CDN detection
    cf_ray = headers.get("CF-RAY", "")
    if cf_ray or "cloudflare" in server.lower():
        technologies.append({"name": "CDN", "value": "Cloudflare", "source": "HTTP Header"})

    if headers.get("X-Varnish"):
        technologies.append({"name": "Cache", "value": "Varnish", "source": "HTTP Header"})

    if headers.get("X-Cache"):
        technologies.append({"name": "Cache", "value": headers["X-Cache"], "source": "HTTP Header"})

    # === CMS / FRAMEWORK DETECTION (HTML) ===
    cms_patterns = [
        (r'<meta name="generator" content="WordPress\s*([\d.]*)"', "WordPress", "CMS"),
        (r'<meta name="generator" content="Joomla[!]?\s*([\d.]*)"', "Joomla", "CMS"),
        (r'<meta name="generator" content="Drupal\s*([\d.]*)"', "Drupal", "CMS"),
        (r'/wp-content/', "WordPress", "CMS"),
        (r'/wp-includes/', "WordPress", "CMS"),
        (r'Moodle', "Moodle", "LMS"),
        (r'<meta name="generator" content="Hugo\s*([\d.]*)"', "Hugo", "SSG"),
        (r'__next', "Next.js", "Framework"),
        (r'__nuxt', "Nuxt.js", "Framework"),
        (r'ng-version="([\d.]+)"', "Angular", "Framework"),
        (r'data-reactroot', "React", "Library"),
        (r'__GATSBY', "Gatsby", "SSG"),
        (r'Shopify\.', "Shopify", "E-commerce"),
        (r'<!-- This is Squarespace', "Squarespace", "CMS"),
        (r'<meta name="generator" content="Wix', "Wix", "CMS"),
        (r'Laravel', "Laravel", "Framework"),
        (r'csrfmiddlewaretoken', "Django", "Framework"),
        (r'__RequestVerificationToken', "ASP.NET", "Framework"),
        (r'PHPSESSID', "PHP", "Language"),
        (r'JSESSIONID', "Java", "Language"),
        (r'ASP\.NET_SessionId', "ASP.NET", "Framework"),
    ]

    seen_tech = set()
    for pattern, name, category in cms_patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match and name not in seen_tech:
            seen_tech.add(name)
            version = ""
            if match.lastindex and match.group(1):
                version = match.group(1)
            technologies.append({
                "name": name, "value": version or "detected",
                "source": "HTML", "category": category
            })

    # === JAVASCRIPT LIBRARIES ===
    js_patterns = [
        (r'jquery[.\-/](\d+\.\d+[\.\d]*)', "jQuery"),
        (r'bootstrap[.\-/](\d+\.\d+[\.\d]*)', "Bootstrap"),
        (r'vue[.\-/](\d+\.\d+[\.\d]*)', "Vue.js"),
        (r'react[.\-/](\d+\.\d+[\.\d]*)', "React"),
        (r'angular[.\-/](\d+\.\d+[\.\d]*)', "Angular"),
        (r'lodash[.\-/](\d+\.\d+[\.\d]*)', "Lodash"),
        (r'moment[.\-/](\d+\.\d+[\.\d]*)', "Moment.js"),
        (r'axios[.\-/](\d+\.\d+[\.\d]*)', "Axios"),
        (r'd3[.\-/]v?(\d+\.\d+[\.\d]*)', "D3.js"),
        (r'chart\.js[.\-/](\d+\.\d+[\.\d]*)', "Chart.js"),
        (r'gsap', "GSAP"),
        (r'three\.js', "Three.js"),
        (r'socket\.io', "Socket.IO"),
        (r'fontawesome|fa-', "Font Awesome"),
        (r'tailwindcss|tailwind', "Tailwind CSS"),
        (r'google-analytics|ga\.js|gtag', "Google Analytics"),
        (r'gtm\.js|googletagmanager', "Google Tag Manager"),
        (r'facebook.*pixel|fbevents', "Facebook Pixel"),
        (r'hotjar', "Hotjar"),
        (r'clarity\.ms', "Microsoft Clarity"),
        (r'recaptcha', "Google reCAPTCHA"),
    ]

    for pattern, name in js_patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match and name not in seen_tech:
            seen_tech.add(name)
            version = match.group(1) if match.lastindex else ""
            technologies.append({
                "name": name, "value": version or "detected",
                "source": "HTML/JS"
            })

    # === PHP VERSION from headers ===
    php_match = re.search(r'PHP/([\d.]+)', powered + " " + server)
    if php_match:
        php_ver = php_match.group(1)
        technologies.append({"name": "PHP", "value": php_ver, "source": "HTTP Header"})
        # Check if outdated
        major = int(php_ver.split(".")[0]) if php_ver.split(".")[0].isdigit() else 0
        minor = int(php_ver.split(".")[1]) if len(php_ver.split(".")) > 1 and php_ver.split(".")[1].isdigit() else 0
        if major < 8:
            failed += 1
            findings.append({
                "check": f"Tech: PHP {php_ver} (outdated)",
                "status": "FAIL", "severity": "HIGH",
                "detail": f"PHP {php_ver} terdeteksi — versi ini sudah End of Life dan tidak mendapat security patches",
                "recommendation": f"Upgrade PHP ke versi 8.2+ (current stable)"
            })

    # Generate summary finding
    if technologies:
        tech_summary = ", ".join(
            f"{t['name']}" + (f" {t['value']}" if t['value'] != 'detected' else "")
            for t in technologies[:10]
        )
        passed += 1
        findings.insert(0, {
            "check": "Technology Stack",
            "status": "PASS", "severity": "INFO",
            "detail": f"Terdeteksi {len(technologies)} teknologi: {tech_summary}",
            "recommendation": "-"
        })
    else:
        passed += 1
        findings.append({
            "check": "Technology Fingerprint",
            "status": "PASS", "severity": "INFO",
            "detail": "Tidak banyak teknologi yang bisa diidentifikasi (server menyembunyikan fingerprint dengan baik)",
            "recommendation": "-"
        })

    return {"target": url, "findings": findings, "technologies": technologies,
            "tech_count": len(technologies), "passed": passed, "failed": failed,
            "total_checks": max(passed + failed, 1)}
