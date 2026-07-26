"""
Spencer v2.0 — WordPress Plugin & Theme Vulnerability Scanner
Enumerasi plugin/theme WordPress yang ter-install pada target,
deteksi versinya, dan flag yang outdated atau punya kerentanan known.

Tidak menggunakan database CVE eksternal — fingerprinting via:
1. Path enumeration (/wp-content/plugins/, /wp-content/themes/)
2. readme.txt parsing untuk version detection
3. Static list plugin populer dan latest version
"""

import re
import random
import string
import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.crawler import HEADERS


# Top 50 plugin WordPress paling populer (berdasarkan jumlah install di WordPress.org)
# Disertai versi stable terbaru (perlu update berkala)
POPULAR_PLUGINS = [
    {"slug": "akismet", "name": "Akismet Anti-Spam", "latest": "5.4"},
    {"slug": "contact-form-7", "name": "Contact Form 7", "latest": "5.9"},
    {"slug": "wordpress-seo", "name": "Yoast SEO", "latest": "23.4"},
    {"slug": "wpforms-lite", "name": "WPForms Lite", "latest": "1.9.2"},
    {"slug": "elementor", "name": "Elementor", "latest": "3.25"},
    {"slug": "woocommerce", "name": "WooCommerce", "latest": "9.4"},
    {"slug": "jetpack", "name": "Jetpack", "latest": "13.9"},
    {"slug": "classic-editor", "name": "Classic Editor", "latest": "1.6"},
    {"slug": "wordfence", "name": "Wordfence Security", "latest": "8.0"},
    {"slug": "all-in-one-seo-pack", "name": "All in One SEO", "latest": "4.7"},
    {"slug": "duplicate-post", "name": "Duplicate Post", "latest": "4.5"},
    {"slug": "wp-super-cache", "name": "WP Super Cache", "latest": "1.12"},
    {"slug": "wp-optimize", "name": "WP-Optimize", "latest": "3.7"},
    {"slug": "really-simple-ssl", "name": "Really Simple SSL", "latest": "8.2"},
    {"slug": "updraftplus", "name": "UpdraftPlus", "latest": "1.24"},
    {"slug": "google-analytics-for-wordpress", "name": "MonsterInsights", "latest": "9.4"},
    {"slug": "litespeed-cache", "name": "LiteSpeed Cache", "latest": "6.5"},
    {"slug": "redirection", "name": "Redirection", "latest": "5.4"},
    {"slug": "wp-mail-smtp", "name": "WP Mail SMTP", "latest": "4.3"},
    {"slug": "tinymce-advanced", "name": "TinyMCE Advanced", "latest": "5.6"},
    {"slug": "elementor-pro", "name": "Elementor Pro", "latest": "3.25"},
    {"slug": "advanced-custom-fields", "name": "Advanced Custom Fields", "latest": "6.3"},
    {"slug": "polylang", "name": "Polylang", "latest": "3.6"},
    {"slug": "wpml-multilingual-cms", "name": "WPML", "latest": "4.6"},
    {"slug": "loco-translate", "name": "Loco Translate", "latest": "2.6"},
    {"slug": "cookie-notice", "name": "Cookie Notice", "latest": "2.5"},
    {"slug": "wp-statistics", "name": "WP Statistics", "latest": "14.10"},
    {"slug": "broken-link-checker", "name": "Broken Link Checker", "latest": "2.4"},
    {"slug": "smush", "name": "Smush Image Compression", "latest": "3.18"},
    {"slug": "wp-rocket", "name": "WP Rocket", "latest": "3.17"},
    {"slug": "ninja-forms", "name": "Ninja Forms", "latest": "3.8"},
    {"slug": "mailchimp-for-wp", "name": "MC4WP Mailchimp", "latest": "4.10"},
    {"slug": "google-site-kit", "name": "Site Kit by Google", "latest": "1.144"},
    {"slug": "all-in-one-wp-migration", "name": "All-in-One WP Migration", "latest": "7.91"},
    {"slug": "duplicator", "name": "Duplicator", "latest": "1.5"},
    {"slug": "wp-fastest-cache", "name": "WP Fastest Cache", "latest": "1.3"},
    {"slug": "advanced-cron-manager", "name": "Advanced Cron Manager", "latest": "2.5"},
    {"slug": "antispam-bee", "name": "Antispam Bee", "latest": "2.11"},
    {"slug": "wp-mail-logging", "name": "WP Mail Logging", "latest": "1.13"},
    {"slug": "loginizer", "name": "Loginizer", "latest": "1.9"},
    {"slug": "wp-google-maps", "name": "WP Google Maps", "latest": "9.0"},
    {"slug": "fluentform", "name": "Fluent Forms", "latest": "5.2"},
    {"slug": "happy-elementor-addons", "name": "Happy Addons", "latest": "3.12"},
    {"slug": "elementskit-lite", "name": "ElementsKit", "latest": "3.4"},
    {"slug": "essential-addons-for-elementor-lite", "name": "Essential Addons", "latest": "6.0"},
    {"slug": "premium-addons-for-elementor", "name": "Premium Addons", "latest": "4.10"},
    {"slug": "ultimate-elementor", "name": "Ultimate Addons", "latest": "1.36"},
    {"slug": "envato-elements", "name": "Envato Elements", "latest": "2.0"},
    {"slug": "astra-sites", "name": "Starter Templates", "latest": "4.4"},
    {"slug": "elementor-header-footer-builder", "name": "Header Footer Elementor", "latest": "1.6"},
]


def scan_wordpress(url: str, timeout: int = 8, max_workers: int = 8) -> dict:
    """
    Scan WordPress site untuk plugin/theme enumeration dan version detection.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if not url.endswith("/"):
        url += "/"
    
    findings = []
    passed = 0
    failed = 0
    plugins_found = []
    themes_found = []
    
    # Verifikasi target WordPress
    if not _is_wordpress(url, timeout):
        findings.append({
            "check": "WordPress Detection",
            "status": "PASS",
            "severity": "INFO",
            "detail": "Target bukan WordPress — skip WordPress scan",
            "recommendation": "-"
        })
        return {
            "target": url,
            "is_wordpress": False,
            "findings": findings,
            "plugins_found": [],
            "themes_found": [],
            "passed": 1, "failed": 0, "total_checks": 1
        }
    
    # === SCAN 1: Enumerate Plugins ===
    def check_plugin(plugin: dict) -> dict:
        result = _enumerate_plugin(url, plugin, timeout)
        return result
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_plugin, p): p for p in POPULAR_PLUGINS}
        for future in as_completed(futures):
            result = future.result()
            if result and result["found"]:
                plugins_found.append(result)
    
    # === SCAN 2: Enumerate Active Theme ===
    active_theme = _detect_active_theme(url, timeout)
    if active_theme:
        themes_found.append(active_theme)
    
    # === Generate Findings ===
    if plugins_found:
        findings.append({
            "check": "WordPress Plugin Enumeration",
            "status": "PASS",
            "severity": "INFO",
            "detail": f"{len(plugins_found)} plugin terdeteksi: " + 
                      ", ".join([p["name"] + (f" v{p['version']}" if p["version"] else "")
                                for p in plugins_found[:5]]) +
                      (f" + {len(plugins_found)-5} lainnya" if len(plugins_found) > 5 else ""),
            "recommendation": "-"
        })
        passed += 1
        
        # Cek plugin outdated
        for plugin in plugins_found:
            if plugin["version"] and plugin["latest"]:
                if _is_outdated(plugin["version"], plugin["latest"]):
                    failed += 1
                    findings.append({
                        "check": f"Plugin Outdated: {plugin['name']}",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "detail": f"{plugin['name']} v{plugin['version']} terdeteksi outdated "
                                 f"(latest: v{plugin['latest']}). Versi lama sering punya kerentanan known.",
                        "recommendation": f"Update plugin {plugin['name']} ke versi terbaru via WP Admin Dashboard"
                    })
            
            # Cek readme.txt yang exposed
            if plugin.get("readme_exposed"):
                failed += 1
                findings.append({
                    "check": f"Info Disclosure: {plugin['name']} readme.txt",
                    "status": "FAIL",
                    "severity": "LOW",
                    "detail": f"File readme.txt plugin {plugin['name']} accessible — "
                             f"membocorkan versi plugin",
                    "recommendation": f"Blokir akses ke /wp-content/plugins/{plugin['slug']}/readme.txt"
                })
    else:
        passed += 1
        findings.append({
            "check": "WordPress Plugin Enumeration",
            "status": "PASS",
            "severity": "INFO",
            "detail": f"Tidak ada plugin populer terdeteksi dari {len(POPULAR_PLUGINS)} plugin yang di-scan",
            "recommendation": "-"
        })
    
    # Theme findings
    if active_theme:
        findings.append({
            "check": "WordPress Active Theme",
            "status": "PASS",
            "severity": "INFO",
            "detail": f"Active theme: {active_theme['name']}" +
                     (f" v{active_theme['version']}" if active_theme.get("version") else ""),
            "recommendation": "-"
        })
        passed += 1
        
        if active_theme.get("style_exposed"):
            failed += 1
            findings.append({
                "check": f"Info Disclosure: Theme style.css",
                "status": "FAIL",
                "severity": "LOW",
                "detail": f"File style.css theme accessible — membocorkan nama dan versi theme",
                "recommendation": f"Blokir akses langsung ke style.css theme"
            })
    
    # === SCAN 3: WordPress security checks tambahan ===
    _check_wp_security(url, findings, timeout)
    
    # Recount
    passed = sum(1 for f in findings if f["status"] == "PASS")
    failed = sum(1 for f in findings if f["status"] == "FAIL")
    
    return {
        "target": url,
        "is_wordpress": True,
        "findings": findings,
        "plugins_found": plugins_found,
        "themes_found": themes_found,
        "plugins_count": len(plugins_found),
        "passed": passed,
        "failed": failed,
        "total_checks": passed + failed
    }


def _is_wordpress(url: str, timeout: int) -> bool:
    """Cek apakah target benar-benar WordPress.

    FIX FALSE POSITIVE: versi lama menganggap target = WordPress hanya karena
    /wp-login.php membalas 200/301/302/403. SPA / server catch-all membalas 200
    untuk SEMUA path → terdeteksi WordPress secara keliru, lalu seluruh modul WP
    (XML-RPC, readme, dll.) ikut memunculkan false positive.

    Sekarang: butuh fingerprint WordPress NYATA, dan indikator berbasis-path
    hanya dipercaya bila server BUKAN soft-200 (catch-all).
    """
    # 1) Deteksi server soft-200 (membalas 200 untuk path acak yang pasti tak ada)
    soft_200 = False
    try:
        token = "spencerweb-wp-canary-" + "".join(random.choices(string.ascii_lowercase, k=12))
        rc = requests.get(urljoin(url, "/" + token), timeout=timeout, headers=HEADERS,
                          allow_redirects=True)
        if rc.status_code == 200:
            soft_200 = True
    except Exception:
        pass

    # 2) Fingerprint kuat: body homepage mengandung penanda WordPress nyata
    try:
        r = requests.get(url, timeout=timeout, headers=HEADERS, allow_redirects=True)
        body = r.text.lower()
        if ("wp-content" in body or "wp-includes" in body
                or 'content="wordpress' in body or "/wp-json/" in body):
            return True
    except Exception:
        pass

    # 3) Fingerprint kuat: /wp-json/ mengembalikan JSON khas WordPress
    try:
        r = requests.get(urljoin(url, "/wp-json/"), timeout=timeout, headers=HEADERS,
                         allow_redirects=True)
        if r.status_code == 200 and ("wp/v2" in r.text.lower() or '"namespace"' in r.text.lower()):
            return True
    except Exception:
        pass

    # 4) Fallback berbasis-path — HANYA valid bila server BUKAN soft-200
    if not soft_200:
        try:
            r = requests.get(urljoin(url, "/wp-login.php"), timeout=timeout, headers=HEADERS,
                             allow_redirects=False)
            if r.status_code == 200 and any(k in r.text.lower()
                                            for k in ("user_login", "wp-submit", "loginform")):
                return True
            loc = r.headers.get("location", "").lower()
            if r.status_code in (301, 302) and "wp-login" in loc:
                return True
        except Exception:
            pass

    return False


def _enumerate_plugin(base_url: str, plugin: dict, timeout: int) -> dict:
    """Enumerasi keberadaan dan versi satu plugin."""
    plugin_url = urljoin(base_url, f"/wp-content/plugins/{plugin['slug']}/")
    readme_url = urljoin(base_url, f"/wp-content/plugins/{plugin['slug']}/readme.txt")
    
    found = False
    version = None
    readme_exposed = False
    
    # Test 1: Akses plugin directory
    try:
        r = requests.head(plugin_url, timeout=timeout, headers=HEADERS, allow_redirects=False)
        if r.status_code in (200, 301, 302, 403):
            found = True
    except Exception:
        pass
    
    # Test 2: Coba ambil readme.txt untuk version
    if found:
        try:
            r = requests.get(readme_url, timeout=timeout, headers=HEADERS, allow_redirects=True)
            if r.status_code == 200 and "stable tag" in r.text.lower():
                readme_exposed = True
                # Parse version dari readme.txt
                match = re.search(r"Stable tag:\s*([\d.]+)", r.text, re.IGNORECASE)
                if match:
                    version = match.group(1)
        except Exception:
            pass
    
    if found:
        return {
            "found": True,
            "slug": plugin["slug"],
            "name": plugin["name"],
            "version": version,
            "latest": plugin["latest"],
            "readme_exposed": readme_exposed
        }
    return {"found": False}


def _detect_active_theme(url: str, timeout: int) -> dict:
    """Deteksi active theme dari source HTML."""
    try:
        r = requests.get(url, timeout=timeout, headers=HEADERS, allow_redirects=True)
        if r.status_code != 200:
            return None
        
        # Cari path theme di HTML: /wp-content/themes/THEME_NAME/
        match = re.search(r'/wp-content/themes/([^/"\s\']+)/', r.text)
        if not match:
            return None
        
        theme_slug = match.group(1)
        
        # Coba ambil style.css untuk parse version
        style_url = urljoin(url, f"/wp-content/themes/{theme_slug}/style.css")
        version = None
        style_exposed = False
        
        try:
            sr = requests.get(style_url, timeout=timeout, headers=HEADERS, allow_redirects=True)
            if sr.status_code == 200:
                style_exposed = True
                v_match = re.search(r"Version:\s*([\d.]+)", sr.text)
                if v_match:
                    version = v_match.group(1)
        except Exception:
            pass
        
        return {
            "slug": theme_slug,
            "name": theme_slug.replace("-", " ").title(),
            "version": version,
            "style_exposed": style_exposed
        }
    except Exception:
        return None


def _check_wp_security(url: str, findings: list, timeout: int):
    """Pengecekan keamanan WordPress tambahan."""
    
    # Check 1: wp-login.php accessible (umumnya YES, tapi worth noting)
    try:
        r = requests.head(urljoin(url, "/wp-login.php"), timeout=timeout, 
                         headers=HEADERS, allow_redirects=False)
        if r.status_code == 200:
            findings.append({
                "check": "WP Admin Login Page",
                "status": "PASS",
                "severity": "LOW",
                "detail": "wp-login.php accessible — target umum brute force attack",
                "recommendation": "Pertimbangkan: rename URL login, batasi via IP, "
                                 "atau pakai plugin seperti Loginizer / Wordfence"
            })
    except Exception:
        pass
    
    # Check 2: XML-RPC
    try:
        r = requests.head(urljoin(url, "/xmlrpc.php"), timeout=timeout,
                         headers=HEADERS, allow_redirects=False)
        if r.status_code in (200, 405):
            findings.append({
                "check": "XML-RPC Endpoint",
                "status": "FAIL",
                "severity": "MEDIUM",
                "detail": "xmlrpc.php aktif — bisa disalahgunakan untuk brute force "
                         "dan DDoS amplification",
                "recommendation": "Disable XML-RPC jika tidak digunakan, atau batasi aksesnya"
            })
    except Exception:
        pass
    
    # Check 3: User enumeration via author
    try:
        r = requests.get(urljoin(url, "/?author=1"), timeout=timeout,
                        headers=HEADERS, allow_redirects=True)
        if r.status_code == 200 and "/author/" in r.url:
            # Extract username dari URL redirect
            match = re.search(r"/author/([^/]+)/?", r.url)
            if match:
                username = match.group(1)
                findings.append({
                    "check": "User Enumeration",
                    "status": "FAIL",
                    "severity": "MEDIUM",
                    "detail": f"Username admin teridentifikasi: '{username}' via /?author=1",
                    "recommendation": "Disable user enumeration via rewrite rules atau "
                                     "plugin keamanan. Hindari menggunakan username 'admin'."
                })
    except Exception:
        pass
    
    # Check 4: REST API users endpoint
    try:
        r = requests.get(urljoin(url, "/wp-json/wp/v2/users"), timeout=timeout,
                        headers=HEADERS, allow_redirects=True)
        if r.status_code == 200 and "[{" in r.text:
            findings.append({
                "check": "REST API User Enumeration",
                "status": "FAIL",
                "severity": "MEDIUM",
                "detail": "REST API /wp-json/wp/v2/users mengekspos daftar user — "
                         "attacker bisa enumerate username dengan mudah",
                "recommendation": "Disable atau batasi akses ke REST API users endpoint. "
                                 "Pakai plugin seperti Disable REST API atau filter di functions.php"
            })
    except Exception:
        pass


def _is_outdated(current: str, latest: str) -> bool:
    """Bandingkan version string secara sederhana."""
    try:
        curr_parts = [int(x) for x in current.split(".")[:3]]
        lat_parts = [int(x) for x in latest.split(".")[:3]]
        
        # Pad ke 3 elemen
        while len(curr_parts) < 3:
            curr_parts.append(0)
        while len(lat_parts) < 3:
            lat_parts.append(0)
        
        # Compare
        for c, l in zip(curr_parts, lat_parts):
            if c < l:
                # Hanya flag outdated jika beda di major/minor (bukan patch)
                return True
            if c > l:
                return False
        return False
    except (ValueError, IndexError):
        return False
