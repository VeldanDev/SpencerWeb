"""
Spencer — Modul CMS Version Detection
Mendeteksi CMS (Content Management System) yang digunakan target,
versinya, dan apakah versi tersebut sudah outdated (potensi kerentanan).

Deteksi menggunakan fingerprinting: meta tags, specific paths, 
response patterns — TANPA menggunakan database CVE eksternal.
"""

import re
import requests
from urllib.parse import urljoin
from utils.crawler import HEADERS


# CMS fingerprints: path, meta indicators, dan version extraction
CMS_SIGNATURES = {
    "WordPress": {
        "paths": [
            "/wp-login.php",
            "/wp-admin/",
            "/wp-content/",
            "/wp-includes/",
            "/xmlrpc.php",
        ],
        "meta_generator": r"WordPress\s*([\d.]+)?",
        "version_paths": [
            {
                "path": "/feed/",
                "pattern": r"<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>"
            },
            {
                "path": "/readme.html",
                "pattern": r"Version\s*([\d.]+)"
            },
        ],
        "latest_major": "6.7",  # Approximate latest stable
    },
    "Joomla": {
        "paths": [
            "/administrator/",
            "/administrator/index.php",
            "/media/system/",
            "/templates/system/",
        ],
        "meta_generator": r"Joomla!\s*([\d.]+)?",
        "version_paths": [
            {
                "path": "/administrator/manifests/files/joomla.xml",
                "pattern": r"<version>([\d.]+)</version>"
            },
            {
                "path": "/language/en-GB/en-GB.xml",
                "pattern": r"<version>([\d.]+)</version>"
            },
        ],
        "latest_major": "5.2",
    },
    "Drupal": {
        "paths": [
            "/core/misc/drupal.js",
            "/misc/drupal.js",
            "/sites/default/",
            "/core/CHANGELOG.txt",
        ],
        "meta_generator": r"Drupal\s*([\d.]+)?",
        "version_paths": [
            {
                "path": "/CHANGELOG.txt",
                "pattern": r"Drupal\s+([\d.]+)"
            },
            {
                "path": "/core/CHANGELOG.txt",
                "pattern": r"Drupal\s+([\d.]+)"
            },
        ],
        "latest_major": "10.3",
    },
}


def detect_cms(url: str, timeout: int = 10) -> dict:
    """
    Deteksi CMS dan versinya pada target URL.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if not url.endswith("/"):
        url += "/"

    findings = []
    passed = 0
    failed = 0
    detected_cms = None
    detected_version = None

    # === STEP 1: Fetch homepage dan cek meta generator ===
    try:
        resp = requests.get(url, timeout=timeout, headers=HEADERS, allow_redirects=True)
        page_content = resp.text
    except Exception as e:
        return {
            "target": url,
            "error": f"Tidak dapat mengakses target: {e}",
            "findings": [], "passed": 0, "failed": 0, "total_checks": 0
        }

    # Cek meta generator
    for cms_name, sig in CMS_SIGNATURES.items():
        match = re.search(sig["meta_generator"], page_content, re.IGNORECASE)
        if match:
            detected_cms = cms_name
            if match.group(1):
                detected_version = match.group(1)
            break

    # === STEP 2: Path fingerprinting (jika meta generator tidak ditemukan) ===
    if not detected_cms:
        for cms_name, sig in CMS_SIGNATURES.items():
            for path in sig["paths"]:
                try:
                    check_url = urljoin(url, path)
                    r = requests.get(check_url, timeout=timeout, headers=HEADERS,
                                    allow_redirects=False)
                    if r.status_code in (200, 301, 302, 403):
                        detected_cms = cms_name
                        break
                except Exception:
                    continue
            if detected_cms:
                break

    # === STEP 3: Version detection ===
    if detected_cms and not detected_version:
        sig = CMS_SIGNATURES[detected_cms]
        for vp in sig.get("version_paths", []):
            try:
                vurl = urljoin(url, vp["path"])
                r = requests.get(vurl, timeout=timeout, headers=HEADERS, allow_redirects=True)
                if r.status_code == 200:
                    match = re.search(vp["pattern"], r.text)
                    if match:
                        detected_version = match.group(1)
                        break
            except Exception:
                continue

    # === STEP 4: Generate findings ===
    if detected_cms:
        # CMS terdeteksi
        findings.append({
            "check": "CMS Detection",
            "status": "PASS",
            "severity": "INFO",
            "detail": f"CMS terdeteksi: {detected_cms}" +
                      (f" versi {detected_version}" if detected_version else " (versi tidak terdeteksi)"),
            "recommendation": "-"
        })
        passed += 1

        # Cek apakah versi outdated
        if detected_version:
            latest = CMS_SIGNATURES[detected_cms].get("latest_major", "")
            if latest and _is_outdated(detected_version, latest):
                failed += 1
                findings.append({
                    "check": f"{detected_cms} Version Check",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "detail": f"{detected_cms} versi {detected_version} kemungkinan outdated "
                              f"(latest stable: ~{latest}.x). Versi lama sering punya kerentanan known.",
                    "recommendation": f"Update {detected_cms} ke versi terbaru. "
                                     f"Periksa changelog resmi untuk known vulnerabilities."
                })
            else:
                passed += 1
                findings.append({
                    "check": f"{detected_cms} Version Check",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": f"{detected_cms} versi {detected_version} — kemungkinan up to date",
                    "recommendation": "-"
                })

        # Cek exposed version info (information disclosure)
        _check_version_exposure(url, detected_cms, findings, timeout)
        
    else:
        passed += 1
        findings.append({
            "check": "CMS Detection",
            "status": "PASS",
            "severity": "INFO",
            "detail": "Tidak ada CMS populer terdeteksi (custom-built atau non-standard CMS)",
            "recommendation": "-"
        })

    # Recount pass/fail
    passed = sum(1 for f in findings if f["status"] == "PASS")
    failed = sum(1 for f in findings if f["status"] == "FAIL")

    return {
        "target": url,
        "cms": detected_cms,
        "version": detected_version,
        "findings": findings,
        "passed": passed,
        "failed": failed,
        "total_checks": passed + failed
    }


def _check_version_exposure(url: str, cms: str, findings: list, timeout: int):
    """Cek apakah file versi accessible (information disclosure)."""
    exposure_paths = {
        "WordPress": ["/readme.html", "/license.txt"],
        "Joomla": ["/administrator/manifests/files/joomla.xml"],
        "Drupal": ["/CHANGELOG.txt", "/core/CHANGELOG.txt"],
    }
    
    for path in exposure_paths.get(cms, []):
        try:
            r = requests.get(urljoin(url, path), timeout=timeout,
                           headers=HEADERS, allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 50:
                findings.append({
                    "check": f"Info Disclosure: {path}",
                    "status": "FAIL",
                    "severity": "LOW",
                    "detail": f"File '{path}' accessible — membocorkan informasi versi {cms}",
                    "recommendation": f"Blokir akses ke {path} via konfigurasi web server"
                })
                return
        except Exception:
            continue


def _is_outdated(current: str, latest_major: str) -> bool:
    """Bandingkan versi secara sederhana."""
    try:
        curr_parts = [int(x) for x in current.split(".")[:2]]
        latest_parts = [int(x) for x in latest_major.split(".")[:2]]
        
        if curr_parts[0] < latest_parts[0]:
            return True
        if len(curr_parts) > 1 and len(latest_parts) > 1:
            if curr_parts[0] == latest_parts[0] and curr_parts[1] < latest_parts[1]:
                return True
        return False
    except (ValueError, IndexError):
        return False
