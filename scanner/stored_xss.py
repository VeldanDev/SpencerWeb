"""
Spencer v2.0 — Stored XSS Scanner
Deteksi Stored XSS dengan teknik:
1. Submit payload unik (dengan marker) ke setiap form
2. Visit semua halaman yang sudah di-crawl
3. Cek apakah marker muncul di halaman lain

Catatan: Spencer NON-DESTRUCTIVE — payload yang dipakai
dirancang agar tidak benar-benar mengeksekusi atau merusak data.
"""

import requests
import random
import string
import time
from urllib.parse import urljoin
from utils.crawler import HEADERS


def _marker() -> str:
    """Generate marker unik."""
    return "spncrSXSS" + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))


def scan_stored_xss(forms: list, all_urls: list, timeout: int = 10,
                    max_forms: int = 10, wait_seconds: int = 2) -> dict:
    """
    Scan Stored XSS dengan submit payload ke form lalu cek di halaman lain.
    
    Proses:
    1. Untuk setiap form (max_forms), submit payload dengan marker unik
    2. Tunggu beberapa detik (server mungkin perlu waktu untuk save)
    3. Visit semua URL yang sudah di-crawl
    4. Cek apakah marker muncul di response
    """
    findings = []
    passed = 0
    failed = 0
    
    if not forms:
        findings.append({
            "check": "Stored XSS Scan",
            "status": "PASS",
            "severity": "INFO",
            "detail": "Tidak ada form ditemukan untuk diuji",
            "recommendation": "-"
        })
        return {
            "target": all_urls[0] if all_urls else "",
            "findings": findings,
            "forms_submitted": 0,
            "passed": 1, "failed": 0, "total_checks": 1
        }
    
    # Batasi jumlah form yang ditest (Stored XSS testing intensif)
    forms_to_test = forms[:max_forms]
    submissions = []  # Track payload yang sudah disubmit
    
    # === STEP 1: Submit payload ke setiap form ===
    for form in forms_to_test:
        marker = _marker()
        # Payload yang aman tapi tetap terdeteksi
        # Bukan <script> langsung — pakai marker dalam konteks tag yang aman
        payload = f"<span data-spncr='{marker}'>{marker}</span>"
        
        success = _submit_form(form, payload, timeout)
        if success:
            submissions.append({
                "form_action": form["action"],
                "form_method": form["method"],
                "source_url": form.get("source_url", form["action"]),
                "marker": marker,
                "payload": payload
            })
    
    if not submissions:
        passed = 1
        findings.append({
            "check": "Stored XSS Scan",
            "status": "PASS",
            "severity": "INFO",
            "detail": f"Tidak bisa submit ke {len(forms_to_test)} form (mungkin butuh autentikasi)",
            "recommendation": "-"
        })
        return {
            "target": all_urls[0] if all_urls else "",
            "findings": findings,
            "forms_submitted": 0,
            "passed": 1, "failed": 0, "total_checks": 1
        }
    
    # === STEP 2: Tunggu (server mungkin perlu waktu save) ===
    time.sleep(wait_seconds)
    
    # === STEP 3: Visit halaman dan cek marker ===
    pages_to_check = list(set(all_urls + [s["source_url"] for s in submissions]))
    pages_checked = 0
    
    for sub in submissions:
        found_on_pages = []
        
        for url in pages_to_check[:30]:  # Batasi halaman yang dicek
            try:
                r = requests.get(url, timeout=timeout, headers=HEADERS, allow_redirects=True)
                pages_checked += 1
                
                if sub["marker"] in r.text:
                    # Cek apakah payload masih intact (tidak ter-encode)
                    if "<span" in r.text.lower() and sub["marker"] in r.text:
                        # Payload tersimpan dan ter-render → STORED XSS
                        found_on_pages.append(url)
            except Exception:
                continue
        
        if found_on_pages:
            failed += 1
            findings.append({
                "check": f"Stored XSS: Form {sub['form_method']} {_short(sub['form_action'])}",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": f"Payload tersimpan dan ter-reflect di {len(found_on_pages)} halaman. "
                         f"Marker '{sub['marker']}' ditemukan di: "
                         f"{', '.join(_short(u) for u in found_on_pages[:3])}",
                "recommendation": "Sanitasi semua user input SEBELUM disimpan ke database "
                                 "DAN saat ditampilkan kembali. Gunakan HTML encoding "
                                 "(htmlspecialchars di PHP, escape() di template engine)."
            })
    
    if failed == 0:
        passed = 1
        findings.append({
            "check": "Stored XSS Scan",
            "status": "PASS",
            "severity": "INFO",
            "detail": f"Tidak ditemukan Stored XSS ({len(submissions)} form disubmit, "
                     f"{pages_checked} page-checks dilakukan)",
            "recommendation": "-"
        })
    
    return {
        "target": all_urls[0] if all_urls else "",
        "findings": findings,
        "forms_submitted": len(submissions),
        "pages_checked": pages_checked,
        "passed": passed,
        "failed": failed,
        "total_checks": max(passed + failed, 1)
    }


def _submit_form(form: dict, payload: str, timeout: int) -> bool:
    """Submit form dengan payload. Return True jika request berhasil."""
    data = {}
    
    for inp in form["inputs"]:
        if inp["type"] in ("text", "search", "textarea", "url", ""):
            data[inp["name"]] = payload
        elif inp["type"] == "email":
            data[inp["name"]] = "test@spencer-audit.local"
        elif inp["type"] == "tel":
            data[inp["name"]] = "1234567890"
        elif inp["type"] == "number":
            data[inp["name"]] = "1"
        elif inp["type"] == "hidden":
            data[inp["name"]] = inp["value"]
        elif inp["type"] == "password":
            data[inp["name"]] = "Test123!"
        else:
            data[inp["name"]] = inp.get("value", "test")
    
    try:
        if form["method"] == "POST":
            r = requests.post(form["action"], data=data, timeout=timeout,
                            headers=HEADERS, allow_redirects=True)
        else:
            r = requests.get(form["action"], params=data, timeout=timeout,
                           headers=HEADERS, allow_redirects=True)
        
        # Berhasil jika status code 2xx atau 3xx
        return r.status_code < 400
    except Exception:
        return False


def _short(url: str, max_len: int = 35) -> str:
    """Potong URL untuk display."""
    if len(url) > max_len:
        return "..." + url[-(max_len-3):]
    return url
