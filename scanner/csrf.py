"""
Spencer — Modul CSRF (Cross-Site Request Forgery) Checker
Mengecek apakah form pada halaman target memiliki proteksi CSRF yang memadai.

Checks:
1. Keberadaan CSRF token pada setiap form
2. Nama token field yang dikenali
3. Apakah form POST punya proteksi vs form GET
"""

from utils.crawler import fetch_page, extract_forms


# Nama field yang umum digunakan sebagai CSRF token
CSRF_TOKEN_NAMES = [
    "csrf_token", "csrftoken", "csrf", "_csrf",
    "_token", "token", "authenticity_token",
    "__requestverificationtoken", "antiforgerytoken",
    "csrfmiddlewaretoken",  # Django
    "_csrftoken",
    "nonce", "wp_nonce", "_wpnonce",  # WordPress
    "form_token",  # Drupal
    "verification_token",
    "xsrf_token", "_xsrf",
]

# Token patterns di meta tags
CSRF_META_NAMES = [
    "csrf-token", "csrf-param", "xsrf-token",
    "_csrf_token", "csrf_token",
]


def check_csrf(url: str, timeout: int = 10) -> dict:
    """
    Cek proteksi CSRF pada semua form di halaman target.
    
    Returns:
        dict dengan findings list
    """
    findings = []
    passed = 0
    failed = 0

    resp, soup = fetch_page(url, timeout)
    if not resp or not soup:
        return {
            "target": url,
            "error": "Tidak dapat mengakses halaman target",
            "findings": [], "passed": 0, "failed": 0, "total_checks": 0
        }

    forms = extract_forms(url, soup)
    
    # === CHECK 1: Meta tag CSRF ===
    has_meta_csrf = False
    for meta_name in CSRF_META_NAMES:
        meta = soup.find("meta", attrs={"name": meta_name})
        if meta and meta.get("content"):
            has_meta_csrf = True
            passed += 1
            findings.append({
                "check": f"CSRF Meta Tag: {meta_name}",
                "status": "PASS",
                "severity": "INFO",
                "detail": f"CSRF token ditemukan di meta tag '{meta_name}'",
                "recommendation": "-"
            })
            break

    if not forms:
        findings.append({
            "check": "CSRF Form Analysis",
            "status": "PASS",
            "severity": "INFO",
            "detail": "Tidak ada form ditemukan di halaman ini",
            "recommendation": "-"
        })
        return {
            "target": url,
            "findings": findings,
            "forms_analyzed": 0,
            "passed": passed + 1,
            "failed": 0,
            "total_checks": passed + 1
        }

    # === CHECK 2: Per-form CSRF analysis ===
    for form in forms:
        form_action = form["action"]
        form_method = form["method"]
        
        # Cari CSRF token di form inputs
        has_csrf_token = False
        token_field = None
        
        for inp in form["inputs"]:
            name_lower = inp["name"].lower()
            # Cek apakah nama input cocok dengan CSRF token patterns
            if name_lower in CSRF_TOKEN_NAMES or any(t in name_lower for t in ["csrf", "token", "nonce", "xsrf"]):
                if inp["type"] == "hidden" and inp.get("value"):
                    has_csrf_token = True
                    token_field = inp["name"]
                    break

        if form_method == "POST":
            # POST form HARUS punya CSRF token
            if has_csrf_token:
                passed += 1
                findings.append({
                    "check": f"CSRF: POST form → {_short_action(form_action)}",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": f"CSRF token ditemukan: '{token_field}'",
                    "recommendation": "-"
                })
            elif has_meta_csrf:
                passed += 1
                findings.append({
                    "check": f"CSRF: POST form → {_short_action(form_action)}",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": "CSRF token kemungkinan diambil dari meta tag via JavaScript",
                    "recommendation": "-"
                })
            else:
                failed += 1
                findings.append({
                    "check": f"CSRF: POST form → {_short_action(form_action)}",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "detail": "Form POST tanpa CSRF token — rentan terhadap CSRF attack",
                    "recommendation": "Tambahkan CSRF token (hidden input) pada setiap form POST. "
                                     "Gunakan framework yang mendukung CSRF protection built-in "
                                     "(Django, Laravel, Express csrf middleware)."
                })
        else:
            # GET form — less critical tapi tetap dicatat
            if not has_csrf_token and not has_meta_csrf:
                # GET form tanpa CSRF kurang kritis kecuali melakukan state change
                findings.append({
                    "check": f"CSRF: GET form → {_short_action(form_action)}",
                    "status": "PASS",
                    "severity": "LOW",
                    "detail": "Form GET tanpa CSRF token (umumnya acceptable untuk form pencarian)",
                    "recommendation": "Pastikan form GET tidak melakukan perubahan data/state"
                })
                passed += 1
            else:
                passed += 1
                findings.append({
                    "check": f"CSRF: GET form → {_short_action(form_action)}",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": "Form GET dengan CSRF protection",
                    "recommendation": "-"
                })

    return {
        "target": url,
        "findings": findings,
        "forms_analyzed": len(forms),
        "passed": passed,
        "failed": failed,
        "total_checks": passed + failed
    }


def _short_action(action: str, max_len: int = 30) -> str:
    from urllib.parse import urlparse
    path = urlparse(action).path or "/"
    return ("..." + path[-(max_len-3):]) if len(path) > max_len else path
