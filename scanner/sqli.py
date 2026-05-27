"""
Spencer — Modul SQL Injection Scanner
Mendeteksi kerentanan SQL Injection pada form input dan URL parameters.
Menggunakan teknik error-based detection — mengirim payload dan menganalisis
response untuk indikator error SQL dari berbagai DBMS.

Semua payload dan logika deteksi ditulis original.
Scanner ini NON-DESTRUCTIVE: tidak melakukan DROP, DELETE, atau modifikasi data.
"""

import requests
from urllib.parse import urlencode, urljoin
from utils.crawler import fetch_page, extract_forms, extract_links_with_params, get_url_params, HEADERS


# Payload SQLi untuk error-based detection
# Tujuan: memicu SQL syntax error, BUKAN mengeksploitasi
SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "1' ORDER BY 1 --",
    "1 UNION SELECT NULL --",
    "'; SELECT 1 --",
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND '1'='1",
    "1; WAITFOR DELAY '0:0:0' --",
]

# Pattern error SQL dari berbagai DBMS
SQL_ERROR_PATTERNS = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql_",
    "unclosed quotation mark",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    "mysqli_",
    
    # PostgreSQL
    "pg_query",
    "pg_exec",
    "unterminated quoted string",
    "syntax error at or near",
    "invalid input syntax for",
    "postgresql",
    
    # SQLite
    "sqlite3.operationalerror",
    "sqlite_error",
    "unrecognized token",
    "near \"",
    "sqlite3::exception",
    
    # Microsoft SQL Server
    "microsoft sql server",
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
    "mssql_query",
    "odbc sql server driver",
    "sqlsrv_",
    
    # Oracle
    "ora-00933",
    "ora-00921",
    "ora-01756",
    "oracle error",
    "quoted string not properly terminated",
    
    # Generic
    "sql syntax",
    "sql error",
    "sqlexception",
    "sql command not properly ended",
    "invalid query",
    "database error",
    "db error",
    "syntax error in query",
]


def scan_sqli(url: str, timeout: int = 10) -> dict:
    """
    Scan target URL untuk kerentanan SQL Injection.
    
    Proses:
    1. Fetch halaman target
    2. Ekstrak semua form dan URL parameters
    3. Untuk setiap injection point, kirim payload SQLi
    4. Analisis response untuk SQL error patterns
    5. Laporkan temuan
    
    Returns:
        dict dengan findings list
    """
    findings = []
    passed = 0
    failed = 0
    injection_points_tested = 0
    
    # Fetch halaman
    resp, soup = fetch_page(url, timeout)
    if not resp or not soup:
        return {
            "target": url,
            "error": "Tidak dapat mengakses halaman target",
            "findings": [],
            "passed": 0, "failed": 0, "total_checks": 0
        }

    # Kumpulkan injection points
    forms = extract_forms(url, soup)
    url_params = get_url_params(url)
    param_links = extract_links_with_params(url, soup)

    # === TEST 1: Form-based injection ===
    for form in forms:
        for payload in SQLI_PAYLOADS[:6]:  # Batasi payload per form
            result = _test_form_sqli(form, payload, timeout)
            injection_points_tested += 1
            
            if result:
                failed += 1
                findings.append({
                    "check": f"SQLi: Form ({form['method']} {_short_url(form['action'])})",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "detail": f"SQL Injection terdeteksi! Payload: {payload} → Error: {result}",
                    "recommendation": "Gunakan parameterized queries / prepared statements. "
                                     "JANGAN pernah concatenate user input langsung ke SQL query."
                })
                break  # Satu temuan per form cukup
    
    # === TEST 2: URL parameter injection ===
    if url_params:
        for param_name, param_value in url_params.items():
            for payload in SQLI_PAYLOADS[:6]:
                result = _test_param_sqli(url, param_name, payload, timeout)
                injection_points_tested += 1
                
                if result:
                    failed += 1
                    findings.append({
                        "check": f"SQLi: URL param '{param_name}'",
                        "status": "FAIL",
                        "severity": "CRITICAL",
                        "detail": f"SQL Injection terdeteksi pada parameter '{param_name}'! "
                                  f"Payload: {payload} → Error: {result}",
                        "recommendation": "Gunakan parameterized queries / prepared statements. "
                                         "Validasi dan sanitasi semua input dari URL parameters."
                    })
                    break

    # === TEST 3: Link parameter injection ===
    for link in param_links[:10]:  # Batasi jumlah link yang ditest
        for param_name in link["params"]:
            for payload in SQLI_PAYLOADS[:4]:
                result = _test_param_sqli(
                    link["url"] + "?" + urlencode(link["params"]),
                    param_name, payload, timeout
                )
                injection_points_tested += 1
                
                if result:
                    failed += 1
                    findings.append({
                        "check": f"SQLi: {_short_url(link['url'])} param '{param_name}'",
                        "status": "FAIL",
                        "severity": "CRITICAL",
                        "detail": f"SQL Injection terdeteksi! Payload: {payload} → Error: {result}",
                        "recommendation": "Gunakan parameterized queries / prepared statements."
                    })
                    break

    # Jika tidak ada temuan, catat sebagai PASS
    if failed == 0:
        passed = 1
        findings.append({
            "check": "SQL Injection Scan",
            "status": "PASS",
            "severity": "INFO",
            "detail": f"Tidak ditemukan kerentanan SQLi ({injection_points_tested} injection points tested)",
            "recommendation": "-"
        })

    return {
        "target": url,
        "findings": findings,
        "injection_points_tested": injection_points_tested,
        "forms_found": len(forms),
        "url_params_found": len(url_params),
        "links_with_params": len(param_links),
        "passed": passed,
        "failed": failed,
        "total_checks": max(passed + failed, 1)
    }


def _test_form_sqli(form: dict, payload: str, timeout: int) -> str:
    """
    Test satu form dengan satu payload SQLi.
    Returns: error string yang terdeteksi, atau None jika aman.
    """
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
        
        return _check_sql_error(resp.text)
    except Exception:
        return None


def _test_param_sqli(base_url: str, param_name: str, payload: str, timeout: int) -> str:
    """
    Test satu URL parameter dengan payload SQLi.
    Returns: error string yang terdeteksi, atau None jika aman.
    """
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    
    # Inject payload ke parameter target
    params[param_name] = [payload]
    
    # Rebuild URL
    flat = {k: v[0] for k, v in params.items()}
    new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                          parsed.params, urlencode(flat), parsed.fragment))
    
    try:
        resp = requests.get(new_url, timeout=timeout, headers=HEADERS, allow_redirects=True)
        return _check_sql_error(resp.text)
    except Exception:
        return None


def _check_sql_error(response_text: str) -> str:
    """
    Periksa apakah response mengandung SQL error pattern.
    Returns: matched pattern string, atau None.
    """
    lower_text = response_text.lower()
    for pattern in SQL_ERROR_PATTERNS:
        if pattern in lower_text:
            return pattern
    return None


def _short_url(url: str, max_len: int = 35) -> str:
    """Potong URL untuk display."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    path = parsed.path
    if len(path) > max_len:
        path = "..." + path[-(max_len-3):]
    return path
