"""
Spencer — Modul Deteksi Sensitive File Exposure
Mencari file/direktori sensitif yang tidak seharusnya bisa diakses publik.
Semua path list dan logika deteksi ditulis original.
"""

import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed


# Daftar path sensitif yang sering ketinggalan di production
# Disusun per kategori untuk kemudahan maintenance
SENSITIVE_PATHS = [
    # === Version Control ===
    {
        "path": "/.git/HEAD",
        "category": "Version Control",
        "severity": "CRITICAL",
        "description": "Git repository exposed — seluruh source code bisa di-download",
        "recommendation": "Blokir akses ke direktori .git via konfigurasi web server"
    },
    {
        "path": "/.git/config",
        "category": "Version Control",
        "severity": "CRITICAL",
        "description": "Git config exposed — bisa berisi URL remote repository & kredensial",
        "recommendation": "Blokir akses ke direktori .git via konfigurasi web server"
    },
    {
        "path": "/.svn/entries",
        "category": "Version Control",
        "severity": "CRITICAL",
        "description": "SVN repository exposed",
        "recommendation": "Blokir akses ke direktori .svn"
    },

    # === Environment & Config Files ===
    {
        "path": "/.env",
        "category": "Environment Config",
        "severity": "CRITICAL",
        "description": "File .env exposed — biasanya berisi API keys, database password, secret keys",
        "recommendation": "Pindahkan .env ke luar document root atau blokir via web server"
    },
    {
        "path": "/.env.backup",
        "category": "Environment Config",
        "severity": "CRITICAL",
        "description": "Backup file .env exposed",
        "recommendation": "Hapus file backup dari server production"
    },
    {
        "path": "/.env.local",
        "category": "Environment Config",
        "severity": "CRITICAL",
        "description": "File .env.local exposed",
        "recommendation": "Blokir akses ke file .env*"
    },

    # === Web Server Config ===
    {
        "path": "/.htaccess",
        "category": "Server Config",
        "severity": "HIGH",
        "description": "File konfigurasi Apache exposed — bisa berisi rewrite rules & auth config",
        "recommendation": "Konfigurasi web server agar tidak melayani file dot-files"
    },
    {
        "path": "/web.config",
        "category": "Server Config",
        "severity": "HIGH",
        "description": "File konfigurasi IIS exposed",
        "recommendation": "Batasi akses ke web.config"
    },
    {
        "path": "/nginx.conf",
        "category": "Server Config",
        "severity": "HIGH",
        "description": "Konfigurasi Nginx exposed",
        "recommendation": "Jangan simpan file konfigurasi di document root"
    },

    # === CMS Config ===
    {
        "path": "/wp-config.php",
        "category": "CMS Config",
        "severity": "CRITICAL",
        "description": "WordPress config — berisi kredensial database & secret keys",
        "recommendation": "Pastikan PHP diproses server, bukan di-serve sebagai plain text"
    },
    {
        "path": "/wp-config.php.bak",
        "category": "CMS Config",
        "severity": "CRITICAL",
        "description": "Backup WordPress config — bisa di-download sebagai plain text",
        "recommendation": "Hapus semua file backup dari server production"
    },
    {
        "path": "/wp-config.php~",
        "category": "CMS Config",
        "severity": "CRITICAL",
        "description": "Editor backup WordPress config",
        "recommendation": "Hapus file temporary editor dari server"
    },
    {
        "path": "/configuration.php",
        "category": "CMS Config",
        "severity": "CRITICAL",
        "description": "Joomla config exposed",
        "recommendation": "Pastikan PHP file diproses, bukan di-serve mentah"
    },

    # === Database Files ===
    {
        "path": "/dump.sql",
        "category": "Database",
        "severity": "CRITICAL",
        "description": "Database dump file — berisi seluruh data database",
        "recommendation": "Hapus file database dump dari server production"
    },
    {
        "path": "/backup.sql",
        "category": "Database",
        "severity": "CRITICAL",
        "description": "Database backup file exposed",
        "recommendation": "Simpan backup di lokasi yang tidak bisa diakses publik"
    },
    {
        "path": "/database.sql",
        "category": "Database",
        "severity": "CRITICAL",
        "description": "Database file exposed",
        "recommendation": "Hapus dari document root"
    },
    {
        "path": "/db.sqlite3",
        "category": "Database",
        "severity": "CRITICAL",
        "description": "SQLite database exposed — seluruh database bisa di-download",
        "recommendation": "Pindahkan database ke luar document root"
    },

    # === Backup & Archives ===
    {
        "path": "/backup.zip",
        "category": "Backup",
        "severity": "HIGH",
        "description": "File backup ZIP exposed",
        "recommendation": "Hapus file backup dari server production"
    },
    {
        "path": "/backup.tar.gz",
        "category": "Backup",
        "severity": "HIGH",
        "description": "File backup TAR.GZ exposed",
        "recommendation": "Hapus file backup dari server production"
    },
    {
        "path": "/site.zip",
        "category": "Backup",
        "severity": "HIGH",
        "description": "Archive website exposed",
        "recommendation": "Hapus file archive dari server production"
    },

    # === Info & Debug Pages ===
    {
        "path": "/phpinfo.php",
        "category": "Info Disclosure",
        "severity": "HIGH",
        "description": "phpinfo() exposed — membocorkan versi PHP, modul, konfigurasi server",
        "recommendation": "Hapus file phpinfo.php dari server production"
    },
    {
        "path": "/info.php",
        "category": "Info Disclosure",
        "severity": "HIGH",
        "description": "PHP info page exposed",
        "recommendation": "Hapus dari server production"
    },
    {
        "path": "/server-status",
        "category": "Info Disclosure",
        "severity": "MEDIUM",
        "description": "Apache server-status exposed — info koneksi aktif & performa",
        "recommendation": "Batasi akses ke /server-status hanya dari IP internal"
    },
    {
        "path": "/server-info",
        "category": "Info Disclosure",
        "severity": "MEDIUM",
        "description": "Apache server-info exposed",
        "recommendation": "Batasi akses hanya dari IP internal"
    },

    # === Admin Panels ===
    {
        "path": "/admin/",
        "category": "Admin Panel",
        "severity": "MEDIUM",
        "description": "Admin panel terdeteksi — perlu verifikasi apakah dilindungi autentikasi",
        "recommendation": "Pastikan admin panel dilindungi autentikasi kuat + IP allowlist"
    },
    {
        "path": "/administrator/",
        "category": "Admin Panel",
        "severity": "MEDIUM",
        "description": "Administrator panel (Joomla-style) terdeteksi",
        "recommendation": "Lindungi dengan autentikasi + ubah URL default"
    },
    {
        "path": "/wp-admin/",
        "category": "Admin Panel",
        "severity": "LOW",
        "description": "WordPress admin panel default",
        "recommendation": "Pertimbangkan mengubah URL wp-admin atau membatasi akses via IP"
    },
    {
        "path": "/phpmyadmin/",
        "category": "Admin Panel",
        "severity": "HIGH",
        "description": "phpMyAdmin terdeteksi — akses langsung ke manajemen database",
        "recommendation": "Hapus phpMyAdmin dari production atau batasi akses via IP allowlist"
    },

    # === Log Files ===
    {
        "path": "/error.log",
        "category": "Log Files",
        "severity": "MEDIUM",
        "description": "Error log exposed — bisa berisi path internal, stack trace, info sensitif",
        "recommendation": "Pindahkan log ke luar document root"
    },
    {
        "path": "/access.log",
        "category": "Log Files",
        "severity": "MEDIUM",
        "description": "Access log exposed — berisi IP pengunjung & request history",
        "recommendation": "Pindahkan log ke luar document root"
    },
    {
        "path": "/debug.log",
        "category": "Log Files",
        "severity": "MEDIUM",
        "description": "Debug log exposed",
        "recommendation": "Nonaktifkan debug mode & hapus log dari document root"
    },

    # === Package Manager ===
    {
        "path": "/package.json",
        "category": "Package Info",
        "severity": "LOW",
        "description": "Node.js package.json exposed — membocorkan dependensi & versi",
        "recommendation": "Blokir akses ke package.json via web server"
    },
    {
        "path": "/composer.json",
        "category": "Package Info",
        "severity": "LOW",
        "description": "PHP Composer config exposed — membocorkan dependensi",
        "recommendation": "Blokir akses ke composer.json"
    },

    # === API Documentation ===
    {
        "path": "/swagger.json",
        "category": "API Docs",
        "severity": "MEDIUM",
        "description": "Swagger/OpenAPI spec exposed — membocorkan seluruh API endpoint",
        "recommendation": "Lindungi dokumentasi API dengan autentikasi"
    },
    {
        "path": "/api-docs",
        "category": "API Docs",
        "severity": "MEDIUM",
        "description": "API documentation exposed",
        "recommendation": "Batasi akses ke dokumentasi API"
    },
]


def _get_soft_404_sizes(url: str, timeout: int = 8) -> set:
    """
    Canary check: request beberapa path yang OBVIOUSLY tidak ada.
    Catat ukuran response-nya. Kalau file sensitif punya ukuran sama
    dengan canary → itu soft 404, bukan file asli.
    
    v2.1: Path canary dibuat lebih natural untuk bypass Cloudflare 
    bot detection yang bisa block random-looking URLs.
    """
    canary_paths = [
        "/this-page-definitely-does-not-exist-12345",
        "/products/nonexistent-item-xyz",
        "/services/random-page-asdfgh",
        "/blog/this-post-doesnt-exist-67890",
        "/about/non-existent-section.html",
    ]
    
    soft_404_sizes = set()
    
    for path in canary_paths:
        try:
            canary_url = urljoin(url, path)
            resp = requests.get(
                canary_url,
                timeout=timeout,
                allow_redirects=False,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                }
            )
            if resp.status_code == 200 and len(resp.content) > 0:
                # Server return 200 untuk path yang tidak ada = soft 404!
                soft_404_sizes.add(len(resp.content))
        except Exception:
            pass
    
    return soft_404_sizes


def scan_sensitive_files(url: str, timeout: int = 8, max_workers: int = 10) -> dict:
    """
    Scan target URL untuk file/direktori sensitif yang ter-expose.
    
    v2.0 UPDATE: Canary check untuk deteksi soft 404.
    Server yang return HTTP 200 untuk semua path (custom error page)
    akan dideteksi dan finding-nya di-filter sebagai false positive.
    
    Menggunakan ThreadPoolExecutor untuk concurrent scanning (faster).
    Hanya mengecek response code, TIDAK men-download konten file.
    
    Args:
        url: Target base URL
        timeout: Request timeout dalam detik
        max_workers: Jumlah concurrent threads
    
    Returns:
        dict dengan findings list
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    # Pastikan URL berakhir dengan /
    if not url.endswith("/"):
        url = url + "/"

    findings = []
    exposed = 0
    protected = 0
    not_found = 0
    false_positives_filtered = 0

    # ═══ CANARY CHECK — deteksi soft 404 sebelum scan ═══
    soft_404_sizes = _get_soft_404_sizes(url, timeout)
    is_soft_404_server = len(soft_404_sizes) > 0

    def check_path(path_info: dict) -> dict:
        """Check satu path, return finding dict."""
        target_url = urljoin(url, path_info["path"])
        
        try:
            response = requests.get(
                target_url,
                timeout=timeout,
                allow_redirects=False,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                }
            )

            status = response.status_code
            content_length = len(response.content)

            if status == 200 and content_length > 0:
                
                # ═══ LAYER 1: Canary-based filtering ═══
                if is_soft_404_server and content_length in soft_404_sizes:
                    return {"result_type": "soft_404_filtered", "size": content_length}
                
                # Tolerance check: ukuran sangat dekat dengan canary (±50 bytes)
                if is_soft_404_server:
                    for canary_size in soft_404_sizes:
                        if abs(content_length - canary_size) <= 50:
                            return {"result_type": "soft_404_filtered", "size": content_length}
                
                # File exists dan bisa diakses!
                if _is_likely_real_content(response, path_info["path"]):
                    return {
                        "check": f"File: {path_info['path']}",
                        "status": "FAIL",
                        "severity": path_info["severity"],
                        "category": path_info["category"],
                        "detail": f"EXPOSED! {path_info['description']} (HTTP {status}, {content_length} bytes)",
                        "recommendation": path_info["recommendation"],
                        "result_type": "exposed",
                        "_content_length": content_length  # untuk post-scan analysis
                    }
                else:
                    return {"result_type": "not_found"}

            elif status == 403:
                return {
                    "check": f"File: {path_info['path']}",
                    "status": "PASS",
                    "severity": "INFO",
                    "category": path_info["category"],
                    "detail": f"File ada tapi akses diblokir (HTTP 403) — server melindungi dengan benar",
                    "recommendation": "-",
                    "result_type": "protected"
                }
            else:
                return {"result_type": "not_found"}

        except requests.exceptions.RequestException:
            return {"result_type": "error"}

    # Concurrent scanning
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_path = {
            executor.submit(check_path, path_info): path_info 
            for path_info in SENSITIVE_PATHS
        }

        for future in as_completed(future_to_path):
            result = future.result()
            if result["result_type"] == "exposed":
                exposed += 1
                findings.append(result)
            elif result["result_type"] == "protected":
                protected += 1
                findings.append(result)
            elif result["result_type"] == "soft_404_filtered":
                false_positives_filtered += 1
                not_found += 1
            elif result["result_type"] == "not_found":
                not_found += 1

    # ═══ LAYER 2: POST-SCAN PATTERN DETECTION ═══
    # Kalau 5+ finding punya byte size identik, pasti soft 404 (Cluster Detection)
    # Ini backup kalau canary check gagal (misal di-block Cloudflare)
    size_counter = {}
    for f in findings:
        if f.get("status") == "FAIL" and "_content_length" in f:
            size = f["_content_length"]
            size_counter[size] = size_counter.get(size, 0) + 1
    
    # Identifikasi ukuran yang muncul 5+ kali → pasti soft 404
    cluster_sizes = {size for size, count in size_counter.items() if count >= 5}
    cluster_filtered = 0
    
    if cluster_sizes:
        # Filter finding dengan ukuran "cluster"
        original_findings = findings.copy()
        findings = []
        for f in original_findings:
            if (f.get("status") == "FAIL" 
                and f.get("_content_length") in cluster_sizes):
                cluster_filtered += 1
                exposed -= 1
                false_positives_filtered += 1
                not_found += 1
            else:
                # Clean up internal field sebelum return
                f.pop("_content_length", None)
                findings.append(f)

    # Sort findings: FAIL pertama, lalu by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: (
        0 if x["status"] == "FAIL" else 1,
        severity_order.get(x["severity"], 4)
    ))

    # Notes
    soft_404_detected = is_soft_404_server or len(cluster_sizes) > 0
    soft_404_note = None
    if soft_404_detected and false_positives_filtered > 0:
        detection_method = []
        if is_soft_404_server:
            detection_method.append("canary check")
        if cluster_sizes:
            detection_method.append(f"pattern cluster (sizes: {sorted(cluster_sizes)})")
        method_str = " + ".join(detection_method)
        soft_404_note = (f"⚠ Server menggunakan custom 404 page (soft 404). "
                        f"Terdeteksi via {method_str}. "
                        f"{false_positives_filtered} false positive di-filter otomatis.")

    return {
        "target": url,
        "findings": findings,
        "exposed": exposed,
        "protected": protected,
        "not_found": not_found,
        "false_positives_filtered": false_positives_filtered,
        "soft_404_detected": soft_404_detected,
        "soft_404_note": soft_404_note,
        "soft_404_sizes": list(soft_404_sizes) + list(cluster_sizes),
        "total_paths_checked": len(SENSITIVE_PATHS),
        "passed": protected + not_found,
        "failed": exposed,
        "total_checks": exposed + protected
    }


def _is_likely_real_content(response, path: str) -> bool:
    """
    Heuristik untuk membedakan file asli vs custom 404 page.
    Banyak server me-return 200 OK untuk semua path tapi isinya halaman 404.
    """
    content = response.text.lower()
    content_length = len(response.content)

    # Jika sangat kecil (< 20 bytes), kemungkinan bukan file sensitif
    if content_length < 20:
        return False

    # Cek apakah response mengandung indikator 404
    not_found_indicators = [
        "not found", "404", "page not found", "does not exist",
        "halaman tidak ditemukan", "tidak ditemukan"
    ]
    
    for indicator in not_found_indicators:
        if indicator in content:
            # Tapi khusus untuk .git/HEAD, format-nya "ref: refs/heads/..."
            if path == "/.git/HEAD" and content.startswith("ref:"):
                return True
            # Untuk .env, cek format KEY=VALUE
            if path == "/.env" and "=" in content:
                return True
            return False

    # Untuk file tertentu, validasi format konten
    if path == "/.git/HEAD":
        return content.strip().startswith("ref:") or len(content.strip()) == 40
    
    if path in ("/.env", "/.env.local", "/.env.backup"):
        # Format .env: KEY=VALUE per line
        lines = content.strip().split("\n")
        env_like = sum(1 for line in lines if "=" in line and not line.strip().startswith("<"))
        return env_like > 0
    
    if path in ("/package.json", "/composer.json", "/swagger.json"):
        return content.strip().startswith("{")
    
    # Default: jika status 200 dan ada konten, anggap real
    return True
