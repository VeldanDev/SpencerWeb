#!/usr/bin/env python3
"""
Spencer v2.0 — Powerful Web Security Audit Tool
Metode: OWASP Top 10 + CVSS Scoring
Tugas Akhir Teknik Komputer — Politeknik Negeri Medan

NEW IN v2.0:
- Deep web crawling (multi-page discovery)
- Advanced SQLi (Error + Boolean + Time-based)
- Stored XSS detection
- Full port scan mode (top 100 / top 1000 / full 65535)
- WordPress plugin enumeration & vulnerability checks
"""

import os
import sys
import json
import time
import datetime
import urllib3
from urllib.parse import urlparse

# Suppress SSL warnings dari requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# v1 modules
from scanner.headers import audit_headers
from scanner.ssl_audit import audit_ssl
from scanner.sensitive_files import scan_sensitive_files, SENSITIVE_PATHS
from scanner.cms_detect import detect_cms
from scanner.sqli import scan_sqli
from scanner.xss import scan_xss
from scanner.csrf import check_csrf
from scanner.port_scan import scan_ports

# v2 modules
from utils.spider import deep_crawl
from scanner.sqli_advanced import scan_sqli_advanced
from scanner.stored_xss import scan_stored_xss
from scanner.port_scan_advanced import scan_ports_advanced
from scanner.wp_scanner import scan_wordpress

# v3 modules
from scanner.open_redirect import scan_open_redirect
from scanner.cors_scanner import scan_cors
from scanner.http_methods import scan_http_methods
from scanner.info_leak import scan_info_leak
from scanner.cookie_audit import scan_cookies
from scanner.clickjacking import scan_clickjacking

# v3 batch 2 modules
from scanner.dir_discovery import scan_directories
from scanner.tech_fingerprint import scan_tech_fingerprint
from scanner.security_txt import scan_security_files
from scanner.waf_detect import scan_waf

from utils.scoring import calculate_grade, grade_color, RESET_COLOR, dedup_findings

# Optional: PDF report generation (graceful if reportlab not installed)
try:
    from utils.pdf_report import generate_pdf_report
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


BANNER = """
\033[96m╔══════════════════════════════════════════════════════════╗
║                                                          ║
║  ███████╗██████╗ ███████╗███╗  ██╗ ██████╗███████╗██████╗ ║
║  ██╔════╝██╔══██╗██╔════╝████╗ ██║██╔════╝██╔════╝██╔══██╗║
║  ███████╗██████╔╝█████╗  ██╔██╗██║██║     █████╗  ██████╔╝║
║  ╚════██║██╔═══╝ ██╔══╝  ██║╚████║██║     ██╔══╝  ██╔══██╗║
║  ███████║██║     ███████╗██║ ╚███║╚██████╗███████╗██║  ██║║
║  ╚══════╝╚═╝     ╚══════╝╚═╝  ╚══╝╚═════╝╚══════╝╚═╝  ╚═╝║
║                ██╗    ██╗███████╗██████╗                  ║
║                ██║    ██║██╔════╝██╔══██╗                 ║
║                ██║ █╗ ██║█████╗  ██████╔╝                 ║
║                ██║███╗██║██╔══╝  ██╔══██╗                 ║
║                ╚███╔███╔╝███████╗██████╔╝                 ║
║                 ╚══╝╚══╝ ╚══════╝╚═════╝                  ║
║                                                          ║
║   SpencerWeb — Web Security Audit Tool v2.0              ║
║   Metode: OWASP Top 10 + CVSS Scoring                    ║
║                                                          ║
║   ⚠  Gunakan hanya pada target yang Anda miliki izinnya  ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝\033[0m
"""

SC = {"CRITICAL":"\033[95m", "HIGH":"\033[91m", "MEDIUM":"\033[93m",
      "LOW":"\033[96m", "INFO":"\033[92m"}
SO = {"CRITICAL":0, "HIGH":1, "MEDIUM":2, "LOW":3, "INFO":4}


# ─── Display helpers ─────────────────────────────────────

def hdr(num, title):
    print(f"\n\033[1m{'━'*60}\033[0m")
    print(f"  \033[1m\033[96m[MODULE {num}]\033[0m \033[1m{title}\033[0m")
    print(f"\033[1m{'━'*60}\033[0m")

def tbl(findings, limit=None):
    if not findings:
        print(f"  \033[92mTidak ada temuan.\033[0m")
        return
    show = findings[:limit] if limit else findings
    print(f"\n  {'CHECK':<42} {'STATUS':<8} {'SEVERITY'}")
    print(f"  {'─'*42} {'─'*8} {'─'*10}")
    for f in show:
        icon = "\033[92m✅\033[0m" if f["status"] == "PASS" else "\033[91m❌\033[0m"
        print(f"  {f['check'][:40]:<42} {icon} {f['status']:<5} "
              f"{SC.get(f['severity'],'')}{f['severity']}{RESET_COLOR}")
    if limit and len(findings) > limit:
        print(f"  \033[90m... +{len(findings)-limit} more (lihat full report JSON)\033[0m")

def summ(p, f, t):
    print(f"\n  Passed: \033[92m{p}\033[0m | Failed: \033[91m{f}\033[0m | Total: {t}")

def grade_display(all_f, modules_with_error):
    fails = [f for f in all_f if f.get("status") == "FAIL"]
    fails = dedup_findings(fails)  # FIX: dedup root-cause sebelum scoring
    gi = calculate_grade(fails)
    
    # FIX: jika banyak module error, jangan kasih Grade A
    if modules_with_error >= 3:
        gi["grade"] = "?"
        gi["score"] = 0
        gi["summary"] = f"Scan tidak lengkap ({modules_with_error} module error)"
    
    c = grade_color(gi["grade"]) if gi["grade"] != "?" else "\033[93m"
    print(f"\n\033[1m{'═'*60}\033[0m")
    print(f"  \033[1m  SPENCER SECURITY GRADE:  {c}\033[1m{gi['grade']}\033[0m  "
          f"\033[1m(Score: {gi['score']}/100)\033[0m")
    print(f"  Temuan: {gi['summary']}")
    print(f"\033[1m{'═'*60}\033[0m")
    return gi

def recs(all_f):
    fails = [f for f in all_f if f.get("status") == "FAIL"]
    fails = dedup_findings(fails)  # FIX: rekomendasi ikut deduped, konsisten dgn grade
    if not fails:
        print(f"\n  \033[92m✅ Semua pengecekan lolos!\033[0m\n")
        return
    print(f"\n\033[1m  📋 REKOMENDASI PERBAIKAN ({len(fails)} temuan)\033[0m\n")
    fails.sort(key=lambda x: SO.get(x.get("severity", "INFO"), 4))
    for i, f in enumerate(fails, 1):
        print(f"  {i:>2}. [{SC.get(f['severity'],'')}{f['severity']}{RESET_COLOR}] {f['check']}")
        if f.get("detail"):
            print(f"      {f['detail'][:110]}")
        print(f"      → {f['recommendation']}")
        print()

def save(target, modules, gi, all_f, elapsed, crawl_info):
    domain = urlparse(target).netloc.replace(".", "_").replace(":", "_")
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    rdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(rdir, exist_ok=True)
    fp = os.path.join(rdir, f"spencer_v2_{domain}_{ts}.json")
    
    report = {
        "scan_info": {
            "tool": "SpencerWeb v2.0",
            "author": "SpencerWeb Security Audit Tool",
            "method": "OWASP Top 10 + CVSS Scoring",
            "timestamp": datetime.datetime.now().isoformat(),
            "target": target,
            "scan_duration_seconds": round(elapsed, 2),
        },
        "crawl_info": crawl_info,
        "grade": gi,
        "modules": {
            name: {
                **{k: v for k, v in d.items() 
                   if k in ("findings","passed","failed","raw_headers","cert_info",
                           "tls_version","cms","version","open_ports","ip","hostname",
                           "forms_found","injection_points_tested","forms_analyzed",
                           "total_paths_checked","tests_performed","total_tests",
                           "plugins_found","themes_found","is_wordpress","mode",
                           "scan_label","ports_scanned","pages_checked","forms_submitted")},
            }
            for name, d in modules.items()
        },
        "all_findings": ([f for f in all_f if f.get("status") != "FAIL"]
                         + dedup_findings([f for f in all_f if f.get("status") == "FAIL"])),
        "all_findings_raw": all_f,
        "statistics": {
            "total_checks": sum(m.get("total_checks", 0) for m in modules.values()),
            "total_passed": sum(m.get("passed", 0) for m in modules.values()),
            "total_failed": sum(m.get("failed", 0) for m in modules.values()),
        }
    }
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)
    print(f"\n  \033[96m📄 Report: {fp}\033[0m")
    return fp

# ─── Module runner ─────────────────────────────────────

def run_module(num, title, func, target, all_findings, modules, key, **kwargs):
    """Run module dengan error handling."""
    hdr(num, title)
    try:
        result = func(target, **kwargs)
        modules[key] = result
        if "error" in result:
            print(f"  \033[91mERROR: {result['error']}\033[0m")
            return False
        tbl(result.get("findings", []), limit=15)
        summ(result.get("passed", 0), result.get("failed", 0), result.get("total_checks", 0))
        all_findings.extend(result.get("findings", []))
        return True
    except Exception as e:
        print(f"  \033[91mERROR: {e}\033[0m")
        modules[key] = {"error": str(e), "findings": [], "passed": 0, "failed": 0, "total_checks": 0}
        return False


# ─── Main ──────────────────────────────────────────────

def main():
    print(BANNER)
    
    if len(sys.argv) < 2:
        print("  Usage: python main.py <target_url> [options]\n")
        print("  Options:")
        print("    --quick              Fast scan (no crawling, top 100 ports)")
        print("    --deep               Deep scan (full crawl, advanced SQLi/XSS)  [DEFAULT]")
        print("    --port-mode <mode>   Port scan mode: common|extended|full")
        print("    --max-pages <N>      Max pages to crawl (default 30)")
        print("    --max-depth <N>      Max crawl depth (default 2)")
        print("    --skip-ports         Skip port scanning")
        print("    --skip-active        Skip active tests (SQLi/XSS/CSRF)")
        print("    --skip-crawl         Skip deep crawling (scan homepage only)")
        print("    --skip-stored-xss    Skip Stored XSS test (slow)")
        print("    --skip-time-sqli     Skip Time-based SQLi (slow)")
        print("\n  Example: python main.py https://example.com --deep")
        print("           python main.py https://example.com --quick\n")
        sys.exit(1)
    
    target = sys.argv[1]
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    # Parse options
    args = sys.argv[2:]
    quick = "--quick" in args
    skip_ports = "--skip-ports" in args
    skip_active = "--skip-active" in args
    skip_crawl = "--skip-crawl" in args or quick
    skip_stored_xss = "--skip-stored-xss" in args or quick
    skip_time_sqli = "--skip-time-sqli" in args or quick
    
    # Port mode
    port_mode = "common"
    if "--port-mode" in args:
        idx = args.index("--port-mode")
        if idx + 1 < len(args):
            port_mode = args[idx + 1]
    elif "--deep" in args:
        port_mode = "extended"
    
    # Crawl limits
    max_pages = 30
    max_depth = 2
    if "--max-pages" in args:
        idx = args.index("--max-pages")
        if idx + 1 < len(args):
            try:
                max_pages = int(args[idx + 1])
            except ValueError:
                pass
    if "--max-depth" in args:
        idx = args.index("--max-depth")
        if idx + 1 < len(args):
            try:
                max_depth = int(args[idx + 1])
            except ValueError:
                pass
    
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"  \033[1mTarget:\033[0m       {target}")
    print(f"  \033[1mWaktu:\033[0m        {now}")
    print(f"  \033[1mMode:\033[0m         {'Quick' if quick else 'Deep'}")
    print(f"  \033[1mCrawling:\033[0m     {'NO' if skip_crawl else f'YES (max {max_pages} pages, depth {max_depth})'}")
    print(f"  \033[1mPort mode:\033[0m    {port_mode}")
    print(f"\n  \033[93m🔍 Memulai Spencer v2.0 security audit...\033[0m")
    
    start = time.time()
    all_findings = []
    modules = {}
    error_count = 0
    
    # ═══════════════════════════════════════════
    # PHASE 0: Deep Crawl (collect forms & URLs)
    # ═══════════════════════════════════════════
    crawl_info = {"pages_crawled": 0, "forms_found": 0, "urls_with_params": 0}
    forms = []
    param_links = []
    all_urls = [target]
    
    if not skip_crawl:
        hdr(0, f"Deep Web Crawler (max {max_pages} pages, depth {max_depth})")
        print(f"  \033[93m  Crawling website...\033[0m")
        try:
            crawl_result = deep_crawl(target, max_depth=max_depth, max_pages=max_pages)
            crawl_info = {
                "pages_crawled": crawl_result["pages_crawled"],
                "forms_found": crawl_result["forms_found"],
                "urls_with_params": crawl_result["urls_with_params"],
                "pages_failed": crawl_result["pages_failed"],
            }
            forms = crawl_result["forms"]
            param_links = crawl_result["param_links"]
            all_urls = crawl_result["all_urls"]
            
            print(f"\n  \033[92m✅ Crawl complete\033[0m")
            print(f"  Pages crawled  : {crawl_info['pages_crawled']}")
            print(f"  Forms found    : {crawl_info['forms_found']}")
            print(f"  Param URLs     : {crawl_info['urls_with_params']}")
            print(f"  Failed pages   : {crawl_info['pages_failed']}")
        except Exception as e:
            print(f"  \033[91mCrawl error: {e}\033[0m")
    
    # ═══════════════════════════════════════════
    # MODULE 1-4: Passive Scans
    # ═══════════════════════════════════════════
    
    # Module 1: Headers — scan multiple pages (headers can differ per path)
    hdr(1, f"HTTP Security Headers Audit ({len(all_urls)} pages)")
    try:
        # Scan homepage headers (primary)
        r1 = audit_headers(target)
        modules["headers"] = r1
        
        # Also check unique headers on other crawled pages (sample max 5)
        if len(all_urls) > 1:
            extra_pages = all_urls[1:6]  # Sample up to 5 extra pages
            pages_checked = 1
            for page_url in extra_pages:
                try:
                    page_r = audit_headers(page_url)
                    pages_checked += 1
                    # Only add NEW findings not already found on homepage
                    existing_checks = {f["check"] for f in r1.get("findings", [])}
                    for f in page_r.get("findings", []):
                        if f["status"] == "FAIL" and f["check"] not in existing_checks:
                            f["check"] = f["check"] + f" ({urlparse(page_url).path})"
                            r1["findings"].append(f)
                            r1["failed"] = r1.get("failed", 0) + 1
                            r1["total_checks"] = r1.get("total_checks", 0) + 1
                except Exception:
                    pass
            print(f"  \033[90m  Checked headers on {pages_checked} pages\033[0m")
        
        tbl(r1.get("findings", []), limit=15)
        summ(r1.get("passed", 0), r1.get("failed", 0), r1.get("total_checks", 0))
        all_findings.extend(r1.get("findings", []))
    except Exception as e:
        print(f"  \033[91mERROR: {e}\033[0m")
        modules["headers"] = {"error": str(e), "findings": [], "passed": 0, "failed": 0, "total_checks": 0}
        error_count += 1
    
    if not run_module(2, "SSL/TLS Certificate Audit", audit_ssl,
                      target, all_findings, modules, "ssl"):
        error_count += 1
    
    # Module 3: Sensitive Files
    hdr(3, f"Sensitive File Exposure ({len(SENSITIVE_PATHS)} paths)")
    try:
        r3 = scan_sensitive_files(target)
        modules["sensitive_files"] = r3
        if r3.get("findings"):
            tbl(r3["findings"], limit=10)
        else:
            print(f"\n  \033[92m✅ Tidak ada file sensitif yang ter-expose.\033[0m")
        
        # Tampilkan soft 404 warning jika terdeteksi
        if r3.get("soft_404_detected") and r3.get("soft_404_note"):
            print(f"\n  \033[93m⚠  {r3['soft_404_note']}\033[0m")
        
        print(f"\n  Scanned: {r3['total_paths_checked']} | "
              f"Exposed: \033[91m{r3['exposed']}\033[0m | "
              f"Protected: \033[92m{r3['protected']}\033[0m | "
              f"Filtered (soft 404): \033[93m{r3.get('false_positives_filtered', 0)}\033[0m")
        summ(r3["passed"], r3["failed"], r3.get("total_checks", 0))
        all_findings.extend(r3.get("findings", []))
    except Exception as e:
        print(f"  \033[91mERROR: {e}\033[0m")
        modules["sensitive_files"] = {"error": str(e), "findings": [], "passed":0, "failed":0, "total_checks":0}
        error_count += 1
    
    if not run_module(4, "CMS Version Detection", detect_cms,
                      target, all_findings, modules, "cms"):
        error_count += 1
    
    # ═══════════════════════════════════════════
    # MODULE 5: WordPress Plugin Scanner (NEW v2)
    # ═══════════════════════════════════════════
    cms_info = modules.get("cms", {})
    if cms_info.get("cms") == "WordPress":
        if not run_module(5, "WordPress Plugin & Theme Scanner [v2]", scan_wordpress,
                          target, all_findings, modules, "wordpress"):
            error_count += 1
    else:
        hdr(5, "WordPress Plugin Scanner [v2]")
        print(f"  \033[93m⏭  Target bukan WordPress — module di-skip\033[0m")
    
    # ═══════════════════════════════════════════
    # MODULE 6-8: Active Tests (Advanced)
    # ═══════════════════════════════════════════
    if not skip_active:
        # Module 6: Advanced SQLi (Error + Boolean + Time-based)
        hdr(6, "Advanced SQL Injection [v2: Error+Boolean+Time]")
        try:
            r6 = scan_sqli_advanced(target, forms=forms, param_links=param_links,
                                    enable_time_based=not skip_time_sqli)
            modules["sqli_advanced"] = r6
            if r6.get("findings"):
                tbl(r6["findings"], limit=10)
            tp = r6.get("tests_performed", {})
            print(f"\n  Tests: Error={tp.get('error_based',0)} | "
                  f"Boolean={tp.get('boolean_based',0)} | Time={tp.get('time_based',0)}")
            summ(r6.get("passed",0), r6.get("failed",0), r6.get("total_checks",0))
            all_findings.extend(r6.get("findings", []))
        except Exception as e:
            print(f"  \033[91mERROR: {e}\033[0m")
            modules["sqli_advanced"] = {"error": str(e), "findings":[], "passed":0, "failed":0, "total_checks":0}
            error_count += 1
        
        # Module 7: Reflected XSS — scan ALL crawled pages
        hdr(7, f"Reflected XSS Scanner ({len(all_urls)} pages)")
        try:
            xss_findings = []
            xss_passed = 0
            xss_failed = 0
            xss_points = 0
            pages_with_xss = set()
            
            # Scan setiap URL yang di-crawl (max 20 pages)
            for page_url in all_urls[:20]:
                r7 = scan_xss(page_url)
                if "error" in r7:
                    continue
                xss_points += r7.get("injection_points_tested", 0)
                
                for f in r7.get("findings", []):
                    if f["status"] == "FAIL":
                        # Tambahkan path info ke check name
                        path = urlparse(page_url).path or "/"
                        if path not in pages_with_xss:
                            f["check"] = f["check"] + f" [{path}]"
                            xss_findings.append(f)
                            xss_failed += 1
                            pages_with_xss.add(path)
            
            if xss_failed == 0:
                xss_passed = 1
                xss_findings.append({
                    "check": "Reflected XSS Scan",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": f"Tidak ditemukan Reflected XSS di {len(all_urls[:20])} halaman "
                             f"({xss_points} injection points tested)",
                    "recommendation": "-"
                })
            
            modules["xss"] = {
                "findings": xss_findings,
                "passed": xss_passed,
                "failed": xss_failed,
                "total_checks": max(xss_passed + xss_failed, 1),
                "pages_scanned": len(all_urls[:20]),
                "injection_points_tested": xss_points
            }
            tbl(xss_findings, limit=10)
            print(f"\n  Pages scanned: {len(all_urls[:20])} | "
                  f"Injection points: {xss_points}")
            summ(xss_passed, xss_failed, max(xss_passed + xss_failed, 1))
            all_findings.extend(xss_findings)
        except Exception as e:
            print(f"  \033[91mERROR: {e}\033[0m")
            modules["xss"] = {"error": str(e), "findings": [], "passed": 0, "failed": 0, "total_checks": 0}
            error_count += 1
        
        # Module 8: Stored XSS (NEW v2)
        if not skip_stored_xss and forms:
            hdr(8, "Stored XSS Scanner [v2]")
            print(f"  \033[93m  Submitting payload ke {min(len(forms),10)} forms, "
                  f"lalu cek {len(all_urls)} halaman...\033[0m")
            try:
                r8 = scan_stored_xss(forms, all_urls)
                modules["stored_xss"] = r8
                if r8.get("findings"):
                    tbl(r8["findings"], limit=10)
                print(f"\n  Forms submitted: {r8.get('forms_submitted',0)} | "
                      f"Pages checked: {r8.get('pages_checked',0)}")
                summ(r8.get("passed",0), r8.get("failed",0), r8.get("total_checks",0))
                all_findings.extend(r8.get("findings", []))
            except Exception as e:
                print(f"  \033[91mERROR: {e}\033[0m")
                modules["stored_xss"] = {"error": str(e), "findings":[], "passed":0, "failed":0, "total_checks":0}
                error_count += 1
        else:
            hdr(8, "Stored XSS Scanner [v2]")
            print(f"  \033[93m⏭  Skipped\033[0m")
        
        # Module 9: CSRF — scan ALL crawled pages
        hdr(9, f"CSRF Checker ({len(all_urls)} pages)")
        try:
            csrf_findings = []
            csrf_passed = 0
            csrf_failed = 0
            forms_analyzed = 0
            checked_pages = set()
            
            for page_url in all_urls[:20]:
                path = urlparse(page_url).path or "/"
                if path in checked_pages:
                    continue
                checked_pages.add(path)
                
                r9 = check_csrf(page_url)
                if "error" in r9:
                    continue
                forms_analyzed += r9.get("forms_analyzed", 0)
                
                for f in r9.get("findings", []):
                    if f["status"] == "FAIL":
                        # Tambahkan path info
                        if path != "/" and path not in f.get("check", ""):
                            f["check"] = f["check"] + f" [{path}]"
                        csrf_findings.append(f)
                        csrf_failed += 1
                    elif f["status"] == "PASS":
                        csrf_findings.append(f)
                        csrf_passed += 1
            
            if csrf_failed == 0 and csrf_passed == 0:
                csrf_passed = 1
                csrf_findings.append({
                    "check": "CSRF Form Analysis",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": f"Tidak ada form rentan CSRF di {len(checked_pages)} halaman",
                    "recommendation": "-"
                })
            
            modules["csrf"] = {
                "findings": csrf_findings,
                "passed": csrf_passed,
                "failed": csrf_failed,
                "total_checks": max(csrf_passed + csrf_failed, 1),
                "pages_scanned": len(checked_pages),
                "forms_analyzed": forms_analyzed
            }
            tbl(csrf_findings, limit=10)
            print(f"\n  Pages scanned: {len(checked_pages)} | "
                  f"Forms analyzed: {forms_analyzed}")
            summ(csrf_passed, csrf_failed, max(csrf_passed + csrf_failed, 1))
            all_findings.extend(csrf_findings)
        except Exception as e:
            print(f"  \033[91mERROR: {e}\033[0m")
            modules["csrf"] = {"error": str(e), "findings": [], "passed": 0, "failed": 0, "total_checks": 0}
            error_count += 1
    else:
        print(f"\n  \033[93m⏭  Module 6-9 (Active tests) di-skip (--skip-active)\033[0m")
    
    # ═══════════════════════════════════════════
    # MODULE 11: Open Redirect Scanner
    # ═══════════════════════════════════════════
    if not skip_active:
        hdr(11, f"Open Redirect Scanner ({len(all_urls)} pages)")
        try:
            r11 = scan_open_redirect(target, all_urls=all_urls, param_links=param_links)
            modules["open_redirect"] = r11
            tbl(r11.get("findings", []), limit=10)
            print(f"\n  Tests: {r11.get('tests_performed', 0)}")
            summ(r11.get("passed", 0), r11.get("failed", 0), r11.get("total_checks", 0))
            all_findings.extend(r11.get("findings", []))
        except Exception as e:
            print(f"  \033[91mERROR: {e}\033[0m")
            modules["open_redirect"] = {"error": str(e), "findings": [], "passed": 0, "failed": 0, "total_checks": 0}
            error_count += 1
    
    # ═══════════════════════════════════════════
    # MODULE 12: CORS Misconfiguration
    # ═══════════════════════════════════════════
    hdr(12, f"CORS Misconfiguration Scanner ({len(all_urls)} pages)")
    try:
        r12 = scan_cors(target, all_urls=all_urls)
        modules["cors"] = r12
        tbl(r12.get("findings", []), limit=10)
        print(f"\n  Pages checked: {r12.get('pages_checked', 0)}")
        summ(r12.get("passed", 0), r12.get("failed", 0), r12.get("total_checks", 0))
        all_findings.extend(r12.get("findings", []))
    except Exception as e:
        print(f"  \033[91mERROR: {e}\033[0m")
        modules["cors"] = {"error": str(e), "findings": [], "passed": 0, "failed": 0, "total_checks": 0}
        error_count += 1
    
    # ═══════════════════════════════════════════
    # MODULE 13: HTTP Method Testing
    # ═══════════════════════════════════════════
    hdr(13, "HTTP Method Testing (PUT/DELETE/TRACE)")
    try:
        r13 = scan_http_methods(target, all_urls=all_urls)
        modules["http_methods"] = r13
        tbl(r13.get("findings", []), limit=10)
        print(f"\n  Methods tested: {r13.get('tests_performed', 0)}")
        summ(r13.get("passed", 0), r13.get("failed", 0), r13.get("total_checks", 0))
        all_findings.extend(r13.get("findings", []))
    except Exception as e:
        print(f"  \033[91mERROR: {e}\033[0m")
        modules["http_methods"] = {"error": str(e), "findings": [], "passed": 0, "failed": 0, "total_checks": 0}
        error_count += 1
    
    # ═══════════════════════════════════════════
    # MODULE 14: Information Leak Scanner
    # ═══════════════════════════════════════════
    hdr(14, f"Information Leak Scanner ({len(all_urls)} pages)")
    try:
        r14 = scan_info_leak(target, all_urls=all_urls)
        modules["info_leak"] = r14
        tbl(r14.get("findings", []), limit=10)
        print(f"\n  Pages scanned: {r14.get('pages_scanned', 0)} | "
              f"Leaks found: {r14.get('total_leaks', 0)}")
        summ(r14.get("passed", 0), r14.get("failed", 0), r14.get("total_checks", 0))
        all_findings.extend(r14.get("findings", []))
    except Exception as e:
        print(f"  \033[91mERROR: {e}\033[0m")
        modules["info_leak"] = {"error": str(e), "findings": [], "passed": 0, "failed": 0, "total_checks": 0}
        error_count += 1
    
    # ═══════════════════════════════════════════
    # MODULE 15: Cookie Deep Audit
    # ═══════════════════════════════════════════
    hdr(15, f"Cookie Deep Audit ({len(all_urls)} pages)")
    try:
        r15 = scan_cookies(target, all_urls=all_urls)
        modules["cookies"] = r15
        tbl(r15.get("findings", []), limit=10)
        print(f"\n  Cookies analyzed: {r15.get('cookies_analyzed', 0)}")
        summ(r15.get("passed", 0), r15.get("failed", 0), r15.get("total_checks", 0))
        all_findings.extend(r15.get("findings", []))
    except Exception as e:
        print(f"  \033[91mERROR: {e}\033[0m")
        modules["cookies"] = {"error": str(e), "findings": [], "passed": 0, "failed": 0, "total_checks": 0}
        error_count += 1
    
    # ═══════════════════════════════════════════
    # MODULE 16: Clickjacking Tester
    # ═══════════════════════════════════════════
    hdr(16, f"Clickjacking Tester ({len(all_urls)} pages)")
    try:
        r16 = scan_clickjacking(target, all_urls=all_urls)
        modules["clickjacking"] = r16
        tbl(r16.get("findings", []), limit=10)
        print(f"\n  Pages tested: {r16.get('pages_checked', 0)}")
        summ(r16.get("passed", 0), r16.get("failed", 0), r16.get("total_checks", 0))
        all_findings.extend(r16.get("findings", []))
    except Exception as e:
        print(f"  \033[91mERROR: {e}\033[0m")
        modules["clickjacking"] = {"error": str(e), "findings": [], "passed": 0, "failed": 0, "total_checks": 0}
        error_count += 1
    
    # ═══════════════════════════════════════════
    # MODULE 17: Directory Discovery
    # ═══════════════════════════════════════════
    hdr(17, "Directory Discovery (200+ paths)")
    try:
        from scanner.dir_discovery import DISCOVERY_PATHS as DP_COUNT
        r17 = scan_directories(target)
        modules["dir_discovery"] = r17
        tbl(r17.get("findings", []), limit=15)
        print(f"\n  Paths checked: {r17.get('paths_checked', 0)} | "
              f"Discovered: {r17.get('discovered', 0)}")
        summ(r17.get("passed", 0), r17.get("failed", 0), r17.get("total_checks", 0))
        all_findings.extend(r17.get("findings", []))
    except Exception as e:
        print(f"  \033[91mERROR: {e}\033[0m")
        modules["dir_discovery"] = {"error": str(e), "findings": [], "passed": 0, "failed": 0, "total_checks": 0}
        error_count += 1
    
    # ═══════════════════════════════════════════
    # MODULE 18: Technology Fingerprinting
    # ═══════════════════════════════════════════
    hdr(18, "Technology Fingerprinting")
    try:
        r18 = scan_tech_fingerprint(target, all_urls=all_urls)
        modules["tech"] = r18
        tbl(r18.get("findings", []), limit=10)
        print(f"\n  Technologies detected: {r18.get('tech_count', 0)}")
        summ(r18.get("passed", 0), r18.get("failed", 0), r18.get("total_checks", 0))
        all_findings.extend(r18.get("findings", []))
    except Exception as e:
        print(f"  \033[91mERROR: {e}\033[0m")
        modules["tech"] = {"error": str(e), "findings": [], "passed": 0, "failed": 0, "total_checks": 0}
        error_count += 1
    
    # ═══════════════════════════════════════════
    # MODULE 19: Security.txt & robots.txt
    # ═══════════════════════════════════════════
    hdr(19, "Security.txt & robots.txt Analyzer")
    try:
        r19 = scan_security_files(target)
        modules["security_txt"] = r19
        tbl(r19.get("findings", []), limit=10)
        summ(r19.get("passed", 0), r19.get("failed", 0), r19.get("total_checks", 0))
        all_findings.extend(r19.get("findings", []))
    except Exception as e:
        print(f"  \033[91mERROR: {e}\033[0m")
        modules["security_txt"] = {"error": str(e), "findings": [], "passed": 0, "failed": 0, "total_checks": 0}
        error_count += 1
    
    # ═══════════════════════════════════════════
    # MODULE 20: WAF Detection
    # ═══════════════════════════════════════════
    hdr(20, "WAF (Web Application Firewall) Detection")
    try:
        r20 = scan_waf(target)
        modules["waf"] = r20
        tbl(r20.get("findings", []), limit=10)
        print(f"\n  WAFs detected: {r20.get('waf_count', 0)} | "
              f"Blocked malicious: {'Yes' if r20.get('blocked_malicious') else 'No'}")
        summ(r20.get("passed", 0), r20.get("failed", 0), r20.get("total_checks", 0))
        all_findings.extend(r20.get("findings", []))
    except Exception as e:
        print(f"  \033[91mERROR: {e}\033[0m")
        modules["waf"] = {"error": str(e), "findings": [], "passed": 0, "failed": 0, "total_checks": 0}
        error_count += 1
    
    # ═══════════════════════════════════════════
    # MODULE 10: Advanced Port Scan
    # ═══════════════════════════════════════════
    if not skip_ports:
        hdr(10, f"Port Reconnaissance [v2: {port_mode}]")
        try:
            r10 = scan_ports_advanced(target, mode=port_mode)
            modules["ports"] = r10
            if "error" in r10:
                print(f"  \033[91mERROR: {r10['error']}\033[0m")
                error_count += 1
            else:
                tbl(r10["findings"], limit=15)
                print(f"\n  Mode: {r10['scan_label']}")
                print(f"  IP: {r10.get('ip','-')} | Ports scanned: {r10['ports_scanned']} | "
                      f"Open: \033[93m{len(r10.get('open_ports',[]))}\033[0m")
                summ(r10["passed"], r10["failed"], r10["total_checks"])
                all_findings.extend(r10.get("findings", []))
        except Exception as e:
            print(f"  \033[91mERROR: {e}\033[0m")
            modules["ports"] = {"error":str(e), "findings":[], "passed":0, "failed":0, "total_checks":0}
            error_count += 1
    else:
        print(f"\n  \033[93m⏭  Module 10 (Port Scan) di-skip\033[0m")
    
    # ═══════════════════════════════════════════
    # FINAL RESULTS
    # ═══════════════════════════════════════════
    elapsed = time.time() - start
    gi = grade_display(all_findings, error_count)
    recs(all_findings)
    json_path = save(target, modules, gi, all_findings, elapsed, crawl_info)
    
    # Generate PDF report (if reportlab available and not skipped)
    if PDF_AVAILABLE and "--no-pdf" not in args:
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                report_data = json.load(f)
            pdf_path = generate_pdf_report(report_data)
            print(f"  \033[96m📕 PDF Report: {pdf_path}\033[0m")
        except Exception as e:
            print(f"  \033[93m⚠  PDF generation failed: {e}\033[0m")
    elif not PDF_AVAILABLE:
        print(f"  \033[93m⚠  PDF not generated (install reportlab: pip install reportlab)\033[0m")
    
    tc = sum(m.get("total_checks", 0) for m in modules.values() if "error" not in m)
    tf = sum(m.get("failed", 0) for m in modules.values() if "error" not in m)
    
    print(f"\n  \033[1m{'═'*60}\033[0m")
    print(f"  \033[1m  SpencerWeb scan complete.\033[0m")
    print(f"  Pages: {crawl_info.get('pages_crawled',1)} | "
          f"Checks: {tc} | Vulnerabilities: {tf} | "
          f"Errors: {error_count} | Time: {elapsed:.1f}s")
    print(f"  \033[1m{'═'*60}\033[0m\n")


if __name__ == "__main__":
    main()
