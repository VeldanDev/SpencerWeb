"""
SpencerWeb — Module 17: Directory Discovery
Bruteforce common hidden directories dan files yang sering
ditemukan di web server tapi tidak ter-link dari halaman publik.

200+ paths yang dicek mencakup: admin panels, backup files,
config files, log files, API endpoints, development files, dll.
"""

import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.crawler import HEADERS


DISCOVERY_PATHS = [
    # Admin panels
    "/admin", "/admin/", "/administrator", "/administrator/", "/admin.php",
    "/admin/login", "/admin/login.php", "/admin/index.php",
    "/cpanel", "/webadmin", "/sysadmin", "/manager", "/manage",
    "/dashboard", "/control", "/controlpanel",
    # Login pages
    "/login", "/signin", "/auth", "/authenticate",
    "/user/login", "/users/sign_in", "/account/login",
    # API endpoints
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/users", "/api/config", "/api/status", "/api/health",
    "/graphql", "/graphiql", "/swagger", "/swagger-ui",
    "/api-docs", "/docs/api", "/redoc",
    # Development/debug
    "/debug", "/debug/", "/test", "/testing", "/staging",
    "/dev", "/development", "/sandbox",
    "/console", "/shell", "/terminal",
    "/phpinfo", "/phpinfo.php", "/info.php", "/pi.php",
    "/elmah.axd", "/trace.axd",
    # Version control
    "/.git", "/.git/HEAD", "/.git/config",
    "/.svn", "/.svn/entries", "/.svn/wc.db",
    "/.hg", "/.bzr",
    # Config files
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.env.old", "/.env.save", "/.env.bak",
    "/config.php", "/config.yml", "/config.yaml", "/config.json",
    "/settings.php", "/settings.py", "/settings.json",
    "/database.yml", "/db.php", "/db.json",
    "/wp-config.php.bak", "/web.config",
    # Backup & archives
    "/backup", "/backups", "/backup.sql", "/backup.zip",
    "/backup.tar.gz", "/dump.sql", "/database.sql",
    "/site.zip", "/www.zip", "/public.zip",
    "/old", "/old/", "/bak", "/temp", "/tmp",
    # Logs
    "/logs", "/log", "/error.log", "/access.log", "/debug.log",
    "/app.log", "/application.log", "/server.log",
    # CMS specific
    "/wp-admin", "/wp-login.php", "/wp-json",
    "/wp-content/uploads", "/wp-content/debug.log",
    "/joomla", "/administrator/index.php",
    "/drupal", "/user/register",
    "/magento", "/admin_magento",
    # Server files
    "/server-status", "/server-info",
    "/.htaccess", "/.htpasswd",
    "/nginx.conf", "/httpd.conf",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    # Package managers
    "/package.json", "/package-lock.json", "/yarn.lock",
    "/composer.json", "/composer.lock",
    "/Gemfile", "/Gemfile.lock",
    "/requirements.txt", "/Pipfile", "/Pipfile.lock",
    # Documentation
    "/readme", "/README", "/README.md", "/readme.html",
    "/CHANGELOG", "/CHANGELOG.md", "/LICENSE",
    "/docs", "/documentation",
    # CI/CD
    "/.github", "/.gitlab-ci.yml", "/.travis.yml",
    "/Jenkinsfile", "/Dockerfile", "/docker-compose.yml",
    "/.circleci/config.yml",
    # Monitoring
    "/metrics", "/prometheus", "/grafana",
    "/health", "/healthcheck", "/status", "/ping",
    "/actuator", "/actuator/health", "/actuator/env",
    # Database tools
    "/phpmyadmin", "/phpmyadmin/", "/pma", "/pma/",
    "/adminer", "/adminer.php",
    # Mail
    "/mail", "/webmail", "/roundcube",
    # Other
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/security.txt", "/.well-known/security.txt",
    "/humans.txt", "/ads.txt",
    "/cgi-bin", "/cgi-bin/",
    "/.DS_Store", "/Thumbs.db",
    "/install", "/install.php", "/setup", "/setup.php",
    "/xmlrpc.php", "/wp-cron.php",
    # Hidden APIs
    "/api/swagger.json", "/api/openapi.json",
    "/v1", "/v2", "/.well-known",
]

SEVERITY_MAP = {
    "/.git": "CRITICAL", "/.git/HEAD": "CRITICAL", "/.git/config": "CRITICAL",
    "/.env": "CRITICAL", "/.env.local": "CRITICAL", "/.env.production": "CRITICAL",
    "/.env.backup": "CRITICAL", "/.env.old": "CRITICAL",
    "/backup.sql": "CRITICAL", "/dump.sql": "CRITICAL", "/database.sql": "CRITICAL",
    "/.svn/wc.db": "CRITICAL",
    "/phpinfo.php": "HIGH", "/info.php": "HIGH", "/phpinfo": "HIGH",
    "/phpmyadmin": "HIGH", "/phpmyadmin/": "HIGH", "/pma": "HIGH",
    "/adminer": "HIGH", "/adminer.php": "HIGH",
    "/server-status": "MEDIUM", "/server-info": "MEDIUM",
    "/debug": "MEDIUM", "/console": "MEDIUM",
    "/wp-content/debug.log": "HIGH",
    "/docker-compose.yml": "HIGH", "/Dockerfile": "MEDIUM",
    "/.htpasswd": "CRITICAL",
    "/actuator/env": "HIGH", "/actuator": "MEDIUM",
    "/graphiql": "MEDIUM", "/swagger-ui": "LOW",
    "/elmah.axd": "HIGH", "/trace.axd": "HIGH",
}


def scan_directories(url, timeout=6, max_workers=15):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if not url.endswith("/"):
        url += "/"

    findings = []
    discovered = 0
    not_found = 0
    errors = 0

    # Canary check for soft 404
    canary_sizes = set()
    for cp in ["/spw-disc-canary-xyz123", "/spw-disc-canary-abc456"]:
        try:
            r = requests.get(urljoin(url, cp), timeout=timeout, headers=HEADERS,
                            allow_redirects=False)
            if r.status_code == 200:
                canary_sizes.add(len(r.content))
        except Exception:
            pass

    def check(path):
        target = urljoin(url, path)
        try:
            r = requests.get(target, timeout=timeout, headers=HEADERS,
                            allow_redirects=False)
            if r.status_code in (200, 301, 302, 403):
                size = len(r.content)
                # Skip soft 404
                if r.status_code == 200 and canary_sizes and size in canary_sizes:
                    return None
                if r.status_code == 200 and canary_sizes:
                    for cs in canary_sizes:
                        if abs(size - cs) <= 50:
                            return None
                return {"path": path, "status": r.status_code, "size": size}
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(check, p): p for p in DISCOVERY_PATHS}
        for f in as_completed(futures):
            result = f.result()
            if result:
                discovered += 1
                path = result["path"]
                status = result["status"]
                severity = SEVERITY_MAP.get(path, "LOW")

                if status == 403:
                    severity = "INFO"
                    detail = f"Path {path} exists but access denied (HTTP 403)"
                    findings.append({
                        "check": f"Directory: {path}", "status": "PASS",
                        "severity": "INFO", "detail": detail,
                        "recommendation": "-"
                    })
                else:
                    detail = f"Path {path} accessible (HTTP {status}, {result['size']} bytes)"
                    rec = "Verifikasi apakah path ini perlu accessible publik. Blokir jika tidak diperlukan."
                    findings.append({
                        "check": f"Directory: {path}", "status": "FAIL",
                        "severity": severity, "detail": detail,
                        "recommendation": rec
                    })
            else:
                not_found += 1

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: (0 if x["status"] == "FAIL" else 1, sev_order.get(x["severity"], 4)))

    passed = sum(1 for f in findings if f["status"] == "PASS")
    failed = sum(1 for f in findings if f["status"] == "FAIL")

    if failed == 0 and passed == 0:
        findings.append({"check": "Directory Discovery", "status": "PASS", "severity": "INFO",
                         "detail": f"Tidak ada hidden path ditemukan dari {len(DISCOVERY_PATHS)} paths",
                         "recommendation": "-"})
        passed = 1

    return {"target": url, "findings": findings, "paths_checked": len(DISCOVERY_PATHS),
            "discovered": discovered, "passed": passed, "failed": failed,
            "total_checks": max(passed + failed, 1)}
