"""
Spencer — Modul Open Port Reconnaissance
Melakukan scanning port TCP umum untuk mengidentifikasi service yang berjalan.
Menggunakan library standar Python (socket) — bukan wrapper Nmap.

Hanya scan top 20 port yang paling umum dan relevan untuk web server.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse


# Top 20 port yang relevan untuk web security audit
COMMON_PORTS = [
    (21,    "FTP",              "File Transfer Protocol — sering punya kerentanan anonymous login"),
    (22,    "SSH",              "Secure Shell — pastikan versi up to date"),
    (23,    "Telnet",           "Telnet — TIDAK terenkripsi, sangat tidak aman"),
    (25,    "SMTP",             "Mail server — bisa disalahgunakan untuk spam relay"),
    (53,    "DNS",              "Domain Name System"),
    (80,    "HTTP",             "Web server tanpa enkripsi"),
    (110,   "POP3",             "Email retrieval — tidak terenkripsi"),
    (143,   "IMAP",             "Email retrieval — tidak terenkripsi"),
    (443,   "HTTPS",            "Web server dengan SSL/TLS"),
    (445,   "SMB",              "File sharing — sering jadi target ransomware"),
    (993,   "IMAPS",            "IMAP dengan SSL"),
    (995,   "POP3S",            "POP3 dengan SSL"),
    (3306,  "MySQL",            "Database MySQL — seharusnya tidak exposed ke publik"),
    (3389,  "RDP",              "Remote Desktop — target utama brute force"),
    (5432,  "PostgreSQL",       "Database PostgreSQL — seharusnya tidak exposed ke publik"),
    (5900,  "VNC",              "Remote desktop — sering tanpa password"),
    (6379,  "Redis",            "In-memory database — sering tanpa autentikasi"),
    (8080,  "HTTP-Alt",         "Web server alternatif / proxy / dev server"),
    (8443,  "HTTPS-Alt",        "HTTPS alternatif"),
    (27017, "MongoDB",          "NoSQL database — sering tanpa autentikasi default"),
]

# Port yang seharusnya TIDAK terbuka ke internet publik
DANGEROUS_PORTS = {
    23:    ("CRITICAL", "Telnet tidak terenkripsi — attacker bisa sniff kredensial"),
    3306:  ("HIGH",     "Database MySQL exposed ke publik — risiko data breach"),
    5432:  ("HIGH",     "Database PostgreSQL exposed ke publik — risiko data breach"),
    6379:  ("HIGH",     "Redis exposed ke publik — sering tanpa auth, bisa RCE"),
    27017: ("HIGH",     "MongoDB exposed ke publik — sering tanpa auth default"),
    5900:  ("HIGH",     "VNC exposed ke publik — remote desktop tanpa enkripsi"),
    445:   ("MEDIUM",   "SMB exposed — target umum ransomware (WannaCry, EternalBlue)"),
    3389:  ("MEDIUM",   "RDP exposed — target brute force dan BlueKeep exploit"),
    110:   ("LOW",      "POP3 tanpa enkripsi — kredensial bisa di-sniff"),
    143:   ("LOW",      "IMAP tanpa enkripsi — kredensial bisa di-sniff"),
}


def scan_ports(url: str, timeout: int = 3, max_workers: int = 15) -> dict:
    """
    Scan port TCP umum pada target host.
    
    Args:
        url: Target URL (hostname diextract otomatis)
        timeout: Timeout per port dalam detik
        max_workers: Jumlah concurrent threads
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    hostname = urlparse(url).netloc
    if ":" in hostname:
        hostname = hostname.split(":")[0]

    findings = []
    passed = 0
    failed = 0
    open_ports = []

    # Resolve hostname
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return {
            "target": url,
            "hostname": hostname,
            "error": f"Tidak dapat resolve hostname: {hostname}",
            "findings": [], "passed": 0, "failed": 0, "total_checks": 0
        }

    def check_port(port_info: tuple) -> dict:
        port, service, desc = port_info
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                return {"port": port, "service": service, "desc": desc, "open": True}
            return {"port": port, "service": service, "open": False}
        except Exception:
            return {"port": port, "service": service, "open": False}

    # Concurrent port scanning
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_port, p): p for p in COMMON_PORTS}
        
        for future in as_completed(futures):
            result = future.result()
            if result["open"]:
                open_ports.append(result)

    # Sort by port number
    open_ports.sort(key=lambda x: x["port"])

    # Generate findings
    for p in open_ports:
        port = p["port"]
        
        if port in DANGEROUS_PORTS:
            severity, risk_detail = DANGEROUS_PORTS[port]
            failed += 1
            findings.append({
                "check": f"Port {port}/{p['service']}",
                "status": "FAIL",
                "severity": severity,
                "detail": f"Port {port} ({p['service']}) TERBUKA — {risk_detail}",
                "recommendation": f"Tutup port {port} via firewall jika tidak diperlukan. "
                                 f"Jika diperlukan, batasi akses via IP allowlist."
            })
        else:
            passed += 1
            findings.append({
                "check": f"Port {port}/{p['service']}",
                "status": "PASS",
                "severity": "INFO",
                "detail": f"Port {port} ({p['service']}) terbuka — {p.get('desc', '')}",
                "recommendation": "-"
            })

    if not open_ports:
        passed += 1
        findings.append({
            "check": "Port Scan",
            "status": "PASS",
            "severity": "INFO",
            "detail": "Tidak ada port terbuka yang terdeteksi dari 20 port yang di-scan",
            "recommendation": "-"
        })

    return {
        "target": url,
        "hostname": hostname,
        "ip": ip,
        "findings": findings,
        "open_ports": [{"port": p["port"], "service": p["service"]} for p in open_ports],
        "ports_scanned": len(COMMON_PORTS),
        "passed": passed,
        "failed": failed,
        "total_checks": passed + failed
    }
