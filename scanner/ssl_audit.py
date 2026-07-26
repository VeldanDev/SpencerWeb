"""
Spencer — Modul Audit SSL/TLS
Mengecek sertifikat SSL, versi TLS, dan konfigurasi keamanan transport layer.
Semua kode ditulis original dari nol menggunakan library standar Python (ssl, socket).
"""

import ssl
import socket
import datetime
from urllib.parse import urlparse


def audit_ssl(url: str, timeout: int = 10) -> dict:
    """
    Audit SSL/TLS pada target URL.
    
    Checks:
    1. Validitas sertifikat (expired? self-signed?)
    2. Masa berlaku sertifikat (berapa hari lagi expired)
    3. Common Name / SAN match dengan domain
    4. Versi TLS yang didukung (TLS 1.0/1.1 = bahaya)
    5. Issuer (siapa yang menerbitkan sertifikat)
    
    Returns:
        dict dengan findings list
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.netloc or parsed.path
    # Hapus port jika ada
    if ":" in hostname:
        hostname = hostname.split(":")[0]
    port = parsed.port or 443

    findings = []
    passed = 0
    failed = 0
    cert_info = {}

    # === FIX FALSE POSITIVE: target HTTP tanpa TLS ===
    # Jika target diakses via http:// (mis. aplikasi lokal / dev server di port
    # non-TLS), memaksa TLS handshake pada port HTTP akan gagal dengan
    # "WRONG_VERSION_NUMBER" dan SEBELUMNYA dilaporkan CRITICAL secara keliru.
    # Itu false positive: port HTTP murni memang tidak bicara TLS.
    if parsed.scheme == "http":
        if _tls_handshake_ok(hostname, 443, timeout):
            # Host ternyata menyediakan HTTPS di 443 → audit sertifikat di sana
            # (hasil valid & relevan untuk produksi).
            port = 443
        else:
            # Tidak ada TLS sama sekali → bukan CRITICAL, ini info/LOW yang jujur.
            return {
                "target": url,
                "hostname": hostname,
                "findings": [{
                    "check": "Ketersediaan HTTPS/TLS",
                    "status": "INFO",
                    "severity": "LOW",
                    "detail": ("Target diakses via HTTP dan tidak menyediakan HTTPS/TLS "
                               "pada port 443. Audit sertifikat SSL tidak berlaku untuk "
                               "endpoint HTTP murni."),
                    "recommendation": ("Untuk lingkungan produksi, aktifkan HTTPS "
                                       "(mis. sertifikat gratis Let's Encrypt). Untuk dev "
                                       "server lokal, kondisi ini wajar.")
                }],
                "cert_info": {},
                "passed": 0,
                "failed": 0,
                "total_checks": 0
            }

    # === CHECK 1: Koneksi SSL & Sertifikat ===
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()
                tls_version = tls_sock.version()
                cert_info = cert
    except ssl.SSLCertVerificationError as e:
        failed += 1
        findings.append({
            "check": "Validitas Sertifikat SSL",
            "status": "FAIL",
            "severity": "CRITICAL",
            "detail": f"Sertifikat tidak valid: {str(e)[:100]}",
            "recommendation": "Perbarui sertifikat SSL dengan yang valid dari Certificate Authority terpercaya"
        })
        # Coba lagi tanpa verifikasi untuk mendapatkan info sertifikat
        try:
            context_noverify = ssl.create_default_context()
            context_noverify.check_hostname = False
            context_noverify.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context_noverify.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    cert = tls_sock.getpeercert(binary_form=False)
                    cipher = tls_sock.cipher()
                    tls_version = tls_sock.version()
                    if cert:
                        cert_info = cert
        except Exception:
            pass
        
        return {
            "target": url,
            "hostname": hostname,
            "findings": findings,
            "cert_info": cert_info,
            "passed": passed,
            "failed": failed,
            "total_checks": passed + failed
        }
    except ssl.SSLError as e:
        failed += 1
        findings.append({
            "check": "Koneksi SSL",
            "status": "FAIL",
            "severity": "CRITICAL",
            "detail": f"SSL error: {str(e)[:100]}",
            "recommendation": "Periksa konfigurasi SSL server"
        })
        return {
            "target": url,
            "hostname": hostname,
            "findings": findings,
            "cert_info": {},
            "passed": passed,
            "failed": failed,
            "total_checks": passed + failed
        }
    except (socket.timeout, ConnectionRefusedError, socket.gaierror) as e:
        return {
            "target": url,
            "hostname": hostname,
            "error": f"Tidak dapat terhubung ke {hostname}:{port} — {e}",
            "findings": findings,
            "cert_info": {},
            "passed": 0,
            "failed": 0,
            "total_checks": 0
        }

    # Sertifikat valid (berhasil connect tanpa error)
    passed += 1
    findings.append({
        "check": "Validitas Sertifikat SSL",
        "status": "PASS",
        "severity": "INFO",
        "detail": "Sertifikat valid dan terpercaya",
        "recommendation": "-"
    })

    # === CHECK 2: Masa berlaku sertifikat ===
    if cert_info:
        not_after_str = cert_info.get("notAfter", "")
        if not_after_str:
            try:
                # Format: 'MMM DD HH:MM:SS YYYY GMT'  atau  'Mon DD HH:MM:SS YYYY GMT'
                not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                days_remaining = (not_after - datetime.datetime.utcnow()).days

                if days_remaining < 0:
                    failed += 1
                    findings.append({
                        "check": "Masa Berlaku Sertifikat",
                        "status": "FAIL",
                        "severity": "CRITICAL",
                        "detail": f"Sertifikat sudah EXPIRED {abs(days_remaining)} hari yang lalu",
                        "recommendation": "Segera perbarui sertifikat SSL"
                    })
                elif days_remaining < 30:
                    failed += 1
                    findings.append({
                        "check": "Masa Berlaku Sertifikat",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "detail": f"Sertifikat akan expired dalam {days_remaining} hari ({not_after_str})",
                        "recommendation": "Perbarui sertifikat sebelum expired"
                    })
                elif days_remaining < 90:
                    passed += 1
                    findings.append({
                        "check": "Masa Berlaku Sertifikat",
                        "status": "PASS",
                        "severity": "LOW",
                        "detail": f"Sertifikat berlaku {days_remaining} hari lagi ({not_after_str})",
                        "recommendation": "Jadwalkan pembaruan sertifikat"
                    })
                else:
                    passed += 1
                    findings.append({
                        "check": "Masa Berlaku Sertifikat",
                        "status": "PASS",
                        "severity": "INFO",
                        "detail": f"Sertifikat berlaku {days_remaining} hari lagi ({not_after_str})",
                        "recommendation": "-"
                    })
            except ValueError:
                findings.append({
                    "check": "Masa Berlaku Sertifikat",
                    "status": "INFO",
                    "severity": "INFO",
                    "detail": f"Tidak dapat mem-parse tanggal: {not_after_str}",
                    "recommendation": "Verifikasi manual"
                })

    # === CHECK 3: Versi TLS ===
    if tls_version:
        tls_bad = ["TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"]
        tls_good = ["TLSv1.2", "TLSv1.3"]

        if tls_version in tls_bad:
            failed += 1
            findings.append({
                "check": "Versi TLS",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": f"Server menggunakan {tls_version} (deprecated, rentan serangan)",
                "recommendation": "Upgrade ke TLS 1.2 atau TLS 1.3. Nonaktifkan TLS 1.0 dan 1.1"
            })
        elif tls_version in tls_good:
            passed += 1
            findings.append({
                "check": "Versi TLS",
                "status": "PASS",
                "severity": "INFO",
                "detail": f"Server menggunakan {tls_version}",
                "recommendation": "-"
            })
        else:
            findings.append({
                "check": "Versi TLS",
                "status": "INFO",
                "severity": "INFO",
                "detail": f"Versi TLS: {tls_version}",
                "recommendation": "Verifikasi manual"
            })

    # === CHECK 4: Cipher strength ===
    if cipher:
        cipher_name, cipher_protocol, cipher_bits = cipher
        if cipher_bits and cipher_bits < 128:
            failed += 1
            findings.append({
                "check": "Cipher Strength",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": f"Cipher lemah: {cipher_name} ({cipher_bits}-bit)",
                "recommendation": "Gunakan cipher dengan minimal 128-bit (AES-128 atau lebih tinggi)"
            })
        else:
            passed += 1
            findings.append({
                "check": "Cipher Strength",
                "status": "PASS",
                "severity": "INFO",
                "detail": f"Cipher: {cipher_name} ({cipher_bits}-bit)",
                "recommendation": "-"
            })

    # === CHECK 5: Issuer ===
    if cert_info:
        issuer = cert_info.get("issuer", ())
        issuer_dict = {}
        for item in issuer:
            for key, value in item:
                issuer_dict[key] = value

        issuer_org = issuer_dict.get("organizationName", "Unknown")
        issuer_cn = issuer_dict.get("commonName", "Unknown")

        # Self-signed check sederhana
        subject = cert_info.get("subject", ())
        subject_dict = {}
        for item in subject:
            for key, value in item:
                subject_dict[key] = value

        if issuer_org == subject_dict.get("organizationName", "") and \
           issuer_cn == subject_dict.get("commonName", ""):
            failed += 1
            findings.append({
                "check": "Certificate Issuer",
                "status": "FAIL",
                "severity": "HIGH",
                "detail": f"Kemungkinan self-signed certificate (Issuer = Subject: {issuer_cn})",
                "recommendation": "Gunakan sertifikat dari CA terpercaya (Let's Encrypt gratis)"
            })
        else:
            passed += 1
            findings.append({
                "check": "Certificate Issuer",
                "status": "PASS",
                "severity": "INFO",
                "detail": f"Diterbitkan oleh: {issuer_org} ({issuer_cn})",
                "recommendation": "-"
            })

    # === CHECK 6: Subject Alternative Names (SAN) ===
    if cert_info:
        san = cert_info.get("subjectAltName", ())
        san_domains = [value for type_, value in san if type_ == "DNS"]

        if san_domains:
            domain_match = any(
                _match_domain(hostname, san_domain) for san_domain in san_domains
            )
            if domain_match:
                passed += 1
                findings.append({
                    "check": "Domain Match (SAN)",
                    "status": "PASS",
                    "severity": "INFO",
                    "detail": f"Domain '{hostname}' tercantum di SAN sertifikat",
                    "recommendation": "-"
                })
            else:
                failed += 1
                findings.append({
                    "check": "Domain Match (SAN)",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "detail": f"Domain '{hostname}' TIDAK tercantum di SAN. SAN: {', '.join(san_domains[:5])}",
                    "recommendation": "Pastikan sertifikat mencakup domain yang benar"
                })
        else:
            findings.append({
                "check": "Domain Match (SAN)",
                "status": "INFO",
                "severity": "LOW",
                "detail": "Tidak ada Subject Alternative Names di sertifikat",
                "recommendation": "Tambahkan SAN ke sertifikat"
            })

    return {
        "target": url,
        "hostname": hostname,
        "tls_version": tls_version if 'tls_version' in dir() else "Unknown",
        "cipher": cipher if 'cipher' in dir() else None,
        "findings": findings,
        "cert_info": _simplify_cert(cert_info),
        "passed": passed,
        "failed": failed,
        "total_checks": passed + failed
    }


def _tls_handshake_ok(hostname: str, port: int, timeout: int) -> bool:
    """Cek apakah host benar-benar menerima TLS handshake di port tertentu.
    Dipakai untuk membedakan target HTTP murni vs host yang punya HTTPS."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=hostname):
                return True
    except Exception:
        return False


def _match_domain(hostname: str, pattern: str) -> bool:
    """Cek apakah hostname cocok dengan pattern (termasuk wildcard *.domain.com)."""
    if pattern.startswith("*."):
        # Wildcard: *.example.com matches sub.example.com tapi bukan example.com
        suffix = pattern[2:]
        return hostname.endswith(suffix) and hostname != suffix
    return hostname == pattern


def _simplify_cert(cert: dict) -> dict:
    """Sederhanakan cert dict untuk report."""
    if not cert:
        return {}
    
    result = {}
    
    # Subject
    subject = cert.get("subject", ())
    for item in subject:
        for key, value in item:
            result[f"subject_{key}"] = value
    
    # Issuer
    issuer = cert.get("issuer", ())
    for item in issuer:
        for key, value in item:
            result[f"issuer_{key}"] = value
    
    result["notBefore"] = cert.get("notBefore", "")
    result["notAfter"] = cert.get("notAfter", "")
    result["serialNumber"] = cert.get("serialNumber", "")
    
    # SAN
    san = cert.get("subjectAltName", ())
    result["san"] = [value for type_, value in san if type_ == "DNS"]
    
    return result
