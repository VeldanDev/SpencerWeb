# Spencer v2.0 — Powerful Web Security Audit Tool

**Metode:** OWASP Top 10 + CVSS Scoring
**TA Teknik Komputer — Politeknik Negeri Medan**

---

## 🚀 Quick Start

```bash
# 1. Setup Python (CLI scanner)
python -m venv venv
venv\Scripts\activate                    # Windows
pip install -r requirements.txt

# 2. Setup Node.js (Dashboard)
cd dashboard
npm install
cd ..

# 3. Run!

# Option A: CLI Scanner
python main.py https://target.com

# Option B: Web Dashboard
run-dashboard.bat                        # Windows
# atau:  cd dashboard && node server.js
# Buka http://localhost:3000
```

---

## 📦 Komponen

| Komponen | Tech | Fungsi |
|---|---|---|
| **CLI Scanner** | Python | Engine scanning utama, 10 modules |
| **Web Dashboard** | Node.js + Express | UI visual, real-time scan progress, history |
| **PDF Report** | Python (reportlab) | Laporan profesional untuk mitra |
| **JSON Report** | Built-in | Raw data untuk integrasi |

---

## 🛡️ 10 Security Modules

| # | Module | Tipe | Apa yang dicek |
|---|--------|------|----------------|
| 0 | Deep Web Crawler | Recon | Crawl seluruh website, kumpulkan form & params |
| 1 | HTTP Security Headers | Passive | HSTS, CSP, X-Frame, dll |
| 2 | SSL/TLS Audit | Passive | Sertifikat, TLS version, cipher |
| 3 | Sensitive File Exposure | Passive | 35 path sensitif (.git, .env, backup) |
| 4 | CMS Detection | Passive | WordPress/Joomla/Drupal + versi |
| 5 | WordPress Plugin Scanner | Passive | 50 plugin populer + outdated check |
| 6 | Advanced SQL Injection | Active | Error + Boolean + Time-based **(verified)** |
| 7 | Reflected XSS | Active | Reflected XSS detection |
| 8 | Stored XSS | Active | Multi-page payload reflection check |
| 9 | CSRF Checker | Active | Form CSRF token analysis |
| 10 | Port Reconnaissance | Active | Top 100 / 1000 / Full 65535 ports |

---

## 💻 CLI Usage

```bash
# Default deep scan
python main.py https://target.com

# Quick scan
python main.py https://target.com --quick

# Custom crawl
python main.py https://target.com --max-pages 50 --max-depth 3

# Port modes
python main.py https://target.com --port-mode common      # top 100 (default)
python main.py https://target.com --port-mode extended    # top 1000
python main.py https://target.com --port-mode full        # all 65535

# Skip slow modules
python main.py https://target.com --skip-time-sqli --skip-stored-xss
python main.py https://target.com --skip-active           # no SQLi/XSS/CSRF
python main.py https://target.com --skip-ports            # no port scan

# Skip PDF generation
python main.py https://target.com --no-pdf
```

---

## 🖥️ Dashboard

Web-based UI yang menampilkan:
- **📊 Statistics overview** — total scans, vulnerabilities, average grade
- **🔍 New Scan form** — trigger scan dari browser
- **📡 Live output** — real-time stdout dari scanner via WebSocket
- **📁 Reports history** — semua hasil scan tersimpan, click untuk detail
- **🎯 Findings detail** — full report dengan severity tags, recommendations

```bash
# Start dashboard
run-dashboard.bat                  # Windows
node dashboard/server.js           # Manual

# Akses: http://localhost:3000
```

---

## 📕 PDF Report

Otomatis generate setelah scan, atau via API. PDF berisi:
- Cover page dengan grade & target info
- Executive summary dengan severity breakdown
- Metodologi audit
- Detail per vulnerability (severity, deskripsi, rekomendasi)
- Detail per module
- Top 5 prioritized recommendations
- Disclaimer

File output: `reports/spencer_{domain}_{timestamp}.pdf`

### Unduh Hasil PDF (Dashboard)

Setiap laporan di dashboard punya tombol **"Unduh PDF"** (di daftar laporan)
dan **"Unduh Hasil (PDF)"** (di halaman detail laporan).

- Bila PDF untuk laporan tersebut sudah pernah di-generate (`reports/spencer_{domain}_{timestamp}.pdf`),
  file langsung dikirim.
- Bila belum ada, server membuatnya on-demand lewat `tools/make_pdf.py` (memanggil
  `generate_pdf_report()` yang sama seperti CLI), lalu mengirim hasilnya.

Endpoint API: `GET /api/reports/:filename/pdf` (`:filename` = nama file JSON,
mis. `spencer_v2_contoh_com_20260101_120000.json`).

Server otomatis memilih interpreter Python yang tepat: `venv/Scripts/python.exe`
bila ada dan reportlab terpasang di sana, kalau tidak jatuh ke Python global.
Bila reportlab tidak terpasang di manapun, endpoint mengembalikan `501` dengan
pesan galat berbahasa Indonesia.

---

## ⭐ Yang Baru di v2.0

✅ **Deep crawling** — scan seluruh website, bukan cuma homepage
✅ **Verified Time-based SQLi** — 3-step verification (SLEEP 3 → SLEEP 5 → baseline) mengurangi false positive
✅ **Boolean-based SQLi** — bandingkan TRUE vs FALSE response
✅ **Stored XSS** — submit payload, cek di halaman lain
✅ **WordPress plugin scan** — 50 plugin populer + version check
✅ **Full port scan** — 65535 ports option
✅ **PDF Report Generator** — laporan profesional auto-generated
✅ **Node.js Dashboard** — Web UI dengan real-time scan progress
✅ **WebSocket live output** — lihat scan progress langsung di browser
✅ **Smart grading** — grade `?` saat scan error, bukan auto-A

---

## 🗂️ Struktur Project

```
spencer/
├── main.py                        # CLI entry point
├── requirements.txt               # Python deps
├── run-dashboard.bat              # Windows launcher
├── README.md
│
├── scanner/                       # Python scanning modules
│   ├── headers.py                 # Module 1
│   ├── ssl_audit.py               # Module 2
│   ├── sensitive_files.py         # Module 3
│   ├── cms_detect.py              # Module 4
│   ├── wp_scanner.py              # Module 5 ⭐
│   ├── sqli.py                    # SQLi v1
│   ├── sqli_advanced.py           # Module 6 ⭐ (verified)
│   ├── xss.py                     # Module 7
│   ├── stored_xss.py              # Module 8 ⭐
│   ├── csrf.py                    # Module 9
│   ├── port_scan.py               # Port scan v1
│   └── port_scan_advanced.py      # Module 10 ⭐
│
├── utils/
│   ├── scoring.py                 # CVSS Grade A-F
│   ├── crawler.py                 # Form/URL helpers
│   ├── spider.py                  # Deep crawler ⭐
│   └── pdf_report.py              # PDF generator ⭐
│
├── dashboard/                     # Node.js Web UI ⭐
│   ├── server.js                  # Express + WebSocket server
│   ├── package.json
│   └── public/
│       ├── index.html
│       ├── style.css
│       └── app.js
│
└── reports/                       # Output (JSON + PDF)
```

---

## ⚠️ Disclaimer

Spencer dibuat untuk audit keamanan yang sah dan tujuan pendidikan.
Gunakan **HANYA** pada website yang Anda miliki izinnya.
Penggunaan tanpa izin dapat melanggar UU ITE dan UU PDP.

Hasil scan automated bisa berupa false positive — verifikasi manual
sebelum kesimpulan final, terutama untuk finding CRITICAL.
