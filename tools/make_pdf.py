"""
Spencer — CLI helper untuk membuat ulang laporan PDF dari berkas JSON hasil scan.

Dipanggil oleh dashboard (server.js) saat pengguna mengunduh PDF sebuah laporan
yang belum pernah di-generate ke PDF sebelumnya. Tidak menulis ulang logic
pembuatan PDF — hanya memanggil utils.pdf_report.generate_pdf_report().

Usage:
    python tools/make_pdf.py <path_ke_json>

Mencetak path file PDF yang dihasilkan ke stdout bila berhasil.

Exit codes:
    0 - sukses
    1 - argumen tidak valid / path di luar reports/ / JSON tidak valid / kesalahan lain
    2 - reportlab belum terpasang di interpreter Python ini
"""

import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")

sys.path.insert(0, PROJECT_ROOT)


def main():
    if len(sys.argv) != 2:
        print("Pemakaian: python tools/make_pdf.py <path_ke_json>", file=sys.stderr)
        sys.exit(1)

    json_path = os.path.abspath(sys.argv[1])
    reports_dir_real = os.path.realpath(REPORTS_DIR)
    json_path_real = os.path.realpath(json_path)

    # Cegah path traversal: berkas JSON wajib berada di dalam folder reports/
    if os.path.commonpath([reports_dir_real, json_path_real]) != reports_dir_real:
        print("Ditolak: berkas JSON harus berada di dalam folder reports/", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(json_path_real):
        print(f"Berkas tidak ditemukan: {json_path}", file=sys.stderr)
        sys.exit(1)

    try:
        from utils.pdf_report import generate_pdf_report, REPORTLAB_AVAILABLE
    except ImportError as e:
        print(f"Gagal mengimpor modul utils.pdf_report: {e}", file=sys.stderr)
        sys.exit(1)

    if not REPORTLAB_AVAILABLE:
        print("reportlab tidak terinstall. Jalankan: pip install reportlab", file=sys.stderr)
        sys.exit(2)

    try:
        with open(json_path_real, "r", encoding="utf-8") as f:
            json_report = json.load(f)
    except Exception as e:
        print(f"Gagal membaca berkas JSON: {e}", file=sys.stderr)
        sys.exit(1)

    # Petakan nama sesuai pola folder reports/:
    #   JSON: spencer_v2_{domain}_{timestamp}.json
    #   PDF : spencer_{domain}_{timestamp}.pdf
    base = os.path.basename(json_path_real)
    name, _ = os.path.splitext(base)
    if name.startswith("spencer_v2_"):
        pdf_name = "spencer_" + name[len("spencer_v2_"):] + ".pdf"
    else:
        pdf_name = name + ".pdf"
    output_path = os.path.join(REPORTS_DIR, pdf_name)

    try:
        result_path = generate_pdf_report(json_report, output_path)
    except Exception as e:
        print(f"Gagal membuat PDF: {e}", file=sys.stderr)
        sys.exit(1)

    print(result_path)
    sys.exit(0)


if __name__ == "__main__":
    main()
