"""Génère le PDF du dossier à partir de dossier.html.

  python dossier/build.py --out ../Workshop2026-M2-GX-Dossier.pdf

Rendu : Microsoft Edge (ou Chrome) en mode sans fenêtre ; en-pied et numéros de page ajoutés ensuite avec
PyMuPDF. Dépendance : pip install pymupdf. Les figures se régénèrent avec tools/plot_rehearsals.py.
"""
import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

import pymupdf

HERE = Path(__file__).resolve().parent
BROWSERS = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
]
FOOTER = "RESILIENCE-ALPHA · Workshop 2026 M2 · plateforme et données fictives"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--html", default=str(HERE / "dossier.html"))
    a = ap.parse_args()
    browser = next((b for b in BROWSERS if Path(b).exists()), None)
    if not browser:
        sys.exit("ni Edge ni Chrome trouvé")
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        raw = Path(tmp) / "raw.pdf"
        subprocess.run([browser, "--headless", "--disable-gpu", "--no-pdf-header-footer",
                        f"--print-to-pdf={raw}", Path(a.html).resolve().as_uri()], check=True, timeout=180,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        doc = pymupdf.open(raw)
        grey = (0.39, 0.45, 0.55)
        for i, page in enumerate(doc, 1):
            y = page.rect.height - 28
            page.insert_text((45, y), FOOTER, fontsize=7.5, fontname="helv", color=grey)
            label = str(i)
            w = pymupdf.get_text_length(label, fontname="helv", fontsize=7.5)
            page.insert_text((page.rect.width - 45 - w, y), label, fontsize=7.5, fontname="helv", color=grey)
        doc.set_metadata({"title": "PROJECT RESILIENCE-ALPHA : dossier d'ingénierie et de gouvernance",
                          "author": "Équipe G? (à compléter)", "subject": "Workshop 2026 M2 EPSI"})
        out = Path(a.out).resolve()
        doc.save(out, garbage=3, deflate=True)
        pages = len(doc)
        doc.close()
        print(f"{out} : {pages} pages")


if __name__ == "__main__":
    main()
