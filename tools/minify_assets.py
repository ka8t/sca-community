#!/usr/bin/env python3
"""
Minification des assets du rapport HTML.
À lancer après toute modification de report.css, report.js ou charts.js.
Produit report.min.css, report.min.js, charts.min.js dans templates/.

Usage : python tools/minify_assets.py
"""
import os
import sys

try:
    import rcssmin
    import rjsmin
except ImportError:
    venv_python = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".venv", "bin", "python")
    if os.path.exists(venv_python) and sys.executable != os.path.realpath(venv_python):
        os.execv(venv_python, [venv_python] + sys.argv)
    print("Erreur : rcssmin et rjsmin requis. Lancez : .venv/bin/pip install rcssmin rjsmin")
    sys.exit(1)

TEMPLATES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")

ASSETS = [
    ("report.css",  "report.min.css",  "css"),
    ("report.js",   "report.min.js",   "js"),
    ("charts.js",   "charts.min.js",   "js"),
]

def minify(src: str, kind: str) -> str:
    if kind == "css":
        return rcssmin.cssmin(src)
    return rjsmin.jsmin(src)

total_before = total_after = 0

for src_name, min_name, kind in ASSETS:
    src_path = os.path.join(TEMPLATES, src_name)
    min_path = os.path.join(TEMPLATES, min_name)

    with open(src_path, encoding="utf-8") as f:
        src = f.read()

    minified = minify(src, kind)

    with open(min_path, "w", encoding="utf-8") as f:
        f.write(minified)

    before, after = len(src.encode()), len(minified.encode())
    ratio = (1 - after / before) * 100 if before else 0
    total_before += before
    total_after  += after
    print(f"  {src_name:20s} → {min_name:24s}  {before:>7,} → {after:>7,} bytes  (-{ratio:.1f}%)")

total_ratio = (1 - total_after / total_before) * 100 if total_before else 0
print(f"\n  Total : {total_before:,} → {total_after:,} bytes  (-{total_ratio:.1f}%)")
