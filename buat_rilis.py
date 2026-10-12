# -*- coding: utf-8 -*-
"""Menyusun paket rilis: dist\\ForensikRunner-v<versi>.zip + .sha256 untuk diunggah ke GitHub Releases.
Jalankan: python buat_rilis.py   (versi diambil dari APP_VERSION di forensik_core.py)
Lalu di GitHub: Releases > Draft new release > tag v<versi> > lampirkan kedua berkas > Publish.
"""
import hashlib, os, re, zipfile
HERE = os.path.dirname(os.path.abspath(__file__))
ver = re.search(r'APP_VERSION\s*=\s*"([^"]+)"', open(os.path.join(HERE, "forensik_core.py"), encoding="utf-8").read()).group(1)
EXT = (".py", ".bat", ".ps1", ".md", ".txt", ".png", ".jpg", ".ico", ".json")
SKIP = {"__pycache__", "_backup_versi", "dist", "tools", "config.json"}
os.makedirs(os.path.join(HERE, "dist"), exist_ok=True)
out = os.path.join(HERE, "dist", "ForensikRunner-v%s.zip" % ver)
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for dp, dn, fn in os.walk(HERE):
        dn[:] = [d for d in dn if d not in SKIP]
        for f in fn:
            if f in SKIP or not f.lower().endswith(EXT):
                continue
            p = os.path.join(dp, f)
            z.write(p, os.path.join("ForensikRunner", os.path.relpath(p, HERE)))
h = hashlib.sha256(open(out, "rb").read()).hexdigest()
open(out + ".sha256", "w").write("%s  %s\n" % (h, os.path.basename(out)))
print("Paket :", out); print("SHA256:", h)
print("Unggah zip dan .sha256 sebagai aset rilis dengan tag v%s." % ver)
