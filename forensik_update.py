# -*- coding: utf-8 -*-
"""Pembaruan aplikasi Forensik Runner dari rilis GitHub (lihat PRD F30).

Hanya mengunduh (GET). Tidak mengirim data kasus. Update ditolak bila checksum SHA-256 tidak tersedia/tidak cocok.
"""
import hashlib
import io
import json
import os
import re
import shutil
import time
import urllib.request
import zipfile

ALLOWED_HOSTS = ("api.github.com", "github.com", "objects.githubusercontent.com", "codeload.github.com",
                 "release-assets.githubusercontent.com")
OVERWRITE_EXT = (".py", ".bat", ".ps1", ".md", ".txt", ".png", ".jpg", ".ico")
USER_JSON_OK_IF_MISSING = (".json",)
BACKUP_DIR = "_backup_versi"
MAX_ZIP = 60 * 1024 * 1024
MAX_FILES = 400
REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$")


DEFAULT_REPO = "andri-puspo/forensik_runner_P2_DJP"


class UpdateError(Exception):
    pass


def parse_version(v):
    """'v1.2.3' -> (1, 2, 3); angka saja, bagian non-angka diabaikan."""
    nums = re.findall(r"\d+", str(v or ""))
    return tuple(int(x) for x in nums[:4]) or (0,)


def is_newer(remote, local):
    a, b = list(parse_version(remote)), list(parse_version(local))
    n = max(len(a), len(b))
    a += [0] * (n - len(a)); b += [0] * (n - len(b))
    return a > b


def _safe_url(url):
    m = re.match(r"^https://([^/:]+)(/|$)", url or "")
    if not m or m.group(1).lower() not in ALLOWED_HOSTS:
        raise UpdateError("Alamat unduhan ditolak (hanya HTTPS ke GitHub): %s" % (url or "")[:80])
    return url


class _NoCrossHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _safe_url(newurl)
        nr = urllib.request.HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, headers, newurl)
        if nr is not None:
            h_old = re.match(r"^https://([^/]+)", req.full_url)
            h_new = re.match(r"^https://([^/]+)", newurl)
            if not (h_old and h_new and h_old.group(1) == h_new.group(1)):
                nr.headers.pop("Authorization", None)
                nr.unredirected_hdrs.pop("Authorization", None)
        return nr


def _http_get(url, token="", accept="application/vnd.github+json", limit=MAX_ZIP, timeout=30):
    _safe_url(url)
    hdr = {"User-Agent": "ForensikRunner-Updater", "Accept": accept}
    if token:
        hdr["Authorization"] = "Bearer " + token
    op = urllib.request.build_opener(_NoCrossHostRedirect())
    try:
        with op.open(urllib.request.Request(url, headers=hdr), timeout=timeout) as r:
            data = r.read(limit + 1)
    except Exception as e:
        raise UpdateError("Gagal menghubungi GitHub: %s" % e)
    if len(data) > limit:
        raise UpdateError("Berkas unduhan terlalu besar.")
    return data


def check(repo, local_version, token="", http_get=None):
    """Kembalikan dict info rilis terbaru: version, tag, notes, newer, zip_url, sha256."""
    g = http_get or _http_get
    if not REPO_RE.match(repo or ""):
        raise UpdateError("Repositori belum diisi/format salah. Gunakan pemilik/nama, mis. dit-p2/forensik-runner.")
    raw = g("https://api.github.com/repos/%s/releases/latest" % repo, token)
    try:
        rel = json.loads(raw.decode("utf-8"))
    except Exception:
        raise UpdateError("Jawaban GitHub tidak dapat dibaca.")
    tag = rel.get("tag_name") or ""
    if not tag:
        raise UpdateError("Repositori belum memiliki rilis.")
    assets = rel.get("assets") or []
    zip_asset = next((a for a in assets if str(a.get("name", "")).lower().endswith(".zip")), None)
    zip_url = (zip_asset.get("url") or zip_asset.get("browser_download_url")) if zip_asset else None
    sha = None
    sha_asset = next((a for a in assets if str(a.get("name", "")).lower().endswith(".sha256")), None)
    if sha_asset:
        try:
            txt = g(sha_asset.get("url") or sha_asset["browser_download_url"], token, "application/octet-stream", 4096).decode("utf-8", "ignore")
            m = re.search(r"\b([0-9a-fA-F]{64})\b", txt)
            sha = m.group(1).lower() if m else None
        except UpdateError:
            sha = None
    if not sha:
        m = re.search(r"sha-?256\s*[:=]\s*([0-9a-fA-F]{64})", rel.get("body") or "", re.I)
        sha = m.group(1).lower() if m else None
    return dict(version=tag.lstrip("vV"), tag=tag, notes=(rel.get("body") or "").strip()[:1500],
                newer=is_newer(tag, local_version), zip_url=zip_url, sha256=sha, name=rel.get("name") or tag)


def _find_root(names):
    """Folder di dalam zip yang memuat forensik_core.py (mungkin ada folder induk)."""
    for n in names:
        if n.replace("\\", "/").endswith("forensik_core.py"):
            return n.replace("\\", "/")[:-len("forensik_core.py")]
    raise UpdateError("Paket tidak memuat forensik_core.py - bukan paket Forensik Runner.")


def apply_zip(data, app_dir, old_version, expected_sha256):
    """Verifikasi, cadangkan, dan timpa. Kembalikan (folder_cadangan, daftar_berkas_diperbarui, daftar_json_baru)."""
    if not expected_sha256:
        raise UpdateError("Rilis tidak menyertakan checksum SHA-256 - update ditolak demi keamanan.")
    got = hashlib.sha256(data).hexdigest()
    if got.lower() != expected_sha256.lower():
        raise UpdateError("Checksum tidak cocok (unduhan rusak atau diubah). Update dibatalkan.\nDiharapkan: %s\nDiperoleh : %s" % (expected_sha256, got))
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        raise UpdateError("Paket zip tidak valid.")
    infos = [i for i in z.infolist() if not i.is_dir()]
    if len(infos) > MAX_FILES:
        raise UpdateError("Paket memuat terlalu banyak berkas.")
    root = _find_root([i.filename for i in infos])
    plan, jsons = [], []
    base = os.path.realpath(app_dir)
    for i in infos:
        n = i.filename.replace("\\", "/")
        if not n.startswith(root):
            continue
        rel = n[len(root):]
        if not rel or rel.startswith("/") or ".." in rel.split("/") or ":" in rel:
            raise UpdateError("Paket memuat jalur tidak aman: %s" % n)
        top = rel.split("/")[0].lower()
        if top in ("__pycache__", BACKUP_DIR, "tools", "hasil_forensik", "dist") or rel.lower() == "config.json":
            continue
        ext = os.path.splitext(rel)[1].lower()
        dest = os.path.realpath(os.path.join(app_dir, *rel.split("/")))
        if not (dest == base or dest.startswith(base + os.sep)):
            raise UpdateError("Paket memuat jalur tidak aman: %s" % n)
        if ext in OVERWRITE_EXT:
            plan.append((i, rel, dest, False))
        elif ext in USER_JSON_OK_IF_MISSING:
            plan.append((i, rel, dest, True))
    if not any(r == "forensik_core.py" for _, r, _, _ in plan):
        raise UpdateError("Paket tidak lengkap.")
    stamp = time.strftime("%Y%m%d_%H%M%S")
    bdir = os.path.join(app_dir, BACKUP_DIR, "v%s_%s" % (old_version, stamp))
    updated = []
    for i, rel, dest, user_json in plan:
        if os.path.exists(dest):
            if user_json:
                dest = dest + ".baru"
                jsons.append(rel)
            else:
                bp = os.path.join(bdir, *rel.split("/"))
                os.makedirs(os.path.dirname(bp), exist_ok=True)
                shutil.copy2(dest, bp)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with z.open(i) as src, open(dest, "wb") as out:
            shutil.copyfileobj(src, out)
        updated.append(rel)
    os.makedirs(bdir, exist_ok=True)
    return bdir, updated, jsons


def list_backups(app_dir):
    d = os.path.join(app_dir, BACKUP_DIR)
    if not os.path.isdir(d):
        return []
    return sorted(x for x in os.listdir(d) if os.path.isdir(os.path.join(d, x)) and not x.startswith("dipulihkan_"))


def rollback(app_dir):
    """Pulihkan cadangan terbaru. Kembalikan nama cadangan yang dipulihkan."""
    b = list_backups(app_dir)
    if not b:
        raise UpdateError("Belum ada cadangan versi sebelumnya.")
    last = b[-1]
    src = os.path.join(app_dir, BACKUP_DIR, last)
    n = 0
    for dp, _, fs in os.walk(src):
        for f in fs:
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, src)
            dest = os.path.join(app_dir, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy2(p, dest)
            n += 1
    shutil.move(src, os.path.join(app_dir, BACKUP_DIR, "dipulihkan_" + last))
    return last, n


def download_and_apply(info, app_dir, old_version, token="", http_get=None):
    if not info.get("zip_url"):
        raise UpdateError("Rilis tidak memuat berkas .zip.")
    g = http_get or _http_get
    data = g(info["zip_url"], token, "application/octet-stream", MAX_ZIP, 120)
    return apply_zip(data, app_dir, old_version, info.get("sha256"))
