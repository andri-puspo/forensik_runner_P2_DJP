# -*- coding: utf-8 -*-
"""Integrasi lintas alat: matriks cakupan, lini masa terpadu, korelasi USB, jejak drive eksternal, indikator kata kunci.
Hanya mengolah data hasil alat apa adanya; semua keluaran adalah INDIKATOR untuk ditelaah pemeriksa, bukan simpulan."""
import collections, datetime as dt, json, os, re

DEFAULT_KEYWORDS = {
    "Penyimpanan awan / transfer berkas": ["drive.google.com", "docs.google.com", "dropbox", "onedrive", "sharepoint.com", "mega.nz",
                                           "mega.io", "wetransfer", "icloud.com", "box.com", "4shared", "mediafire"],
    "Platform aset kripto / dompet": ["binance", "indodax", "tokocrypto", "pintu.co.id", "pluang", "reku.id", "coinbase", "kraken.com",
                                      "okx.com", "bybit", "kucoin", "huobi", "metamask", "trustwallet", "etherscan", "bscscan",
                                      "uniswap", "pancakeswap", "coinmarketcap", "coingecko", "ledger.com", "trezor", "wallet.dat"],
    "Marketplace / e-commerce": ["tokopedia", "shopee", "lazada", "bukalapak", "blibli", "shop.tiktok", "sellercenter", "seller.shopee",
                                 "mp.weixin", "alibaba", "amazon.", "olx.co.id"],
    "Perbankan & pembayaran online": ["klikbca", "bca.co.id", "ibank.bankmandiri", "bankmandiri", "livin", "bri.co.id", "bni.co.id",
                                      "cimbniaga", "permatabank", "paypal", "wise.com", "payoneer", "ovo.id", "gopay", "dana.id"],
    "Layanan perpajakan": ["pajak.go.id", "ereg.pajak", "djponline", "efaktur", "coretax", "ebupot", "e-bupot", "ebilling"],
    "Dokumen pembukuan / keuangan (nama berkas)": ["faktur", "invoice", "kwitansi", "jurnal", "ledger", "buku besar", "laporan keuangan",
                                                   "neraca", "laba rugi", "rekening koran", "mutasi", "bukti potong", "pembukuan",
                                                   "payroll", "penggaji", "rekonsiliasi", "general ledger", "trial balance"],
    "Aplikasi pembersih / penyembunyi jejak": ["ccleaner", "bleachbit", "eraser", "sdelete", "veracrypt", "truecrypt", "tor browser",
                                               "torbrowser", "cipher /w", "privazer", "wipe", "shredder", "dban", "vpn"],
    "Frasa pencarian penghapusan / penyembunyian data": ["cara hapus", "hapus transaksi", "hapus data", "hapus permanen", "hapus riwayat",
                                                         "hapus log", "delete transaction", "delete history", "clear history",
                                                         "clear browsing", "recover deleted", "anti forensic", "sembunyikan data"],
}
KW_FILE = "indikator_kata_kunci.json"

TIME_PREF = ["visit time", "last visit", "visit date", "last visited", "action time", "last plug", "plug time", "last access", "accessed", "modified time", "last write",
             "created date", "created time", "modified", "created", "time", "date"]

THEMES = [
    ("Perangkat USB / media eksternal", ["usbdeview", "usbdrivelog", "usblogview", "driveletterview"]),
    ("Riwayat penggunaan internet", ["browsinghistoryview", "chromehistoryview", "mozillahistoryview", "iehv"]),
    ("Berkas yang dibuka / disimpan", ["opensavefilesview", "lastactivityview", "ofview"]),
    ("Folder yang pernah diakses (termasuk yang sudah tidak ada)", ["shellbagsview"]),
    ("Berkas terhapus / versi sebelumnya", ["previousfilesrecovery"]),
    ("Aktivitas pengguna & sistem (lini masa)", ["lastactivityview"]),
    ("Konfigurasi jaringan, koneksi aktif & IP publik", ["networkinterfacesview", "cports", "ipnetinfo", "sysexp"]),
]

_TS = re.compile(r"(\d{1,4})[/.\-](\d{1,2})[/.\-](\d{1,4})(?:[ T,]+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?\s*([AaPp][Mm])?)?")


def load_keywords(app_dir):
    p = os.path.join(app_dir, KW_FILE)
    try:
        d = json.load(open(p, encoding="utf-8"))
        if isinstance(d, dict) and d:
            kw = {k: [x for x in v if x] for k, v in d.items() if isinstance(v, list)}
            return kw, kw != DEFAULT_KEYWORDS
    except Exception:
        pass
    return DEFAULT_KEYWORDS, False


def write_default_keywords(app_dir):
    p = os.path.join(app_dir, KW_FILE)
    if not os.path.exists(p):
        json.dump(DEFAULT_KEYWORDS, open(p, "w", encoding="utf-8"), indent=2, ensure_ascii=False)


def _find_col(header, *cands):
    low = [h.lower() for h in header]
    for c in cands:
        for i, h in enumerate(low):
            if c in h:
                return i
    return None


def _detect_dayfirst(values):
    a12 = b12 = False
    for v in values[:3000]:
        m = _TS.search(v or "")
        if not m or len(m.group(1)) == 4:
            continue
        a12 |= int(m.group(1)) > 12
        b12 |= int(m.group(2)) > 12
    if a12 and not b12:
        return True, "pasti dd/mm"
    if b12 and not a12:
        return False, "pasti mm/dd"
    return True, "ASUMSI dd/mm (tidak dapat dipastikan dari data)"


def parse_ts(s, dayfirst):
    m = _TS.search(s or "")
    if not m:
        return None
    x, y, z, hh, mi, ss, ap = m.groups()
    try:
        if len(x) == 4:
            Y, M, D = int(x), int(y), int(z)
        else:
            a, b, Y = int(x), int(y), int(z)
            D, M = (a, b) if dayfirst else (b, a)
            if Y < 100:
                Y += 2000
        h = int(hh or 0)
        if ap:
            h = h % 12 + (12 if ap.lower() == "pm" else 0)
        return dt.datetime(Y, M, D, h, int(mi or 0), int(ss or 0))
    except (ValueError, TypeError):
        return None


def _row_text(row):
    return " | ".join(c for c in row if c)


def _serials(res, colnames=("serial",)):
    out = {}
    if not res or not res["rows"]:
        return out
    h = res["header"]
    ci = _find_col(h, *colnames)
    ni = _find_col(h, "device name", "description", "device model", "product", "model")
    ti = _find_col(h, "last plug", "plug time", "created date")
    if ci is None:
        return out
    for r in res["rows"]:
        sn = (r[ci] if ci < len(r) else "").strip()
        if len(sn) < 4 or set(sn) <= {"0"}:
            continue
        out[sn.lower()] = dict(serial=sn, name=(r[ni] if ni is not None and ni < len(r) else ""),
                               time=(r[ti] if ti is not None and ti < len(r) else ""))
    return out


def analyze(results, hw=None, app_dir=None, max_timeline=300, tools_meta=None):
    by = {r["key"]: r for r in results}
    titles = {r["key"]: r["title"] for r in results}
    out = dict(notes=[])
    # ---- 1. matriks cakupan
    cov = []
    for tema, keys in THEMES:
        parts, total = [], 0
        for k in keys:
            r = by.get(k)
            if not r:
                parts.append("%s: tidak dijalankan" % titles.get(k, k)); continue
            n = len(r["rows"]) if r["rows"] else (len(r["raw_text"].splitlines()) if r["raw_text"] else 0)
            total += n
            parts.append("%s: %s (%d)" % (r["title"], r["status"], n))
        cov.append((tema, "\n".join(parts), total))
    out["coverage"] = cov
    # ---- 2. lini masa terpadu
    events, per_tool = [], []
    for r in results:
        if not r["rows"]:
            continue
        h = r["header"]
        ti = None
        for pref in TIME_PREF:
            ti = _find_col(h, pref)
            if ti is not None:
                break
        if ti is None:
            continue
        vals = [row[ti] if ti < len(row) else "" for row in r["rows"]]
        dayfirst, how = _detect_dayfirst(vals)
        # kolom ringkasan
        meta_cols = (tools_meta or {}).get(r["key"], [])
        si = []
        for pref in meta_cols:
            for i, name in enumerate(h):
                if pref in name.lower() and i != ti and i not in si:
                    si.append(i); break
        if not si:
            si = [i for i in range(len(h)) if i != ti][:3]
        n_ok = 0; first = last = None
        for row in r["rows"]:
            t = parse_ts(row[ti] if ti < len(row) else "", dayfirst)
            if not t:
                continue
            n_ok += 1
            first = t if first is None or t < first else first
            last = t if last is None or t > last else last
            events.append((t, r["title"], " | ".join((row[i] if i < len(row) else "")[:90] for i in si[:3] if i < len(row) and row[i])))
        per_tool.append((r["title"], h[ti], len(r["rows"]), n_ok, first, last, how))
    events.sort(key=lambda e: e[0])
    out["timeline_total"] = len(events)
    out["timeline_all"] = list(reversed(events))
    out["timeline"] = list(reversed(events[-max_timeline:]))        # terbaru lebih dulu
    out["timeline_tools"] = per_tool
    # ---- 3. korelasi serial USB
    ud, dl = _serials(by.get("usbdeview")), _serials(by.get("usbdrivelog"))
    ulog = by.get("usblogview")
    log_text = (ulog["raw_text"].lower() if ulog and ulog.get("raw_text") else "")
    cross = []
    for k in sorted(set(ud) | set(dl)):
        a, b = ud.get(k), dl.get(k)
        cross.append(((a or b)["serial"], (a or b)["name"], "ya" if a else "-", "ya" if b else "-",
                      "ya" if (log_text and k in log_text) else "-", (a or b)["time"]))
    out["usb_cross"] = cross
    out["usb_cross_both"] = sum(1 for k in set(ud) & set(dl))
    # ---- 4. huruf drive eksternal -> jejak akses berkas
    letters = set()
    drv = by.get("driveletterview")
    if drv and drv["rows"]:
        h = drv["header"]; li = _find_col(h, "drive letter", "letter"); ty = _find_col(h, "drive type", "type")
        for row in drv["rows"]:
            t = (row[ty] if ty is not None and ty < len(row) else "").lower()
            if li is not None and li < len(row) and any(w in t for w in ("removable", "usb", "external")):
                m = re.match(r"\s*([A-Za-z])", row[li])
                if m:
                    letters.add(m.group(1).upper())
    if ud:
        pass
    udr = by.get("usbdeview")
    if udr and udr["rows"]:
        h = udr["header"]; li = _find_col(h, "drive letter")
        if li is not None:
            for row in udr["rows"]:
                m = re.match(r"\s*([A-Za-z]):?", row[li] if li < len(row) else "")
                if m:
                    letters.add(m.group(1).upper())
    letters.discard("C")
    hits = []
    if letters:
        rx = re.compile(r"(?<![A-Za-z])([%s]):[\\/]" % "".join(sorted(letters)), re.I)
        for k in ("opensavefilesview", "shellbagsview", "lastactivityview", "previousfilesrecovery", "ofview"):
            r = by.get(k)
            if not r or not r["rows"]:
                continue
            for row in r["rows"]:
                t = _row_text(row)
                if rx.search(t):
                    hits.append((r["title"], t[:200]))
    out["removable_letters"] = sorted(letters)
    out["ext_hits"] = len(hits)
    out["ext_samples"] = hits[:40]
    # ---- 5. indikator kata kunci
    kws, custom = load_keywords(app_dir or ".")
    out["kw_custom"] = custom
    kwres = []
    sources = [(r["title"], r["rows"], r["header"]) for r in results if r["rows"]
               and r["key"] in ("browsinghistoryview", "chromehistoryview", "mozillahistoryview", "iehv", "opensavefilesview", "lastactivityview", "shellbagsview",
                                "previousfilesrecovery", "usbdeview", "ofview", "cports")]
    texts = [(t, _row_text(row)) for t, rows, _ in sources for row in rows]
    low = [(t, s.lower(), s) for t, s in texts]
    for cat, words in kws.items():
        if not words:
            continue
        rx = re.compile("|".join(re.escape(w.lower()) for w in sorted(set(words), key=len, reverse=True)))
        cnt = collections.Counter(); per = collections.Counter(); samples = []; rows_hit = 0
        for t, l, s in low:
            ms = rx.findall(l)
            if ms:
                rows_hit += 1; per[t] += 1
                for w in set(ms):
                    cnt[w] += 1
                if len(samples) < 12:
                    samples.append((t, s[:170]))
        kwres.append(dict(cat=cat, rows=rows_hit, top=cnt.most_common(8), per_tool=dict(per), samples=samples))
    out["keywords"] = kwres
    out["records_scanned"] = len(texts)
    out["notes"] = [
        "Seluruh keluaran bab ini adalah INDIKATOR untuk ditelaah pemeriksa; kecocokan kata kunci atau korelasi bukan bukti dan bukan simpulan.",
        "Lini masa memakai nilai waktu apa adanya dari tiap alat (zona waktu perangkat: %s). Format tanggal ditentukan per kolom; bila tidak pasti dipakai asumsi dd/mm." % (
            ((hw or {}).get("tz") or {}).get("id") or "tidak diketahui"),
        "Daftar kata kunci %s (%s)." % ("dimuat dari berkas kustom yang telah diubah" if custom else "bawaan aplikasi, belum diubah", KW_FILE),
    ]
    return out


def export_csv(ig, outdir):
    """Simpan data lengkap integrasi ke Data_Mentah."""
    import csv, os
    def w(name, header, rows):
        with open(os.path.join(outdir, name), "w", newline="", encoding="utf-8-sig") as f:
            c = csv.writer(f); c.writerow(header); c.writerows(rows)
    w("Integrasi_Linimasa.csv", ["waktu", "alat", "keterangan"],
      [(t.strftime("%Y-%m-%d %H:%M:%S"), a, d) for t, a, d in ig["timeline_all"]])
    w("Integrasi_USB.csv", ["serial", "nama", "USBDeview", "USBDriveLog", "USBLogView", "waktu"], ig["usb_cross"])
    w("Integrasi_Kata_Kunci.csv", ["kategori", "alat", "rekaman"],
      [(k["cat"], a, b) for k in ig["keywords"] for a, b in k["samples"]])


def export_kasus_csv(ks, outdir):
    """Simpan tabel analisis kasus ke Data_Mentah."""
    import csv
    def w(name, header, rows):
        with open(os.path.join(outdir, name), "w", newline="", encoding="utf-8-sig") as f:
            c = csv.writer(f); c.writerow(header); c.writerows(rows)
    w("Kasus_Pengaitan_USB.csv", ["huruf", "identitas_perangkat", "driveletterview", "jumlah_jejak", "awal", "akhir", "alat"],
      [(r["letter"], r["ident"], r["dl"], r["n"], r["first"], r["last"], r["tools"]) for r in ks["usb_rows"]])
    w("Kasus_Anomali_USB.csv", ["objek", "uraian"], ks["anomalies"])
    w("Kasus_Host_UNC.csv", ["host", "jenis", "share", "jumlah", "awal", "akhir", "alat"],
      [(a["host"], "IP" if a["is_ip"] else "nama host", ", ".join(a["shares"]), a["n"], a["first"], a["last"], ", ".join(a["tools"])) for a in ks["unc"]])
    w("Kasus_Kata_Kunci.csv", ["kata_kunci", "jumlah", "awal", "akhir", "per_alat"],
      [(k["term"], k["n"], k["first"], k["last"], "; ".join("%s=%d" % kv for kv in k["per"].items())) for k in ks["case_kw"]])
    w("Kasus_Validasi_KAPE.csv", ["jenis", "petunjuk", "terkonfirmasi", "kecocokan", "modul", "contoh"],
      [(v["kind"], v["lead"], "ya" if v["ok"] else "belum", v["n"], v["mods"], v["sample"]) for v in ks["val"]["rows"]])
