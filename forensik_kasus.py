# -*- coding: utf-8 -*-
"""Analisis tingkat-kasus (F20-F23): pengaitan USB, anomali, host/UNC, kata kunci kasus, validasi ke keluaran KAPE,
dan matriks uji bukti terisi sebagian. Semua keluaran adalah INDIKATOR untuk ditelaah pemeriksa, bukan simpulan."""
import collections, hashlib, os, re

import forensik_integrasi as ig

ACCESS_TOOLS = ("opensavefilesview", "shellbagsview", "lastactivityview", "previousfilesrecovery", "ofview")
_LET = re.compile(r"(?<![A-Za-z0-9])([A-Za-z]):[\\/]")
_UNC = re.compile(r"\\\\([^\\/\s|\"'?.][^\\/\s|\"']*)\\([^\\/\s|\"']+)")
_PATH = re.compile(r"([A-Za-z]:\\[^|\"\t]{3,}|\\\\[^\\/\s|\"]+\\[^|\"\t]{2,})")
KAPE_CAP_FILE = 150 * 1024 * 1024
KAPE_CAP_TOTAL = 600 * 1024 * 1024


def _fmt(t):
    return t.strftime("%d-%m-%Y %H:%M:%S") if t else "-"


def build_records(results):
    """Daftar rekaman datar: (key, judul, teks, waktu|None) dari seluruh baris semua alat."""
    recs = []
    for r in results:
        if not r["rows"]:
            continue
        h = r["header"]
        ti = None
        for pref in ig.TIME_PREF:
            ti = ig._find_col(h, pref)
            if ti is not None:
                break
        dayfirst = ig._detect_dayfirst([(row[ti] if ti < len(row) else "") for row in r["rows"]])[0] if ti is not None else True
        for row in r["rows"]:
            ts = ig.parse_ts(row[ti] if ti is not None and ti < len(row) else "", dayfirst) if ti is not None else None
            recs.append((r["key"], r["title"], ig._row_text(row), ts))
    return recs


def _short_hash(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for b in iter(lambda: f.read(1 << 20), b""):
                h.update(b)
        return h.hexdigest()[:16] + "..."
    except OSError:
        return "-"


def _usb_table(by, recs, notes):
    """Tabel huruf drive -> perangkat -> serial + anomali."""
    ud = by.get("usbdeview")
    dev, anomalies = [], []
    if ud and ud["rows"]:
        h = ud["header"]
        c = dict(name=ig._find_col(h, "device name"), desc=ig._find_col(h, "description"), conn=ig._find_col(h, "connected"),
                 let=ig._find_col(h, "drive letter"), ser=ig._find_col(h, "serial"), cre=ig._find_col(h, "created date"),
                 last=ig._find_col(h, "last plug"), typ=ig._find_col(h, "device type"))
        get = lambda row, k: (row[c[k]] if c[k] is not None and c[k] < len(row) else "").strip()
        cdf = ig._detect_dayfirst([get(r, "cre") for r in ud["rows"]])[0]
        ldf = ig._detect_dayfirst([get(r, "last") for r in ud["rows"]])[0]
        for row in ud["rows"]:
            txt = ig._row_text(row).lower()
            letters = [x.upper() for x in re.findall(r"([A-Za-z]):", get(row, "let"))] or \
                      [x.upper() for x in re.findall(r"^\s*([A-Za-z])\s*$", get(row, "let"))]
            storage = bool(letters) or "mass storage" in txt or "disk" in (get(row, "typ") + get(row, "desc")).lower()
            if not storage:
                continue
            dev.append(dict(name=get(row, "name") or get(row, "desc"), serial=get(row, "ser"), conn=get(row, "conn"),
                            letters=letters, created=ig.parse_ts(get(row, "cre"), cdf), created_s=get(row, "cre"),
                            last=ig.parse_ts(get(row, "last"), ldf), last_s=get(row, "last")))
    # jejak akses per huruf drive
    hits = collections.defaultdict(lambda: dict(n=0, first=None, last=None, tools=collections.Counter(), sample=[]))
    for key, title, text, ts in recs:
        if key not in ACCESS_TOOLS:
            continue
        for L in set(x.upper() for x in _LET.findall(text)):
            if L == "C":
                continue
            d = hits[L]; d["n"] += 1; d["tools"][title] += 1
            if ts:
                d["first"] = ts if d["first"] is None or ts < d["first"] else d["first"]
                d["last"] = ts if d["last"] is None or ts > d["last"] else d["last"]
            if len(d["sample"]) < 3:
                d["sample"].append(text[:160])
    dl = {}
    drv = by.get("driveletterview")
    if drv and drv["rows"]:
        h = drv["header"]; li = ig._find_col(h, "drive letter", "letter"); ty = ig._find_col(h, "drive type", "type")
        ci = ig._find_col(h, "connected")
        for row in drv["rows"]:
            m = re.match(r"\s*([A-Za-z])", row[li]) if li is not None and li < len(row) else None
            if m:
                dl[m.group(1).upper()] = ((row[ty] if ty is not None and ty < len(row) else "") + (
                    " / terhubung: " + row[ci] if ci is not None and ci < len(row) and row[ci] else "")).strip()
    by_letter = collections.defaultdict(list)
    for d in dev:
        for L in d["letters"]:
            by_letter[L].append(d)
    # tabel pengaitan
    rows = []
    for L in sorted(set(by_letter) | set(hits)):
        if L == "C":
            continue
        ds = by_letter.get(L, [])
        hd = hits.get(L)
        ident = "; ".join("%s (serial %s; terhubung: %s)" % (d["name"] or "-", d["serial"] or "-", d["conn"] or "-") for d in ds) or \
                "TIDAK terkait perangkat USB pada USBDeview"
        rows.append(dict(letter=L, ident=ident, dl=dl.get(L, "-"), n=hd["n"] if hd else 0,
                         first=hd["first"] if hd else None, last=hd["last"] if hd else None,
                         tools=", ".join("%s: %d" % kv for kv in hd["tools"].items()) if hd else "-",
                         sample=hd["sample"] if hd else [], devices=ds))
        # anomali (b) akses sebelum created
        for d in ds:
            if hd and hd["first"] and d["created"] and hd["first"] < d["created"]:
                anomalies.append(("%s:" % L, "Akses pada huruf %s: tercatat paling awal %s, SEBELUM waktu 'created' perangkat %s (%s). "
                                  "Perlu dijelaskan (mis. huruf dipakai perangkat lain, atau 'created' berubah karena driver dipasang ulang)." % (
                                      L, _fmt(hd["first"]), d["name"] or d["serial"], _fmt(d["created"]))))
        if len(ds) >= 2:
            anomalies.append(("%s:" % L, "Huruf %s: tercatat dipakai %d perangkat berbeda: %s. Huruf drive bukan identitas perangkat." % (
                L, len(ds), "; ".join(d["name"] or d["serial"] for d in ds))))
        if hd and not ds:
            anomalies.append(("%s:" % L, "Ada %d jejak akses pada huruf %s: tetapi tidak terkait perangkat USB mana pun (DriveLetterView: %s). "
                              "Dapat berupa drive jaringan terpetakan, drive virtual, atau perangkat yang tidak tercatat; "
                              "uji dengan MountPoints2/Map Network Drive MRU." % (hd["n"], L, dl.get(L, "tidak terdaftar"))))
    # (a) created identik
    grp = collections.defaultdict(list)
    for d in dev:
        if d["created"]:
            grp[d["created"]].append(d)
    for t, ds in grp.items():
        if len(ds) >= 3:
            anomalies.append(("created identik", "%d perangkat memiliki waktu 'created' identik (%s): %s. Lebih mungkin pembaruan registry "
                              "massal (mis. update Windows) daripada koneksi pertama." % (
                                  len(ds), _fmt(t), ", ".join((d["name"] or "?") + "/" + (d["serial"] or "?")[-6:] for d in ds))))
    # (c) tanpa huruf, (d) serial tidak unik
    for d in dev:
        if not d["letters"] and d["serial"]:
            anomalies.append(("tanpa huruf drive", "Perangkat penyimpan '%s' (serial %s) tercatat tanpa huruf drive; media ini perlu diidentifikasi "
                              "dan dipertimbangkan pada kelengkapan perolehan (P3)." % (d["name"] or "-", d["serial"])))
        if len(d["serial"]) > 1 and d["serial"][1] == "&":
            anomalies.append(("serial tidak unik", "Perangkat '%s' memiliki serial '%s' (karakter kedua '&'): serial dibuat Windows, bukan "
                              "serial pabrikan, sehingga perlu koroborasi tambahan." % (d["name"] or "-", d["serial"])))
    return rows, anomalies, dev


def _unc_table(recs):
    agg = {}
    for key, title, text, ts in recs:
        for host, share in _UNC.findall(text):
            if host in ("?", ".", "*"):
                continue
            a = agg.setdefault(host.lower(), dict(host=host, shares=collections.Counter(), tools=collections.Counter(), n=0,
                                                   first=None, last=None, sample=text[:150]))
            a["n"] += 1; a["shares"][share] += 1; a["tools"][title] += 1
            if ts:
                a["first"] = ts if a["first"] is None or ts < a["first"] else a["first"]
                a["last"] = ts if a["last"] is None or ts > a["last"] else a["last"]
    out = sorted(agg.values(), key=lambda x: -x["n"])[:40]
    for a in out:
        a["is_ip"] = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", a["host"]))
    return out


def _smb_table(by):
    """Koneksi SMB aktif (CurrPorts): remote port 445/139 -> host, proses, status."""
    r = by.get("cports")
    if not r or not r["rows"]:
        return []
    h = r["header"]
    rp, ra, pn, stt, rh = (ig._find_col(h, "remote port"), ig._find_col(h, "remote address"), ig._find_col(h, "process name"),
                           ig._find_col(h, "state"), ig._find_col(h, "remote host"))
    if rp is None or ra is None:
        return []
    agg = {}
    for row in r["rows"]:
        port = (row[rp] if rp < len(row) else "").strip().lower()
        if port.split()[0:1] not in (["445"], ["139"]) and port not in ("microsoft-ds", "netbios-ssn"):
            continue
        addr = (row[ra] if ra < len(row) else "").strip()
        if not addr:
            continue
        key = (addr, (row[pn] if pn is not None and pn < len(row) else ""))
        a = agg.setdefault(key, dict(addr=addr, proc=key[1], n=0, state=set(), host=(row[rh] if rh is not None and rh < len(row) else "")))
        a["n"] += 1
        if stt is not None and stt < len(row) and row[stt]:
            a["state"].add(row[stt])
    return sorted(agg.values(), key=lambda x: -x["n"])[:30]


def _case_keywords(recs, terms):
    out = []
    for term in terms:
        t = term.lower()
        per = collections.Counter(); first = last = None; samples = []; n = 0
        for key, title, text, ts in recs:
            if t in text.lower():
                n += 1; per[title] += 1
                if ts:
                    first = ts if first is None or ts < first else first
                    last = ts if last is None or ts > last else last
                if len(samples) < 8:
                    samples.append((title, text[:170]))
        out.append(dict(term=term, n=n, per=dict(per), first=first, last=last, samples=samples))
    return out


def _leads(usb_rows, unc, terms, dev):
    """Petunjuk NirSoft yang akan dicari pada keluaran KAPE: (jenis, nilai)."""
    leads, seen = [], set()
    def add(kind, v):
        v = (v or "").strip().rstrip("\\ ")
        k = v.lower()
        if len(k) >= 5 and k not in seen and len(leads) < 250:
            seen.add(k); leads.append((kind, v))
    for r in usb_rows:
        if r["n"]:
            for s in r["sample"]:
                for p in _PATH.findall(s):
                    add("path", p)
    for a in unc:
        add("host/UNC", "\\\\" + a["host"] + "\\" + (a["shares"].most_common(1)[0][0] if a["shares"] else ""))
    for d in dev:
        if d["serial"] and len(d["serial"]) >= 6 and d["serial"][1:2] != "&":
            add("serial USB", d["serial"])
    for t in terms:
        add("kata kunci kasus", t)
    return leads


def _validate_kape(leads, kape_m):
    """Cari tiap petunjuk di seluruh CSV keluaran modul KAPE (streaming). Hanya status & kecocokan teks."""
    info = dict(ran=False, files=0, bytes=0, truncated=False, rows=[])
    if not kape_m or not os.path.isdir(kape_m) or not leads:
        return info
    files = []
    for dp, _, fns in os.walk(kape_m):
        for fn in fns:
            if fn.lower().endswith(".csv"):
                files.append(os.path.join(dp, fn))
    if not files:
        return info
    info["ran"] = True
    rx = re.compile("|".join(re.escape(v.lower()) for _, v in sorted(leads, key=lambda x: -len(x[1]))))
    idx = {v.lower(): i for i, (_, v) in enumerate(leads)}
    mods = [collections.defaultdict(collections.Counter) for _ in leads]
    cnt = [0] * len(leads); samp = [""] * len(leads)
    total = 0
    for p in files:
        try:
            size = os.path.getsize(p)
        except OSError:
            continue
        if size > KAPE_CAP_FILE or total + size > KAPE_CAP_TOTAL:
            info["truncated"] = True; continue
        total += size; info["files"] += 1
        rel = os.path.relpath(p, kape_m).split(os.sep)
        mod = "/".join(rel[:-1][:2]) or rel[0]
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    low = line.lower()
                    for m in set(rx.findall(low)):
                        i = idx.get(m)
                        if i is None:
                            continue
                        cnt[i] += 1; mods[i][mod][os.path.basename(p)] += 1
                        if not samp[i]:
                            samp[i] = line.strip()[:200]
        except OSError:
            continue
    info["bytes"] = total
    for i, (kind, v) in enumerate(leads):
        info["rows"].append(dict(kind=kind, lead=v, ok=cnt[i] > 0, n=cnt[i],
                                 mods=", ".join("%s (%d)" % (m, sum(c.values())) for m, c in sorted(mods[i].items(), key=lambda x: -sum(x[1].values()))[:4]) or "-",
                                 sample=samp[i]))
    return info


def _matrix(usb_rows, unc, ckw, val, by, osi_user, user_nama):
    """Matriks Uji Bukti terisi sebagian; Kontradiksi (sebagian) dan Kesimpulan oleh pemeriksa."""
    def tool_ver(*keys):
        out = []
        for k in keys:
            r = by.get(k)
            if r:
                out.append("%s %s" % (r["title"], (r["bin"] or {}).get("version") or "versi ?"))
        return "; ".join(out)
    def file_hash(*keys):
        out = []
        for k in keys:
            r = by.get(k)
            if r and r.get("files"):
                out.append("%s: %s" % (os.path.basename(r["files"][0]), _short_hash(r["files"][0])))
        return "\n".join(out) or "-"
    vmap = {}
    for v in (val or {}).get("rows", []):
        vmap[v["lead"].lower()] = v
    attrib = "Akun Windows pelaksana: %s; pengguna perangkat (petugas): %s. Atribusi ke akun lain perlu bukti tambahan." % (osi_user, user_nama)
    rows = []
    def corr_for(vals):
        ok = [v for v in vals if v and v["ok"]]
        if not (val or {}).get("ran"):
            return "Belum divalidasi (keluaran parser KAPE belum ada)."
        return ("Terkonfirmasi teks pada: " + "; ".join("%s -> %s" % (v["lead"][:50], v["mods"]) for v in ok[:3])) if ok else \
               "Tidak ditemukan pada keluaran KAPE (ketiadaan bukan bukti ketiadaan)."
    for r in usb_rows:
        if not r["n"] and not r["devices"]:
            continue
        sers = [d["serial"] for d in r["devices"] if d["serial"]]
        vals = [vmap.get(s.lower()) for s in sers] + [vmap.get(p.lower().rstrip("\\ ")) for s in r["sample"] for p in _PATH.findall(s)]
        rows.append(("Folder/berkas pada huruf %s: berada pada media eksternal tertentu (identifikasi media)" % r["letter"],
                     "%s\nJejak akses: %d (%s - %s)\n%s" % (r["ident"], r["n"], _fmt(r["first"]), _fmt(r["last"]), r["tools"]),
                     file_hash("usbdeview", "lastactivityview", "opensavefilesview", "shellbagsview"),
                     tool_ver("usbdeview", "lastactivityview", "opensavefilesview", "shellbagsview"),
                     attrib, corr_for(vals),
                     "Lihat anomali pada bab integrasi bagian pengaitan USB." if (r["devices"] and len(r["devices"]) > 1) or not r["devices"] else "-"))
    for a in unc[:6]:
        v = vmap.get(("\\\\" + a["host"] + "\\" + (a["shares"].most_common(1)[0][0] if a["shares"] else "")).lower())
        rows.append(("Akses ke share jaringan \\\\%s (%s) dapat dikaitkan ke perangkat dan pengguna tertentu" % (a["host"], "IP" if a["is_ip"] else "nama host"),
                     "%d jejak (%s - %s); share: %s" % (a["n"], _fmt(a["first"]), _fmt(a["last"]), ", ".join(a["shares"].keys())[:80]),
                     file_hash("shellbagsview", "lastactivityview"), tool_ver("shellbagsview", "lastactivityview"), attrib, corr_for([v]),
                     "Identifikasi perangkat (pemindaian jaringan/DHCP/ARP) di luar aplikasi."))
    for k in ckw:
        if not k["n"]:
            continue
        v = vmap.get(k["term"].lower())
        rows.append(("Kata kunci kasus '%s' muncul pada aktivitas komputer" % k["term"],
                     "%d rekaman (%s - %s): %s" % (k["n"], _fmt(k["first"]), _fmt(k["last"]), ", ".join("%s %d" % kv for kv in k["per"].items())),
                     file_hash(*[kk for kk, r in by.items() if r["title"] in k["per"]][:3]),
                     tool_ver(*[kk for kk, r in by.items() if r["title"] in k["per"]][:3]), attrib, corr_for([v]),
                     "Riwayat membuktikan akses ke URL/folder, bukan isi transaksi."))
    return rows[:24]


def analyze_kasus(results, case, integ, kape_m=None, osi_user=""):
    by = {r["key"]: r for r in results}
    recs = build_records(results)
    notes = []
    usb_rows, anomalies, dev = _usb_table(by, recs, notes)
    unc = _unc_table(recs)
    smb = _smb_table(by)
    terms = [t.strip() for t in (case.get("kata_kunci_kasus") or []) if t.strip()]
    ckw = _case_keywords(recs, terms)
    leads = _leads(usb_rows, unc, terms, dev)
    val = _validate_kape(leads, kape_m)
    matrix = _matrix(usb_rows, unc, ckw, val, by, osi_user or "-", case.get("user_nama") or "-")
    return dict(smb=smb, usb_rows=usb_rows, anomalies=anomalies, unc=unc, case_kw=ckw, terms=terms, leads=leads, val=val, matrix=matrix,
                n_recs=len(recs))
