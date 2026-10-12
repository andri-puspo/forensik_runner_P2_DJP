# -*- coding: utf-8 -*-
"""Integrasi KAPE: deteksi, pemeriksaan kelengkapan modul, dan eksekusi terkontrol (opsional)."""
import collections, csv, datetime as dt, hashlib, os, re, shutil, struct, subprocess, sys, time

IS_WIN = sys.platform == "win32"

LIVE_MODULES = [
    "Windows_IPConfig", "Windows_DNSCache", "Windows_ARPCache", "Windows_RoutingTable", "Windows_NetStat",
    "Windows_nbtstat_NetBIOSSessions", "Windows_nbtstat_NetBIOSCache", "Windows_netsh_portproxy",
    "Windows_Net_User", "Windows_Net_LocalGroup", "Windows_Net_Accounts", "Windows_Net_File",
    "Windows_Net_Session", "Windows_Net_Use", "Windows_Net_Start", "Windows_Net_Share",
    "Windows_SystemInfo", "Windows_MsInfo", "Windows_schtasks", "Windows_qwinsta_RDPSessions", "Windows_GpResult",
    "Windows_ManageBDE_BitLockerStatus",           # status saja; BitLockerKeys SENGAJA tidak dimasukkan
    "PowerShell_ProcessList_WMI", "PowerShell_ProcessList_CimInstance", "PowerShell_Startup_Commands",
    "PowerShell_NetUserAdministrators", "PowerShell_Defender_Exclusions",
]
EXCLUDED_ALWAYS = {"windows_managebde_bitlockerkeys"}   # mengekspor kunci pemulihan BitLocker -> tidak pernah otomatis

PROFILES = {
    "live": dict(label="Live Response - jaringan, akun, proses, sistem (tidak menyalin artefak)", targets=[], modules=LIVE_MODULES),
    "triage": dict(label="Triage cepat - !BasicCollection + !EZParser", targets=["!BasicCollection"], modules=["!EZParser"]),
    "sans": dict(label="SANS Triage - !SANS_Triage + !EZParser", targets=["!SANS_Triage"], modules=["!EZParser"]),
    "kapetriage": dict(label="KapeTriage - KapeTriage + !EZParser", targets=["KapeTriage"], modules=["!EZParser"]),
    "custom": dict(label="Kustom - target/modul dipilih petugas", targets=[], modules=[]),
}


def _pe_bits(path):
    try:
        d = open(path, "rb").read(4096)
        o = struct.unpack_from("<I", d, 0x3C)[0]
        m = struct.unpack_from("<H", d, o + 4)[0]
        return {0x14C: 32, 0x8664: 64, 0xAA64: 64}.get(m)
    except Exception:
        return None


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def find_kape(tools_dir):
    """Cari folder yang berisi kape.exe (kedalaman <= 3). Mengembalikan root atau None."""
    if not tools_dir or not os.path.isdir(tools_dir):
        return None
    base_depth = tools_dir.rstrip(os.sep).count(os.sep)
    for dp, dns, fns in os.walk(tools_dir):
        if dp.count(os.sep) - base_depth > 3:
            dns[:] = []
            continue
        for f in fns:
            if f.lower() == "kape.exe":
                return dp
    return None


def _read(path):
    return open(path, encoding="utf-8", errors="replace").read()


def _scan_modules(root):
    mods, bins = {}, {}
    for dp, _, fns in os.walk(os.path.join(root, "Modules", "bin")):
        for f in fns:
            bins.setdefault(f.lower(), os.path.join(dp, f))
    mroot = os.path.join(root, "Modules")
    for dp, dns, fns in os.walk(mroot):
        rel = os.path.relpath(dp, mroot).replace("\\", "/")
        if rel == "bin" or rel.startswith("bin/"):
            dns[:] = []
            continue
        for f in fns:
            if not f.lower().endswith(".mkape"):
                continue
            txt = _read(os.path.join(dp, f))
            name = f[:-6]
            execs = [e.strip().strip("'\"") for e in re.findall(r"^\s*-?\s*Executable:\s*(.+?)\s*$", txt, re.M)]
            url = re.search(r"^BinaryUrl:\s*(\S+)", txt, re.M)
            desc = re.search(r"^Description:\s*(.+?)\s*$", txt, re.M)
            group = rel if rel != "." else "(root)"
            parts = group.split("/")
            disabled = parts[0] in ("!Disabled",)
            mods[name.lower()] = dict(name=name, path=os.path.join(dp, f), group="/".join(parts[:2]) if parts[0] != "Compound" else "Compound",
                                      execs=execs, url=url.group(1) if url else "", desc=desc.group(1).strip("'\"") if desc else "",
                                      disabled=disabled, local=(parts[0] == "!Local"))
    return mods, bins


def _ready(mods, bins, key, memo, stack=()):
    """(siap:bool, daftar_biner_kurang) - menelusuri modul compound secara rekursif."""
    if key in memo:
        return memo[key]
    m = mods.get(key)
    if m is None:
        return (False, ["(modul %s tidak ditemukan)" % key])
    if key in stack:
        return (True, [])
    missing = []
    for ex in m["execs"]:
        e = ex.replace("\\", "/")
        b = os.path.basename(e)
        if b.lower().endswith(".mkape"):
            ok, ms = _ready(mods, bins, b[:-6].lower(), memo, stack + (key,))
            missing += ms
        elif re.match(r"^([a-zA-Z]:/|%)", e):
            if IS_WIN and not os.path.exists(os.path.expandvars(ex)):
                missing.append(b + " (sistem)")
        elif b.lower() not in bins:
            missing.append(b)
    memo[key] = (not missing, sorted(set(missing)))
    return memo[key]


def inspect_kape(root):
    """Periksa kelengkapan KAPE. Hanya membaca."""
    info = dict(root=root, issues=[])
    exe = os.path.join(root, "kape.exe")
    info["exe"] = exe
    info["exe_sha256"] = _sha256(exe) if os.path.exists(exe) else ""
    info["exe_bits"] = _pe_bits(exe)
    gk = os.path.join(root, "gkape.exe")
    info["gkape"] = os.path.exists(gk)
    info["gkape_bits"] = _pe_bits(gk) if info["gkape"] else None
    ver = ""
    cl = os.path.join(root, "ChangeLog.txt")
    if os.path.exists(cl):
        for line in _read(cl).splitlines():
            if re.match(r"^\d+(\.\d+){2,3}\s*$", line.strip()):
                ver = line.strip(); break
    info["version"] = ver or "tidak diketahui"
    info["has_update_script"] = os.path.exists(os.path.join(root, "Get-KAPEUpdate.ps1"))
    info["has_docs"] = os.path.exists(os.path.join(root, "Documentation", "DocumentationAndEULA.txt"))
    # targets
    t_all, t_comp = {}, {}
    troot = os.path.join(root, "Targets")
    for dp, dns, fns in os.walk(troot):
        rel = os.path.relpath(dp, troot).replace("\\", "/")
        if rel.split("/")[0] in ("!Disabled", "!Local"):
            dns[:] = []
            continue
        for f in fns:
            if f.lower().endswith(".tkape"):
                t_all[f[:-6].lower()] = f[:-6]
                if rel == "Compound":
                    t_comp[f[:-6].lower()] = f[:-6]
    info["targets"], info["targets_compound"] = t_all, t_comp
    if not t_all:
        info["issues"].append("Folder Targets kosong/tidak ada.")
    # modules
    if not os.path.isdir(os.path.join(root, "Modules")):
        info["issues"].append("Folder Modules tidak ada.")
        info.update(mods={}, bins={}, groups=[], missing_bins=[], ready_names=set())
        return info
    mods, bins = _scan_modules(root)
    memo, groups = {}, collections.OrderedDict()
    missing_bins = collections.defaultdict(lambda: dict(count=0, url=""))
    ready_names = set()
    for k, m in sorted(mods.items()):
        if m["disabled"]:
            continue
        ok, ms = _ready(mods, bins, k, memo)
        m["ready"], m["missing"] = ok, ms
        g = groups.setdefault(m["group"], dict(total=0, ready=0, missing=collections.Counter()))
        g["total"] += 1
        g["ready"] += int(ok)
        if ok:
            ready_names.add(m["name"].lower())
        for b in ms:
            g["missing"][b] += 1
            missing_bins[b]["count"] += 1
            # sumber unduhan: BinaryUrl modul langsung yang memakai biner tsb
            if not missing_bins[b]["url"] and m["url"] and b.lower().replace(" (sistem)", "") in " ".join(m["execs"]).lower():
                missing_bins[b]["url"] = m["url"]
    info["mods"], info["bins"] = mods, bins
    info["groups"] = [(k, v["total"], v["ready"], dict(v["missing"].most_common(3))) for k, v in sorted(groups.items())]
    info["missing_bins"] = sorted(((k, v["count"], v["url"]) for k, v in missing_bins.items()), key=lambda x: -x[1])
    info["ready_names"] = ready_names
    info["n_modules"] = sum(v["total"] for v in groups.values())
    info["n_ready"] = sum(v["ready"] for v in groups.values())
    info["n_disabled"] = sum(1 for m in mods.values() if m["disabled"])
    info["bin_exes"] = sorted(f for f in bins if f.endswith(".exe"))
    if not info["bin_exes"]:
        info["issues"].append("Modules\\bin tidak berisi biner (.exe).")
    if not info["gkape"]:
        info["issues"].append("gkape.exe (GUI) tidak ada - tidak berpengaruh untuk Forensik Runner.")
    return info


def summarize(info):
    return "KAPE %s | %d target | %d modul (%d siap pakai) | %d biner di Modules\\bin" % (
        info["version"], len(info["targets"]), info.get("n_modules", 0), info.get("n_ready", 0), len(info.get("bin_exes", [])))


def plan_run(info, profile, custom_targets=(), custom_modules=()):
    """Tentukan target/modul yang benar-benar dijalankan; sisanya dicatat dilewati beserta alasannya."""
    prof = PROFILES[profile]
    want_t = list(custom_targets) if profile == "custom" else list(prof["targets"])
    want_m = list(custom_modules) if profile == "custom" else list(prof["modules"])
    tset = info["targets"]
    t_ok, skipped = [], []
    for t in want_t:
        if t.lower() in tset:
            t_ok.append(tset[t.lower()])
        else:
            skipped.append((t, "target tidak ditemukan"))
    m_ok = []
    for m in want_m:
        k = m.lower()
        if k in EXCLUDED_ALWAYS:
            skipped.append((m, "tidak dijalankan otomatis (mengekspor kunci pemulihan BitLocker)")); continue
        mod = info["mods"].get(k)
        if not mod or mod["disabled"]:
            skipped.append((m, "modul tidak ditemukan/nonaktif"))
        elif not mod.get("ready"):
            skipped.append((m, "biner kurang: " + ", ".join(mod.get("missing", [])[:4])))
        else:
            m_ok.append(mod["name"])
    return dict(profile=profile, label=prof["label"], targets=t_ok, modules=m_ok, skipped=skipped)


def build_command(exe, source, tdest, mdest, plan, vss=False):
    drv = source.rstrip("\\/") if len(source) <= 3 else source
    a = [exe]
    if plan["targets"]:
        a += ["--tsource", drv, "--tdest", tdest, "--target", ",".join(plan["targets"])]
        if vss:
            a.append("--vss")
    if plan["modules"]:
        a += ["--msource", tdest if plan["targets"] else (drv + "\\" if len(drv) == 2 and IS_WIN else drv),
              "--mdest", mdest, "--module", ",".join(plan["modules"])]
    return a


def _walk_stats(path):
    n = b = 0
    ext = collections.Counter()
    for dp, _, fns in os.walk(path):
        for f in fns:
            try:
                sz = os.path.getsize(os.path.join(dp, f))
            except OSError:
                sz = 0
            n += 1; b += sz
            ext[os.path.splitext(f)[1].lower() or "(tanpa ekstensi)"] += 1
    return n, b, ext


def _csv_rows(path, limit=200 * 1024 * 1024):
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "rb") as f:
            return max(0, sum(chunk.count(b"\n") for chunk in iter(lambda: f.read(1 << 20), b"")) - 1)
    except Exception:
        return None


def run_kape(info, plan, source, vss, dirs, timeout, log, is_admin, dry=False):
    r = dict(status="DILEWATI", message="", cmd="", exit_code=None, start=None, end=None, source=source, vss=vss,
             plan=plan, tdest=dirs["kape_t"], mdest=dirs["kape_m"], tfiles=0, tbytes=0, ext_top=[], copylog_rows=None,
             skiplog_rows=None, mgroups=[], console_tail="", logs=[])
    if not plan["targets"] and not plan["modules"]:
        r["message"] = "Tidak ada target/modul yang siap dijalankan pada profil ini."
        return r
    if not is_admin:
        r["message"] = "Butuh hak Administrator (KAPE menyalin berkas sistem terkunci)."
        return r
    work = os.path.join(dirs["work"], "kape")
    try:
        if not os.path.exists(work):
            shutil.copytree(info["root"], work, ignore=shutil.ignore_patterns("gkape.exe", "gkape.settings"))
        exe = os.path.join(work, "kape.exe")
        os.makedirs(dirs["kape_t"], exist_ok=True); os.makedirs(dirs["kape_m"], exist_ok=True)
        args = build_command(exe, source, dirs["kape_t"], dirs["kape_m"], plan, vss)
        r["cmd"] = subprocess.list2cmdline(args)
        log("  " + r["cmd"])
        if dry:
            r["status"], r["message"] = "DRY-RUN", "Perintah disusun tetapi tidak dijalankan."
            return r
        console = os.path.join(dirs["kape_m"], "kape_console_stdout.txt")
        r["start"] = dt.datetime.now()
        with open(console, "wb") as out:
            p = subprocess.Popen(args, cwd=work, stdout=out, stderr=subprocess.STDOUT,
                                 creationflags=0x08000000 if IS_WIN else 0)
            try:
                r["exit_code"] = p.wait(timeout=timeout)
                r["status"] = "BERHASIL" if r["exit_code"] == 0 else "SELESAI DENGAN KODE %s" % r["exit_code"]
            except subprocess.TimeoutExpired:
                p.terminate()
                try:
                    p.wait(15)
                except Exception:
                    p.kill()
                r["status"], r["message"] = "TIMEOUT", "Melebihi batas waktu %d detik; hasil parsial mungkin ada." % timeout
        r["end"] = dt.datetime.now()
    except Exception as e:
        r["status"], r["message"] = "GAGAL", "%s: %s" % (type(e).__name__, e)
        r["end"] = dt.datetime.now()
    # ---- kumpulkan hasil
    try:
        r["tfiles"], r["tbytes"], ext = _walk_stats(dirs["kape_t"])
        r["ext_top"] = ext.most_common(10)
        for dp, _, fns in os.walk(dirs["kape_t"]):
            for f in fns:
                low = f.lower()
                if low.endswith("_copylog.csv"):
                    r["copylog_rows"] = _csv_rows(os.path.join(dp, f)); r["logs"].append(os.path.join(dp, f))
                elif low.endswith("_skiplog.csv"):
                    r["skiplog_rows"] = _csv_rows(os.path.join(dp, f)); r["logs"].append(os.path.join(dp, f))
                elif low.endswith("consolelog.txt"):
                    r["logs"].append(os.path.join(dp, f))
        groups = collections.OrderedDict()
        for dp, _, fns in os.walk(dirs["kape_m"]):
            rel = os.path.relpath(dp, dirs["kape_m"])
            top = rel.split(os.sep)[0] if rel != "." else "(root)"
            g = groups.setdefault(top, dict(files=0, bytes=0, rows=0))
            for f in fns:
                fp = os.path.join(dp, f)
                g["files"] += 1; g["bytes"] += os.path.getsize(fp)
                if f.lower().endswith(".csv"):
                    g["rows"] += _csv_rows(fp) or 0
                if f.lower().endswith("consolelog.txt") or f == "kape_console_stdout.txt":
                    r["logs"].append(fp)
        r["mgroups"] = [(k, v["files"], v["bytes"], v["rows"]) for k, v in groups.items()]
        con = os.path.join(dirs["kape_m"], "kape_console_stdout.txt")
        if os.path.exists(con):
            txt = open(con, "rb").read().decode("utf-8", "replace")
            r["console_tail"] = "\n".join(txt.splitlines()[-40:])
        if r["status"] == "BERHASIL" and r["tfiles"] == 0 and not r["mgroups"]:
            r["status"], r["message"] = "KOSONG", "KAPE selesai tetapi tidak menghasilkan berkas."
    except Exception as e:
        r["message"] += " (gagal membaca hasil: %s)" % e
    return r


def readiness_text(info):
    """Ringkasan teks untuk GUI/CLI."""
    L = [summarize(info), "Lokasi: %s" % info["root"],
         "kape.exe: %s-bit (header PE) | SHA-256 %s" % (info["exe_bits"] or "?", info["exe_sha256"][:16] + "..."),
         "gkape.exe: %s | Get-KAPEUpdate.ps1: %s" % ("ada" if info["gkape"] else "tidak ada", "ada" if info["has_update_script"] else "tidak ada"), ""]
    L.append("%-28s %6s %6s  %s" % ("Kelompok modul", "Total", "Siap", "Biner kurang (contoh)"))
    for g, t, ok, ms in info.get("groups", []):
        L.append("%-28s %6d %6d  %s" % (g, t, ok, ", ".join(ms)))
    L.append("")
    L.append("Biner EZTools di Modules\\bin: " + ", ".join(info.get("bin_exes", [])))
    for i in info["issues"]:
        L.append("! " + i)
    return "\n".join(L)
