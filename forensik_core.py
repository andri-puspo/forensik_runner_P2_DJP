# -*- coding: utf-8 -*-
"""Forensik Runner - inti: deteksi OS 32/64-bit, pemilihan biner, eksekusi alat, laporan PDF."""
import csv, ctypes, datetime as dt, getpass, hashlib, io, json, os, platform, re, shutil
import socket, struct, subprocess, sys, time
from xml.sax.saxutils import escape

import forensik_hw as hwmod
import forensik_kape as kmod
import forensik_integrasi as igmod
import forensik_kasus as kasmod

APP_NAME = "Forensik Runner"
APP_VERSION = "1.1"
APP_AUTHOR = "APH4NC-Dit.P2-DJP-KEMENKEU"
IS_WIN = sys.platform == "win32"
ASSETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")

def asset(name):
    p = os.path.join(ASSETS, name)
    return p if os.path.exists(p) else None

BULAN = ["Januari", "Februari", "Maret", "April", "Mei", "Juni", "Juli", "Agustus",
         "September", "Oktober", "November", "Desember"]

# ---------------------------------------------------------------- definisi alat
# mode: "export" = jalankan /scomma + /shtml ; "monitor" = pencatat live (USBLogView)
TOOLS = [
    dict(key="browsinghistoryview", title="BrowsingHistoryView", exe="BrowsingHistoryView.exe",
         timeout=900, mode="export", extra=[],
         desc="Membaca riwayat kunjungan situs dari Chrome, Edge, Firefox, Internet Explorer dan Safari milik pengguna aktif.",
         relevansi="Menunjukkan situs yang diakses (marketplace, bursa/platform kripto, perbankan, penyimpanan awan) dan kapan diakses.",
         cols=["url", "title", "visit time", "visit count", "web browser", "user profile"]),
    dict(key="chromehistoryview", title="ChromeHistoryView", exe="ChromeHistoryView.exe",
         timeout=600, mode="export", extra=[],
         desc="Membaca berkas riwayat Google Chrome pengguna aktif: URL, judul, waktu kunjungan, jumlah kunjungan, referrer.",
         relevansi="Melengkapi BrowsingHistoryView khusus Chrome (situs marketplace, platform kripto, perbankan, penyimpanan awan).",
         cols=["url", "title", "visit time", "visit date", "visit count", "referrer", "visit id"]),
    dict(key="cports", title="CurrPorts", exe="cports.exe", timeout=300, mode="export", flag="/scomma",
         extra=["/AddExportHeaderLine", "1", "/ResolveAddresses", "0", "/CaptureTime", "5000"],
         desc="Daftar port TCP/UDP yang terbuka dan koneksi jaringan aktif beserta proses, path, pengguna, alamat lokal/jarak jauh, dan status. "
              "Pemetaan nama host (DNS) dimatikan agar tidak ada lalu lintas keluar tambahan.",
         relevansi="Menunjukkan koneksi aktif saat pemeriksaan (mis. SMB ke NAS/komputer lain, layanan awan, aplikasi pencatatan daring) dan proses yang memakainya.",
         cols=["process name", "process id", "protocol", "local address", "local port", "remote address", "remote port", "remote host", "state", "user name", "process path"]),
    dict(key="mozillahistoryview", title="MozillaHistoryView", exe="MozillaHistoryView.exe",
         timeout=600, mode="export", extra=[],
         desc="Membaca riwayat Mozilla Firefox (dan turunan berbasis Mozilla) pengguna aktif.",
         relevansi="Melengkapi BrowsingHistoryView khusus Firefox; menunjukkan situs yang diakses dan waktunya.",
         cols=["url", "title", "last visit", "visit date", "visit count", "referrer", "first visit"]),
    dict(key="driveletterview", title="DriveLetterView", exe="DriveLetterView.exe",
         timeout=120, mode="export", extra=[],
         desc="Menampilkan seluruh huruf drive yang sedang dan pernah terpasang (lokal, jaringan, USB, virtual).",
         relevansi="Mengungkap media penyimpanan eksternal/virtual yang pernah terhubung.",
         cols=["drive letter", "drive name", "volume name", "drive type", "connected", "file system", "serial", "last"]),
    dict(key="iehv", title="IEHV", exe="iehv.exe", timeout=600, mode="export", flag="/stab", delim="\t", extra=[],
         desc="IE History Viewer: membaca riwayat Internet Explorer / Edge lama (WebCache), termasuk URL yang diketik. "
              "Alat ini tidak punya /scomma sehingga diekspor dengan /stab (teks bertab).",
         relevansi="Menambah jejak penelusuran dari peramban bawaan Windows yang tidak tercakup alat lain.",
         cols=["url", "title", "modified date", "last visited", "visit count", "accessed", "expires"]),
    dict(key="lastactivityview", title="LastActivityView", exe="LastActivityView.exe",
         timeout=300, mode="export", extra=[],
         desc="Mengumpulkan jejak aktivitas pengguna: file dijalankan/dibuka, instal, error, koneksi jaringan, hidup/mati sistem.",
         relevansi="Membentuk lini masa aktivitas di komputer (siapa melakukan apa dan kapan).",
         cols=["action time", "description", "filename", "full path", "more information"]),
    dict(key="networkinterfacesview", title="NetworkInterfacesView", exe="NetworkInterfacesView.exe",
         timeout=120, mode="export", extra=[],
         desc="Menampilkan seluruh antarmuka jaringan (aktif/nonaktif/virtual): nama, MAC address, IP, DNS, gateway, status.",
         relevansi="Mengidentifikasi perangkat jaringan, adapter VPN/virtual, dan konfigurasi jaringan komputer.",
         cols=["connection name", "adapter name", "mac", "ip address", "gateway", "dns", "status", "connected"]),
    dict(key="ofview", title="OpenedFilesView", exe="OpenedFilesView.exe", timeout=300, mode="export", extra=[],
         desc="Daftar berkas dan folder yang sedang dibuka (handle aktif) oleh proses di komputer, termasuk berkas pada drive eksternal atau share jaringan.",
         relevansi="Bukti berkas/media yang sedang dipakai saat pemeriksaan (snapshot), mis. berkas penjualan yang dibuka dari USB atau NAS.",
         cols=["filename", "full path", "extension", "process", "handle", "file size", "modified", "created", "user name", "write access"]),
    dict(key="opensavefilesview", title="OpenSaveFilesView", exe="OpenSaveFilesView.exe",
         timeout=300, mode="export", extra=[],
         desc="Membaca daftar file yang pernah dibuka/disimpan lewat dialog Open/Save aplikasi Windows.",
         relevansi="Menunjukkan dokumen yang pernah diakses (pembukuan, kontrak, faktur) termasuk di drive eksternal.",
         cols=["filename", "extension", "accessed", "full path", "folder", "application"]),
    dict(key="previousfilesrecovery", title="PreviousFilesRecovery", exe="PreviousFilesRecovery.exe",
         timeout=900, mode="export", extra=[],
         desc="Memindai Volume Shadow Copy untuk menemukan versi file sebelumnya, termasuk file yang telah dihapus/diubah.",
         relevansi="Memulihkan file yang dihapus atau dimodifikasi sebelum pemeriksaan.",
         cols=["filename", "full path", "current modified", "previous modified", "size", "shadow", "status"]),
    dict(key="shellbagsview", title="ShellBagsView", exe="ShellBagsView.exe",
         timeout=300, mode="export", extra=[],
         desc="Membaca ShellBags registry: folder yang pernah dibuka pengguna di Explorer, termasuk folder yang kini sudah tidak ada.",
         relevansi="Bukti keberadaan folder/drive eksternal/jaringan yang pernah diakses walau file sudah dihapus.",
         cols=["folder", "path", "created", "modified", "accessed", "last write", "type", "user"]),
    dict(key="usbdeview", title="USBDeview", exe="USBDeview.exe",
         timeout=300, mode="export",
         extra=["/AddExportHeaderLine", "1", "/DisplayDisconnected", "1", "/DisplayNoPortSerial", "1",
                "/DisplayNoDriver", "1", "/MarkConnectedDevices", "1"],
         desc="Mendaftar seluruh perangkat USB yang sedang terhubung maupun pernah terhubung (nama, serial, VID/PID, tanggal colok).",
         relevansi="Bukti penggunaan flashdisk/HDD eksternal untuk memindahkan data.",
         cols=["device name", "description", "device type", "connected", "drive letter", "serial number",
               "created date", "last plug", "vendorid", "productid", "vendor"]),
    dict(key="usbdrivelog", title="USBDriveLog", exe="USBDriveLog.exe",
         timeout=300, mode="export", extra=[],
         desc="Menyusun log penggunaan drive USB (waktu colok/cabut, model, serial) dari event log dan registry Windows.",
         relevansi="Melengkapi USBDeview dengan jejak waktu colok/cabut berdasarkan log Windows.",
         cols=["plug time", "unplug time", "device model", "drive letter", "serial", "volume", "vendor", "product"]),
    dict(key="usblogview", title="USBLogView", exe="USBLogView.exe",
         timeout=0, mode="monitor", extra=[],
         desc="Pencatat live peristiwa colok/cabut perangkat USB. Tidak punya ekspor baris-perintah, sehingga dijalankan selama jendela pemantauan.",
         relevansi="Merekam aktivitas USB yang terjadi selama pemeriksaan berlangsung (bukan riwayat masa lalu).",
         cols=[]),
    dict(key="ipnetinfo", title="IPNetInfo", exe="ipnetinfo.exe", timeout=0, mode="manual", extra=[],
         desc="Mencari pemilik, negara, dan rentang alamat IP (kueri whois ke server RIR). Berbasis GUI dan memerlukan internet.",
         relevansi="Mengidentifikasi pemilik alamat IP publik yang muncul pada riwayat/aktivitas (mis. server bursa atau penyedia layanan awan).",
         cols=[]),
    dict(key="sysexp", title="SysExporter", exe="sysexp.exe", timeout=0, mode="manual", extra=[],
         manual_text="SysExporter tidak dijalankan otomatis. Alat ini mengekspor isi kontrol (daftar/tabel) pada jendela aplikasi lain yang sedang terbuka dan "
                     "hanya berjalan dari baris perintah bila jendela targetnya ditentukan (/Process, /Title, /Class, /Visible). Karena itu pemeriksa "
                     "menentukan sendiri jendela target (mis. daftar transaksi pada aplikasi akuntansi yang sedang terbuka) dan menjalankannya manual, "
                     "dengan perintah seperti:  sysexp.exe /Process <aplikasi.exe> /Class SysListView32 /Visible Yes /scomma <berkas.csv>. "
                     "Simpan hasil ekspor di folder Data_Mentah, hitung hash-nya, dan catat waktu serta perintah pada berita acara.",
         desc="Mengekspor isi kontrol (ListView/TreeView/teks) dari jendela aplikasi lain yang sedang berjalan.",
         relevansi="Mengambil data tampilan aplikasi yang tidak dapat diekspor secara normal (mis. daftar transaksi di layar) sebagai bukti tambahan.",
         cols=[]),
]
TOOL_BY_KEY = {t["key"]: t for t in TOOLS}


# ---------------------------------------------------------------- util umum
def now():
    return dt.datetime.now()

def tgl_id(d):
    return "%d %s %d" % (d.day, BULAN[d.month - 1], d.year)

def parse_tanggal(s):
    s = (s or "").strip()
    for f in ("%d-%m-%Y", "%d/%m/%Y", "%Y-%m-%d", "%d.%m.%Y"):
        try:
            return dt.datetime.strptime(s, f).date()
        except ValueError:
            pass
    return None

def sha256_file(path, bufsize=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(bufsize)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def clean(s):
    """Hapus karakter kontrol agar aman untuk PDF."""
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(s))

def is_admin():
    if not IS_WIN:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------- deteksi OS 32/64 bit
class _SYSINFO(ctypes.Structure):
    _fields_ = [("wProcessorArchitecture", ctypes.c_ushort), ("wReserved", ctypes.c_ushort),
                ("dwPageSize", ctypes.c_ulong), ("lpMinimumApplicationAddress", ctypes.c_void_p),
                ("lpMaximumApplicationAddress", ctypes.c_void_p), ("dwActiveProcessorMask", ctypes.c_void_p),
                ("dwNumberOfProcessors", ctypes.c_ulong), ("dwProcessorType", ctypes.c_ulong),
                ("dwAllocationGranularity", ctypes.c_ulong), ("wProcessorLevel", ctypes.c_ushort),
                ("wProcessorRevision", ctypes.c_ushort)]

def detect_os():
    """Mengembalikan info OS. 'bits' adalah bitness SISTEM OPERASI (bukan Python)."""
    info = dict(system=platform.system(), release=platform.release(), version=platform.version(),
                edition="", hostname=socket.gethostname(), user=getpass.getuser(),
                python_bits=struct.calcsize("P") * 8, arch="", bits=0, via="")
    if IS_WIN:
        arch = None
        try:
            si = _SYSINFO()
            ctypes.windll.kernel32.GetNativeSystemInfo(ctypes.byref(si))
            arch = {9: "AMD64", 12: "ARM64", 0: "x86", 5: "ARM", 6: "IA64"}.get(si.wProcessorArchitecture)
            info["via"] = "GetNativeSystemInfo"
        except Exception:
            pass
        if not arch:
            arch = os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE", "x86")
            info["via"] = "variabel lingkungan PROCESSOR_ARCHITECTURE"
        info["arch"] = arch
        info["bits"] = 32 if arch.lower() in ("x86", "arm") else 64
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            name = winreg.QueryValueEx(k, "ProductName")[0]
            try:
                disp = winreg.QueryValueEx(k, "DisplayVersion")[0]
            except OSError:
                disp = ""
            try:
                build = winreg.QueryValueEx(k, "CurrentBuildNumber")[0]
                if int(build) >= 22000:
                    name = name.replace("Windows 10", "Windows 11")
            except Exception:
                build = ""
            info["edition"] = ("%s %s (build %s)" % (name, disp, build)).replace("  ", " ").strip()
        except Exception:
            info["edition"] = "Windows %s" % platform.release()
    else:  # hanya untuk pengujian di luar Windows
        m = platform.machine().lower()
        info["arch"] = platform.machine()
        info["bits"] = 64 if ("64" in m or "aarch" in m) else 32
        info["via"] = "platform.machine()"
        info["edition"] = "%s %s" % (platform.system(), platform.release())
    return info

def os_label(osi):
    return "%s - %d-bit (%s)" % (osi["edition"] or osi["system"], osi["bits"], osi["arch"])


# ---------------------------------------------------------------- header PE & pemilihan biner
def pe_bits(path):
    """Bitness biner dari header PE: 32, 64 atau None."""
    try:
        with open(path, "rb") as f:
            d = f.read(4096)
        off = struct.unpack_from("<I", d, 0x3C)[0]
        if d[off:off + 4] != b"PE\0\0":
            return None
        m = struct.unpack_from("<H", d, off + 4)[0]
        return {0x14C: 32, 0x8664: 64, 0xAA64: 64}.get(m)
    except Exception:
        return None

def pe_version(path):
    """FileVersion (atau ProductVersion) dari resource versi PE, tanpa API Windows (lintas platform)."""
    try:
        if os.path.getsize(path) > 40 * 1024 * 1024:
            return None
        d = open(path, "rb").read()
        for name in ("FileVersion", "ProductVersion"):
            key = name.encode("utf-16-le") + b"\x00\x00"
            pos = 0
            while True:
                i = d.find(key, pos)
                if i < 0:
                    break
                pos = i + len(key)
                j = pos
                while j < len(d) and d[j] == 0:
                    j += 1
                if j % 2:
                    j -= 1
                out = []
                while j + 1 < len(d) and not (d[j] == 0 and d[j + 1] == 0) and len(out) < 40:
                    out.append(d[j:j + 2].decode("utf-16-le", "replace")); j += 2
                v = "".join(out).strip()
                if re.match(r"^\d+([.,]\s?\d+)+", v):
                    return v
        return None
    except Exception:
        return None

def _find_exe(folder, exe):
    if not os.path.isdir(folder):
        return None
    for n in os.listdir(folder):
        if n.lower() == exe.lower():
            return os.path.join(folder, n)
    return None

def resolve_binary(tools_dir, tool, os_bits):
    """Pilih biner: OS 64-bit -> x64 bila ada; selain itu 32-bit. Hasil: dict."""
    k, exe = tool["key"], tool["exe"]
    p64 = _find_exe(os.path.join(tools_dir, "64bit", k + "-x64"), exe)
    p32 = _find_exe(os.path.join(tools_dir, k), exe)
    res = dict(path=None, bits=None, note="", found32=bool(p32), found64=bool(p64), version=None)
    if os_bits == 64 and p64:
        res.update(path=p64, bits=pe_bits(p64) or 64)
        res["note"] = "OS 64-bit -> memakai biner 64-bit (x64)."
    elif p32:
        res.update(path=p32, bits=pe_bits(p32) or 32)
        if os_bits == 64:
            res["note"] = ("Versi 64-bit alat ini tidak tersedia di folder; memakai biner 32-bit "
                           "yang berjalan melalui WOW64 pada OS 64-bit.")
        else:
            res["note"] = "OS 32-bit -> memakai biner 32-bit."
    elif p64 and os_bits == 32:
        res["note"] = "Hanya biner 64-bit yang ada, tidak dapat dijalankan pada OS 32-bit."
    else:
        res["note"] = "Biner alat tidak ditemukan di folder."
    if res["path"]:
        res["version"] = pe_version(res["path"])
    return res

def find_tools_dir(start, saved=None):
    """Cari folder alat: tersimpan -> di sekitar aplikasi (sama/induk/folder saudara, mis. ..\\tools)."""
    def ok(d):
        return bool(d) and os.path.isdir(os.path.join(d, "usbdeview"))
    if ok(saved):
        return saved
    cands = [start, os.path.dirname(start), os.path.dirname(os.path.dirname(start))]
    for base in (start, os.path.dirname(start)):
        try:
            for n in sorted(os.listdir(base)):
                cands.append(os.path.join(base, n))
        except OSError:
            pass
    for c in cands:
        if ok(c):
            return c
    return None

CONFIG_NAME = "config.json"

def load_config(app_dir):
    try:
        return json.load(open(os.path.join(app_dir, CONFIG_NAME), encoding="utf-8"))
    except Exception:
        return {}

def save_config(app_dir, cfg):
    try:
        json.dump(cfg, open(os.path.join(app_dir, CONFIG_NAME), "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    except Exception:
        pass


# ---------------------------------------------------------------- identitas kasus
def format_npwp(digits):
    if len(digits) == 15:
        return "%s.%s.%s.%s-%s.%s" % (digits[0:2], digits[2:5], digits[5:8], digits[8:9], digits[9:12], digits[12:15])
    if len(digits) == 16:
        return " ".join(digits[i:i + 4] for i in range(0, 16, 4))
    return digits

def validate_case(c, legacy=False):
    """Kembalikan (daftar_error, kasus_ternormalisasi)."""
    err, n = [], {}
    n["nama_wp"] = (c.get("nama_wp") or "").strip()
    if not n["nama_wp"]:
        err.append("Nama Wajib Pajak wajib diisi.")
    dg = re.sub(r"\D", "", c.get("npwp") or "")
    if len(dg) not in (15, 16):
        err.append("NPWP harus 15 atau 16 digit (terisi %d digit)." % len(dg))
    n["npwp_digits"], n["npwp"] = dg, format_npwp(dg)
    for pre, label in (("sp2", "Surat Perintah Pemeriksaan"), ("st", "Surat Tugas")):
        no = (c.get(pre + "_no") or "").strip()
        if not no:
            err.append("Nomor %s wajib diisi." % label)
        d = parse_tanggal(c.get(pre + "_tgl"))
        if not d:
            err.append("Tanggal %s tidak valid (gunakan dd-mm-yyyy)." % label)
        n[pre + "_no"], n[pre + "_tgl"] = no, d
    for key, label in (("pemeriksa", "Nama pemeriksa pajak"), ("tenaga_ahli", "Nama tenaga ahli")):
        v = c.get(key) or []
        if isinstance(v, str):
            v = v.splitlines()
        v = [x.strip() for x in v if x.strip()]
        if not v:
            err.append("%s wajib diisi (minimal satu)." % label)
        n[key] = v
    for key, label in (("user_nama", "Nama pengguna perangkat"), ("user_jabatan", "Jabatan pengguna perangkat"),
                       ("user_lokasi", "Lokasi perangkat")):
        n[key] = (c.get(key) or "").strip()
        if not n[key]:
            err.append("%s wajib diisi oleh petugas." % label)
    for key in ("id_perkara", "no_berita_acara", "perwakilan_wp"):
        n[key] = (c.get(key) or "").strip()
    def _bool(x):
        return x if isinstance(x, bool) else str(x).strip().lower() in ("1", "true", "ya", "yes", "y")
    n["persetujuan_lisan"] = _bool(c.get("persetujuan_lisan", False))
    n["persetujuan_tertulis"] = _bool(c.get("persetujuan_tertulis", False))
    n["dok_persetujuan"] = (c.get("dok_persetujuan") or "").strip()
    if legacy and "persetujuan_lisan" not in c:
        del n["persetujuan_lisan"], n["persetujuan_tertulis"]
    elif not n["persetujuan_lisan"]:
        err.append("Penegasan persetujuan LISAN dari pengguna perangkat dan pihak Wajib Pajak wajib dicentang.")
    if "persetujuan_tertulis" in n and not n["persetujuan_tertulis"]:
        err.append("Penegasan persetujuan TERTULIS dari pengguna perangkat dan pihak Wajib Pajak wajib dicentang.")
    kk = c.get("kata_kunci_kasus") or []
    if isinstance(kk, str):
        kk = re.split(r"[\n;,]+", kk)
    n["kata_kunci_kasus"] = [x.strip() for x in kk if x and x.strip()][:40]
    n["waktu_referensi"] = (c.get("waktu_referensi") or "").strip()
    n["tahun_pajak"] = (c.get("tahun_pajak") or "").strip()
    n["keterangan"] = (c.get("keterangan") or "").strip()
    return err, n


# ---------------------------------------------------------------- pembacaan hasil
def read_text_auto(path):
    raw = open(path, "rb").read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace")
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8", "replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1252", "replace")

def read_csv_rows(path, delim=","):
    txt = read_text_auto(path)
    if not txt.strip():
        return [], []
    rows = list(csv.reader(io.StringIO(txt), delimiter=delim, quoting=csv.QUOTE_MINIMAL if delim == "," else csv.QUOTE_NONE))
    rows = [r for r in rows if any(c.strip() for c in r)]
    if not rows:
        return [], []
    return rows[0], rows[1:]


# ---------------------------------------------------------------- eksekusi alat
def _startupinfo():
    if not IS_WIN:
        return None, 0
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 7  # SW_SHOWMINNOACTIVE
    return si, 0x08000000  # CREATE_NO_WINDOW

def _copy_tool(src_exe, work_dir):
    """Salin alat ke folder kerja agar berkas .cfg tidak mengubah biner/folder asli."""
    os.makedirs(work_dir, exist_ok=True)
    src_dir = os.path.dirname(src_exe)
    for n in os.listdir(src_dir):
        if n.lower().endswith((".exe", ".cfg", ".dll")):
            shutil.copy2(os.path.join(src_dir, n), os.path.join(work_dir, n))
    return os.path.join(work_dir, os.path.basename(src_exe))

def quote_cmd(args):
    return " ".join('"%s"' % a if (" " in a or not a) else a for a in args)

def run_tool(tool, binfo, dirs, monitor_seconds, log):
    """Jalankan satu alat. Mengembalikan dict hasil."""
    r = dict(key=tool["key"], title=tool["title"], status="TIDAK DITEMUKAN", bin=binfo,
             exe_sha256="", cmd="", exit_code=None, start=None, end=None, files=[],
             header=[], rows=[], raw_text="", message="")
    if not binfo["path"]:
        r["message"] = binfo["note"]
        return r
    r["exe_sha256"] = sha256_file(binfo["path"])
    if tool["mode"] == "manual":
        r["status"], r["message"] = "DILEWATI", "Tidak dijalankan otomatis (GUI + butuh internet); lihat bagian Hasil."
        r["cmd"] = "(tidak dijalankan)"
        return r
    work = os.path.join(dirs["work"], tool["key"])
    exe = _copy_tool(binfo["path"], work)
    base = os.path.join(dirs["raw"], tool["title"])
    si, flags = _startupinfo()
    try:
        if tool["mode"] == "export":
            flag, delim = tool.get("flag", "/scomma"), tool.get("delim", ",")
            out_csv, out_html = base + (".csv" if delim == "," else ".txt"), base + ".html"
            args = [exe, flag, out_csv] + tool["extra"]
            r["cmd"] = quote_cmd(args)
            r["start"] = now()
            log("  %s" % r["cmd"])
            try:
                p = subprocess.run(args, cwd=work, timeout=tool["timeout"], startupinfo=si,
                                   creationflags=flags, capture_output=True)
                r["exit_code"] = p.returncode
            except subprocess.TimeoutExpired:
                r["status"], r["message"] = "TIMEOUT", "Melebihi batas waktu %d detik." % tool["timeout"]
            # ekspor HTML sebagai lampiran (tidak fatal bila gagal)
            if r["status"] != "TIMEOUT":
                try:
                    subprocess.run([exe, "/shtml", out_html] + tool["extra"], cwd=work,
                                   timeout=tool["timeout"], startupinfo=si, creationflags=flags,
                                   capture_output=True)
                except Exception:
                    pass
            r["end"] = now()
            if r["status"] != "TIMEOUT":
                if os.path.exists(out_csv):
                    r["header"], r["rows"] = read_csv_rows(out_csv, delim)
                    r["status"] = "BERHASIL" if r["rows"] else "KOSONG"
                    if not r["rows"]:
                        r["message"] = "Berkas hasil dibuat tetapi tidak berisi data."
                else:
                    r["status"] = "GAGAL"
                    r["message"] = "Alat selesai (kode keluar %s) tetapi berkas hasil tidak terbentuk. " \
                                   "Jalankan sebagai Administrator." % r["exit_code"]
            for f in (out_csv, out_html):
                if os.path.exists(f):
                    r["files"].append(f)
        else:  # monitor (USBLogView)
            logf = base + "_log.txt"
            cfg = ("[General]\r\nTrayIcon=1\r\nStartAsHidden=1\r\nAddToLogFile=1\r\n"
                   "LogFileType=1\r\nLogFilename=%s\r\n" % logf)
            with open(os.path.join(work, os.path.splitext(os.path.basename(exe))[0] + ".cfg"), "w") as f:
                f.write(cfg)
            r["cmd"] = quote_cmd([exe]) + "  (pemantauan %d detik)" % monitor_seconds
            r["start"] = now()
            log("  %s" % r["cmd"])
            p = subprocess.Popen([exe], cwd=work, startupinfo=si, creationflags=flags)
            time.sleep(monitor_seconds)
            p.terminate()
            try:
                r["exit_code"] = p.wait(10)
            except Exception:
                p.kill()
            r["end"] = now()
            if os.path.exists(logf) and os.path.getsize(logf) > 0:
                r["raw_text"] = read_text_auto(logf)
                r["status"] = "BERHASIL"
                r["files"].append(logf)
            else:
                r["status"] = "KOSONG"
                r["message"] = ("Tidak ada peristiwa colok/cabut USB selama %d detik pemantauan." % monitor_seconds)
    except Exception as e:  # satu alat gagal tidak menghentikan yang lain
        r["status"], r["message"] = "GAGAL", "%s: %s" % (type(e).__name__, e)
        r["end"] = r["end"] or now()
    return r


# ---------------------------------------------------------------- IP publik (untuk IPNetInfo manual)
_IPV4 = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")

def collect_public_ips(results):
    """Kumpulkan IPv4 publik dari hasil alat lain. Mengembalikan {ip: {alat: jumlah}}."""
    import ipaddress
    found = {}
    for r in results:
        if r["key"] not in ("browsinghistoryview", "chromehistoryview", "mozillahistoryview", "iehv", "lastactivityview", "cports"):
            continue
        texts = [" ".join(row) for row in r["rows"]] + ([r["raw_text"]] if r.get("raw_text") else [])
        for t in texts:
            for m in _IPV4.findall(t):
                try:
                    ip = ipaddress.ip_address(m)
                except ValueError:
                    continue
                if ip.is_global and not ip.is_multicast:
                    d = found.setdefault(str(ip), {})
                    d[r["title"]] = d.get(r["title"], 0) + 1
    return found

def run_manual(tool, r, dirs, results, log):
    """Alat manual: tidak dijalankan otomatis. IPNetInfo: menyiapkan daftar IP publik untuk ditelusuri manual."""
    if tool["key"] != "ipnetinfo":
        r["start"] = r["end"] = now()
        log("  %s tidak dijalankan otomatis (manual oleh pemeriksa)" % tool["title"])
        return r
    ips = collect_public_ips(results)
    txt = os.path.join(dirs["raw"], "Daftar_IP_Publik.txt")
    csvp = os.path.join(dirs["raw"], "Daftar_IP_Publik.csv")
    with open(txt, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(ips)) + ("\n" if ips else ""))
    with open(csvp, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f); w.writerow(["ip", "total_kemunculan", "sumber"])
        for ip in sorted(ips):
            w.writerow([ip, sum(ips[ip].values()), "; ".join("%s (%d)" % kv for kv in sorted(ips[ip].items()))])
    r["files"] = [txt, csvp]
    r["header"], r["rows"] = ["IP", "Kemunculan", "Sumber"], [[ip, str(sum(v.values())), "; ".join("%s (%d)" % kv for kv in sorted(v.items()))]
                                                              for ip, v in sorted(ips.items())]
    r["raw_text"] = ""
    r["message"] = ("Tidak dijalankan otomatis. %d alamat IPv4 publik terkumpul (dari riwayat peramban, LastActivityView, dan CurrPorts) untuk "
                    "penelusuran manual; angka bertitik berformat IP dapat berupa nomor versi, sehingga perlu diverifikasi." % len(ips))
    r["start"] = r["end"] = now()
    log("  IPNetInfo tidak dijalankan; %d IP publik disimpan ke %s" % (len(ips), txt))
    return r


# ---------------------------------------------------------------- PDF
def _pdf_modules():
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfgen import canvas
    from reportlab.platypus import (BaseDocTemplate, Frame, PageTemplate, Paragraph, Spacer, Table,
                                    TableStyle, KeepTogether, PageBreak, CondPageBreak, Preformatted, Image)
    return locals()

_FONT = {}
def _register_fonts():
    if _FONT:
        return _FONT
    m = _pdf_modules()
    pdfmetrics, TTFont = m["pdfmetrics"], m["TTFont"]
    cand = [("C:\\Windows\\Fonts\\segoeui.ttf", "C:\\Windows\\Fonts\\segoeuib.ttf", "C:\\Windows\\Fonts\\consola.ttf"),
            ("C:\\Windows\\Fonts\\arial.ttf", "C:\\Windows\\Fonts\\arialbd.ttf", "C:\\Windows\\Fonts\\cour.ttf"),
            ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
             "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf")]
    for reg, bold, mono in cand:
        if os.path.exists(reg) and os.path.exists(bold):
            try:
                pdfmetrics.registerFont(TTFont("F-Reg", reg))
                pdfmetrics.registerFont(TTFont("F-Bold", bold))
                pdfmetrics.registerFont(TTFont("F-Mono", mono if os.path.exists(mono) else reg))
                _FONT.update(reg="F-Reg", bold="F-Bold", mono="F-Mono")
                return _FONT
            except Exception:
                continue
    _FONT.update(reg="Helvetica", bold="Helvetica-Bold", mono="Courier")
    return _FONT

CONF_NOTE = ("RAHASIA - Dokumen ini memuat data Wajib Pajak yang wajib dijaga kerahasiaannya "
             "(Pasal 34 UU KUP). Hanya untuk keperluan pemeriksaan.")

def _styles():
    m = _pdf_modules(); P = m["ParagraphStyle"]; colors = m["colors"]; F = _register_fonts()
    base = dict(fontName=F["reg"], fontSize=9, leading=12)
    return dict(
        base=P("b", **base),
        small=P("s", fontName=F["reg"], fontSize=7.5, leading=9.5),
        cell=P("c", fontName=F["reg"], fontSize=7, leading=8.6),
        cellh=P("ch", fontName=F["bold"], fontSize=7, leading=8.6, textColor=colors.white),
        h1=P("h1", fontName=F["bold"], fontSize=16, leading=20, spaceAfter=4),
        h2=P("h2", fontName=F["bold"], fontSize=11, leading=14, spaceBefore=10, spaceAfter=4,
             textColor=colors.HexColor("#1F3A5F")),
        key=P("k", fontName=F["bold"], fontSize=9, leading=12),
        mono=P("m", fontName=F["mono"], fontSize=7, leading=8.5),
    )

def _P(text, style):
    return _pdf_modules()["Paragraph"](escape(clean(text)).replace("\n", "<br/>"), style)

def _numbered_canvas(case, osi, title):
    m = _pdf_modules(); canvas = m["canvas"]; mm = m["mm"]; F = _register_fonts()
    class NC(canvas.Canvas):
        def __init__(self, *a, **k):
            canvas.Canvas.__init__(self, *a, **k); self._saved = []
        def showPage(self):
            self._saved.append(dict(self.__dict__)); self._startPage()
        def save(self):
            n = len(self._saved)
            for st in self._saved:
                self.__dict__.update(st); self._decor(n); canvas.Canvas.showPage(self)
            canvas.Canvas.save(self)
        def _decor(self, n):
            w, h = self._pagesize
            self.setFont(F["reg"], 7); self.setFillGray(0.35)
            lg = asset("logo_crop.png"); tx = 15 * mm
            if lg:
                try:
                    self.drawImage(lg, 15 * mm, h - 10.0 * mm, width=3.45 * mm, height=5.5 * mm, mask="auto")
                    tx = 20 * mm
                except Exception:
                    pass
            ap = asset("app_logo.jpg")
            if ap:
                try:
                    self.drawImage(ap, w - 15 * mm - 7.8 * mm, h - 11.8 * mm, width=7.8 * mm, height=6.85 * mm)
                except Exception:
                    pass
            self.drawString(tx, h - 9 * mm, "%s | NPWP %s | %s" % (case["nama_wp"][:60], case["npwp"], getattr(self, "_title_override", title)))
            self.line(15 * mm, h - 10.5 * mm, w - 15 * mm, h - 10.5 * mm)
            self.line(15 * mm, 12 * mm, w - 15 * mm, 12 * mm)
            self.drawString(15 * mm, 8.5 * mm, CONF_NOTE[:150])
            self.drawString(15 * mm, 4.5 * mm, "%s v%s | Pembuat aplikasi: %s" % (APP_NAME, APP_VERSION, APP_AUTHOR))
            self.drawRightString(w - 15 * mm, 4.5 * mm, "Halaman %d dari %d" % (self._pageNumber, n))
    return NC

def _kv_table(rows, width, st):
    m = _pdf_modules(); Table, TableStyle, colors = m["Table"], m["TableStyle"], m["colors"]
    data = [[_P(k, st["key"]), _P(v, st["base"])] for k, v in rows]
    t = Table(data, colWidths=[width * 0.30, width * 0.70])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9AA5B1")),
                           ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EEF2F7")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    return t

def case_rows(case):
    rows = [("Nama Wajib Pajak", case["nama_wp"]), ("NPWP", case["npwp"]),
            ("Surat Perintah Pemeriksaan", "Nomor: %s\nTanggal: %s" % (case["sp2_no"], tgl_id(case["sp2_tgl"]))),
            ("Surat Tugas", "Nomor: %s\nTanggal: %s" % (case["st_no"], tgl_id(case["st_tgl"]))),
            ("Nama Pemeriksa Pajak", "\n".join("%d. %s" % (i + 1, x) for i, x in enumerate(case["pemeriksa"]))),
            ("Nama Tenaga Ahli", "\n".join("%d. %s" % (i + 1, x) for i, x in enumerate(case["tenaga_ahli"])))]
    rows.append(("Pengguna Perangkat (diisi petugas)", "Nama: %s\nJabatan: %s\nLokasi perangkat: %s" % (
        case["user_nama"], case["user_jabatan"], case["user_lokasi"])))
    if "persetujuan_lisan" in case:
        bentuk = " dan ".join(b for b, k in (("lisan", "persetujuan_lisan"), ("tertulis", "persetujuan_tertulis")) if case.get(k))
        if bentuk:
            txt = ("Akses ke perangkat ini telah memperoleh persetujuan secara %s dari pengguna perangkat (%s) "
                   "dan dari pihak Wajib Pajak (%s)." % (bentuk, case.get("user_nama") or "-", case.get("nama_wp") or "-"))
            if case.get("dok_persetujuan"):
                txt += "\nDokumen persetujuan tertulis: %s" % case["dok_persetujuan"]
            rows.append(("Persetujuan Akses Perangkat", txt))
    for key, label in (("id_perkara", "ID Perkara / Pemeriksaan"), ("no_berita_acara", "Nomor Berita Acara"),
                       ("perwakilan_wp", "Perwakilan WP / Saksi yang hadir")):
        if case.get(key):
            rows.append((label, case[key]))
    if case.get("kata_kunci_kasus"):
        rows.append(("Kata kunci kasus (petugas)", ", ".join(case["kata_kunci_kasus"])))
    if case.get("tahun_pajak"):
        rows.append(("Tahun/Masa Pajak", case["tahun_pajak"]))
    if case.get("keterangan"):
        rows.append(("Keterangan Perangkat", case["keterangan"]))
    return rows

def sys_rows(osi, session):
    return [("Sistem operasi", os_label(osi)),
            ("Arsitektur OS", "%d-bit (%s) - terdeteksi via %s" % (osi["bits"], osi["arch"], osi["via"])),
            ("Python pelaksana", "%d-bit" % osi["python_bits"]),
            ("Nama komputer", osi["hostname"]), ("Pengguna Windows", osi["user"]),
            ("Hak Administrator", "Ya" if session["admin"] else "TIDAK - sebagian data mungkin tidak lengkap"),
            ("Aplikasi", "%s v%s" % (APP_NAME, APP_VERSION)),
            ("Pembuat aplikasi", APP_AUTHOR)]

def _signature(case, st, width):
    m = _pdf_modules(); Table, TableStyle, Spacer, KT = m["Table"], m["TableStyle"], m["Spacer"], m["KeepTogether"]
    def blk(role, names):
        out = [_P(role, st["key"]), _P("\n\n\n\n", st["base"])]
        for n in names:
            out.append(_P(n, st["base"]))
        return out
    data = [[blk("Pemeriksa Pajak", case["pemeriksa"]), blk("Tenaga Ahli", case["tenaga_ahli"])]]
    t = Table(data, colWidths=[width / 2, width / 2])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    return KT([Spacer(1, 14), _P("Dibuat secara otomatis; ditandatangani oleh:", st["small"]), Spacer(1, 4), t])

def _result_table(r, tool, width, st, max_rows):
    m = _pdf_modules(); Table, TableStyle, colors = m["Table"], m["TableStyle"], m["colors"]
    hdr, rows = r["header"], r["rows"]
    idx = []
    for pref in tool["cols"]:
        for i, h in enumerate(hdr):
            if pref in h.lower() and i not in idx:
                idx.append(i); break
    if len(idx) < 3:
        idx = list(range(min(len(hdr), 7)))
    idx = idx[:9]
    shown = rows[:max_rows]
    data = [[_P("No", st["cellh"])] + [_P(hdr[i], st["cellh"]) for i in idx]]
    for n, row in enumerate(shown, 1):
        data.append([_P(str(n), st["cell"])] + [_P(row[i] if i < len(row) else "", st["cell"]) for i in idx])
    cw = [width * 0.04] + [width * 0.96 / len(idx)] * len(idx)
    t = Table(data, colWidths=cw, repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3A5F")),
                           ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9AA5B1")),
                           ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F7FA")]),
                           ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
    cols_shown = ", ".join(hdr[i] for i in idx)
    return t, len(shown), cols_shown

CAUTION_ALL = ("Menjalankan alat secara live mengubah sebagian state sistem (waktu, perintah, dan media yang dipakai dicatat pada laporan ini). "
               "Alat NirSoft membaca profil akun Windows yang sedang menjalankan aplikasi; atribusi ke akun lain perlu bukti tambahan "
               "(mis. NTUSER.DAT/UsrClass.dat hasil KAPE).")
CAUTION_DEFAULT = "Keluaran alat ini adalah hasil interpretasi, bukan artefak primer; verifikasi ke artefak sumber sebelum dijadikan dasar kesimpulan."
CAUTION = {
    "shellbagsview": "ShellBags umumnya mencatat navigasi folder, bukan pembukaan berkas; identifikasi berkas harus dikonfirmasi dengan LNK, Jump Lists, RecentDocs, atau Office MRU. Hasil interpretasi, bukan artefak primer.",
    "lastactivityview": "Menggabungkan beberapa sumber sehingga makna timestamp berbeda per entri dan entri dapat tidak lengkap. Hasil interpretasi, bukan artefak primer.",
    "usbdeview": "Hasil interpretasi Registry; waktu 'created' tidak selalu berarti koneksi pertama (dapat berubah karena driver dipasang ulang atau pembaruan massal). Huruf drive bukan identitas perangkat; identitas ditentukan nomor seri dan volume serial number. Verifikasi ke USBSTOR, setupapi.dev.log, dan Event Log.",
    "usbdrivelog": "Disusun dari event log dan registry; ketiadaan entri bukan bukti ketiadaan aktivitas (log dapat berputar/terhapus).",
    "driveletterview": "Menunjukkan pemetaan huruf drive saat ini dan yang pernah ada; huruf yang sama dapat dipakai perangkat berbeda pada waktu berbeda.",
    "browsinghistoryview": "Riwayat membuktikan akses ke URL, bukan isi transaksi. Visit count dan waktu dapat dipengaruhi sinkronisasi akun peramban; riwayat dapat dihapus pengguna, sehingga ketiadaan entri bukan bukti ketiadaan akses. Judul halaman dapat berubah.",
    "chromehistoryview": "Riwayat membuktikan akses ke URL, bukan isi transaksi; dapat dipengaruhi sinkronisasi akun peramban dan dapat dihapus pengguna. Tabel unduhan (downloads) tidak ditampilkan alat ini.",
    "mozillahistoryview": "Riwayat membuktikan akses ke URL, bukan isi transaksi; dapat dipengaruhi sinkronisasi dan dapat dihapus pengguna.",
    "iehv": "Riwayat membuktikan akses ke URL, bukan isi transaksi; cakupan terbatas pada peramban berbasis WebCache Windows.",
    "opensavefilesview": "Daftar berkas dari dialog Open/Save per aplikasi; tidak menunjukkan isi berkas dan dapat tidak lengkap.",
    "previousfilesrecovery": "Bergantung pada keberadaan Volume Shadow Copy; ketiadaan versi lama bukan bukti ketiadaan berkas sebelumnya.",
    "networkinterfacesview": "Menggambarkan konfigurasi jaringan saat pengambilan, bukan riwayat.",
    "cports": "Snapshot koneksi saat alat dijalankan, bukan riwayat; koneksi yang sudah tertutup tidak tampak. Pemetaan nama host (DNS) dimatikan. Nama pengguna dan path proses memerlukan hak Administrator.",
    "ofview": "Snapshot berkas yang sedang dibuka saat alat dijalankan; berkas yang telah ditutup tidak tampak. Menunjukkan penggunaan berkas, bukan isinya.",
    "sysexp": "Mengekspor tampilan aplikasi lain; isi yang tampil di layar bukan artefak primer dan dapat memuat data di luar lingkup.",
    "usblogview": "Hanya mencatat peristiwa USB selama jendela pemantauan; bukan riwayat masa lalu.",
}


def _tool_body(r, tool, W, st, max_rows, sec_h=None):
    """Bagian C-E untuk satu alat (dipakai laporan per-alat dan laporan final)."""
    m = _pdf_modules(); mm, Spacer = m["mm"], m["Spacer"]; Preformatted = m["Preformatted"]
    sec_h = sec_h or (lambda t: _P(t, st["h2"]))
    s = []
    b = r["bin"]
    ti = [("Deskripsi alat", tool["desc"]), ("Relevansi pemeriksaan", tool["relevansi"]),
          ("Biner yang dijalankan", "%s  [%s-bit]" % (b["path"] or "-", b["bits"] or "?")),
          ("Versi alat (FileVersion)", b.get("version") or "tidak terbaca dari header PE"),
          ("Alasan pemilihan biner", b["note"]),
          ("SHA-256 biner asli", r["exe_sha256"] or "-"),
          ("Perintah", r["cmd"] or "-"),
          ("Waktu mulai", r["start"].strftime("%d-%m-%Y %H:%M:%S") if r["start"] else "-"),
          ("Waktu selesai", r["end"].strftime("%d-%m-%Y %H:%M:%S") if r["end"] else "-"),
          ("Kode keluar", str(r["exit_code"])), ("Status", r["status"] + ((" - " + r["message"]) if r["message"] else ""))]
    s += [sec_h("C. Informasi Alat dan Eksekusi"), _kv_table(ti, W, st)]
    s += [_P("Catatan kehati-hatian: " + CAUTION.get(tool["key"], CAUTION_DEFAULT) + " " + CAUTION_ALL, st["small"])]
    s += [m["CondPageBreak"](70 * mm), sec_h("D. Hasil")]
    if tool["mode"] == "monitor":
        s.append(_P("Catatan: USBLogView hanya mencatat peristiwa colok/cabut USB yang terjadi selama jendela "
                    "pemantauan; alat ini tidak menampilkan riwayat sebelumnya (lihat USBDeview dan USBDriveLog).", st["small"]))
        s.append(Spacer(1, 4))
        if r["raw_text"].strip():
            lines = [clean(x)[:200] for x in r["raw_text"].splitlines()][:1500]
            s.append(Preformatted("\n".join(lines), st["mono"]))
        else:
            s.append(_P(r["message"] or "Tidak ada data.", st["base"]))
    elif tool["mode"] == "manual":
        s.append(_P(tool.get("manual_text") or "IPNetInfo tidak dijalankan oleh Forensik Runner. Alat ini berbasis GUI (tanpa ekspor baris-perintah) dan mengirim "
                    "kueri whois ke server registri alamat IP melalui internet; menjalankannya pada komputer yang diperiksa akan "
                    "menimbulkan lalu lintas keluar dan mengubah kondisi komputer. Penelusuran dilakukan manual pada komputer lain "
                    "yang terhubung internet dengan perintah:  ipnetinfo.exe /ipfile Daftar_IP_Publik.txt", st["base"]))
        s.append(Spacer(1, 4))
        if r["rows"] and tool["key"] == "ipnetinfo":
            rr = dict(r); rr["header"] = ["IP", "Kemunculan", "Sumber"]
            t, n, cols = _result_table(rr, dict(cols=[]), W, st, max_rows)
            s += [_P("Alamat IPv4 publik yang ditemukan pada hasil alat lain (%d alamat):" % len(r["rows"]), st["small"]), Spacer(1, 3), t]
        elif tool["key"] == "ipnetinfo":
            s.append(_P("Tidak ada alamat IPv4 publik ditemukan pada hasil alat lain.", st["base"]))
    elif r["rows"]:
        t, n, cols = _result_table(r, tool, W, st, max_rows)
        s.append(_P("Jumlah rekaman: %d. Ditampilkan: %d. Kolom pada tabel: %s. Seluruh %d kolom tersedia di berkas "
                    "CSV/HTML pada folder Data_Mentah (hash pada manifest.csv)." % (
                        len(r["rows"]), n, cols, len(r["header"])), st["small"]))
        s += [Spacer(1, 4), t]
        if len(r["rows"]) > n:
            s.append(_P("Tabel dipotong pada %d rekaman; lihat berkas CSV untuk data lengkap." % n, st["small"]))
    else:
        s.append(_P(r["message"] or "Tidak ada data.", st["base"]))
    if r["files"]:
        s += [sec_h("E. Berkas Hasil dan Hash (SHA-256)"),
              _kv_table([(os.path.basename(f), sha256_file(f)) for f in r["files"]], W, st)]
    return s


def make_tool_pdf(path, case, osi, session, r, max_rows=3000):
    m = _pdf_modules()
    A4, landscape, mm = m["A4"], m["landscape"], m["mm"]
    BaseDocTemplate, Frame, PageTemplate = m["BaseDocTemplate"], m["Frame"], m["PageTemplate"]
    Spacer, PageBreak, Preformatted = m["Spacer"], m["PageBreak"], m["Preformatted"]
    tool = TOOL_BY_KEY[r["key"]]; st = _styles(); F = _register_fonts()
    ps = landscape(A4)
    doc = BaseDocTemplate(path, pagesize=ps, leftMargin=15 * mm, rightMargin=15 * mm,
                          topMargin=16 * mm, bottomMargin=17 * mm,
                          title="Laporan Forensik Digital - %s" % tool["title"],
                          author=", ".join(case["pemeriksa"]), subject="NPWP %s" % case["npwp"])
    W = ps[0] - 30 * mm
    doc.addPageTemplates([PageTemplate(id="p", frames=[Frame(15 * mm, 17 * mm, W, ps[1] - 33 * mm, id="f")])])
    s = []
    s += [_P("LAPORAN HASIL FORENSIK DIGITAL", st["h1"]), _P("Alat: %s" % tool["title"], st["h2"])]
    s += [_P("A. Identitas Pemeriksaan", st["h2"]), _kv_table(case_rows(case), W, st)]
    s += [_P("B. Informasi Sistem yang Diperiksa", st["h2"]), _kv_table(sys_rows(osi, session), W, st)]
    s += _tool_body(r, tool, W, st, max_rows)
    s.append(_signature(case, st, W))
    doc.build(s, canvasmaker=_numbered_canvas(case, osi, tool["title"]))


def _fmt_bytes(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return ("%d %s" % (n, u)) if u == "B" else ("%.1f %s" % (n, u))
        n /= 1024


def _kape_chapter(kape, num, W, st, h0, h1, Heading, PageBreak):
    m = _pdf_modules(); Table, TableStyle, colors, Spacer = m["Table"], m["TableStyle"], m["colors"], m["Spacer"]
    Preformatted = m["Preformatted"]
    info, run = kape["info"], kape.get("run")
    def tbl(header, rows, widths):
        data = [[_P(h, st["cellh"]) for h in header]] + [[_P(str(c), st["cell"]) for c in r] for r in rows]
        t = Table(data, colWidths=[W * w for w in widths], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3A5F")),
                               ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9AA5B1")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F7FA")])]))
        return t
    s = [PageBreak(), Heading("%d. KAPE - Kelengkapan dan Eksekusi" % num, h0, 0),
         _P("KAPE (Kroll Artifact Parser and Extractor) mengumpulkan dan mem-parsing artefak forensik Windows. "
            "Bagian ini mencatat kelengkapan paket KAPE yang tersedia dan, bila diminta petugas, hasil eksekusinya.", st["small"])]
    s += [Heading("Kelengkapan paket KAPE", h1, 1), _kv_table([
        ("Lokasi", info["root"]), ("Versi (ChangeLog)", info["version"]),
        ("kape.exe", "Header PE: %s-bit (KAPE hanya menyediakan satu biner)\nSHA-256: %s" % (info["exe_bits"] or "?", info["exe_sha256"])),
        ("gkape.exe (GUI)", "ada" if info["gkape"] else "tidak ada (tidak diperlukan Forensik Runner)"),
        ("Get-KAPEUpdate.ps1 / Dokumentasi-EULA", "%s / %s" % ("ada" if info["has_update_script"] else "tidak ada",
                                                              "ada" if info["has_docs"] else "tidak ada")),
        ("Targets (.tkape)", "%d (di antaranya %d compound)" % (len(info["targets"]), len(info["targets_compound"]))),
        ("Modules (.mkape)", "%d aktif; %d siap pakai; %d belum siap; %d di folder !Disabled" % (
            info.get("n_modules", 0), info.get("n_ready", 0), info.get("n_modules", 0) - info.get("n_ready", 0), info.get("n_disabled", 0))),
        ("Biner di Modules\\bin", ", ".join(info.get("bin_exes", [])) or "tidak ada"),
        ("Catatan", "\n".join(info["issues"]) or "Tidak ada masalah struktur folder terdeteksi."),
    ], W, st), Spacer(1, 6)]
    s += [Heading("Kesiapan modul per kelompok", h1, 1),
          _P("Siap = seluruh biner yang dirujuk modul (termasuk modul compound turunannya) tersedia. Perintah bawaan Windows "
             "(net, netstat, ipconfig, dll.) diverifikasi hanya bila aplikasi berjalan di Windows.", st["small"]), Spacer(1, 3),
          tbl(["Kelompok", "Total", "Siap", "Belum siap", "Biner kurang (contoh)"],
              [(g, t, ok, t - ok, ", ".join(ms)) for g, t, ok, ms in info.get("groups", [])], [.2, .07, .07, .09, .57])]
    mb = info.get("missing_bins", [])
    if mb:
        s += [Heading("Biner yang belum tersedia", h1, 1),
              _P("Biner pihak ketiga ini belum ada di Modules\\bin. Forensik Runner tidak mengunduh apa pun; "
                 "gunakan Get-KAPEUpdate.ps1/--sync secara terpisah bila diperlukan dan diizinkan.", st["small"]), Spacer(1, 3),
              tbl(["Biner", "Modul terdampak", "Sumber (BinaryUrl)"], [(b, c, u or "-") for b, c, u in mb[:40]], [.28, .1, .62])]
    if not run:
        s.append(_P("Eksekusi KAPE tidak diminta pada pelaksanaan ini.", st["base"]))
        return s
    pl = run["plan"]
    s += [PageBreak(), Heading("Eksekusi KAPE", h1, 1), _kv_table([
        ("Profil", pl["label"]), ("Sumber (drive)", run["source"] + ("  (+VSS)" if run["vss"] else "")),
        ("Target dijalankan", ", ".join(pl["targets"]) or "-"),
        ("Modul dijalankan", "%d modul: %s" % (len(pl["modules"]), ", ".join(pl["modules"])) if pl["modules"] else "-"),
        ("Dilewati", "\n".join("%s - %s" % (a, b) for a, b in pl["skipped"]) or "-"),
        ("Perintah", run["cmd"] or "-"),
        ("Waktu mulai", run["start"].strftime("%d-%m-%Y %H:%M:%S") if run["start"] else "-"),
        ("Waktu selesai", run["end"].strftime("%d-%m-%Y %H:%M:%S") if run["end"] else "-"),
        ("Kode keluar", str(run["exit_code"])), ("Status", run["status"] + ((" - " + run["message"]) if run["message"] else "")),
        ("Artefak disalin", "%d berkas, %s" % (run["tfiles"], _fmt_bytes(run["tbytes"]))),
        ("CopyLog / SkipLog", "%s baris / %s baris" % (run["copylog_rows"] if run["copylog_rows"] is not None else "-",
                                                      run["skiplog_rows"] if run["skiplog_rows"] is not None else "-")),
        ("Lokasi data", "Artefak: %s\nKeluaran modul: %s" % (run["tdest"], run["mdest"])),
    ], W, st), Spacer(1, 6)]
    if run["ext_top"]:
        s += [Heading("Ekstensi artefak terbanyak", h1, 1), tbl(["Ekstensi", "Jumlah"], run["ext_top"], [.5, .5])]
    if run["mgroups"]:
        s += [Heading("Keluaran modul per folder", h1, 1),
              tbl(["Folder", "Berkas", "Ukuran", "Baris CSV"], [(a, b, _fmt_bytes(c), d) for a, b, c, d in run["mgroups"][:60]], [.5, .12, .18, .2])]
    if run["console_tail"].strip():
        s += [Heading("Ekor console log KAPE", h1, 1), Preformatted("\n".join(clean(x)[:180] for x in run["console_tail"].splitlines()), st["mono"])]
    s.append(_P("Hash SHA-256 log KAPE dan keluaran modul ada di manifest.csv; artefak salinan (KAPE_Target) tidak di-hash ulang "
                "karena KAPE mencatat SHA-1 setiap berkas pada CopyLog.", st["small"]))
    return s


def _integ_chapter(ig, num, W, st, h0, h1, Heading, PageBreak):
    """Bab integrasi lintas alat: semua keluaran berupa indikator, bukan simpulan."""
    m = _pdf_modules(); Table, TableStyle, colors, Spacer = m["Table"], m["TableStyle"], m["colors"], m["Spacer"]
    def tbl(header, rows, widths):
        data = [[_P(h, st["cellh"]) for h in header]] + [[_P(str(c), st["cell"]) for c in r] for r in rows]
        t = Table(data, colWidths=[W * w for w in widths], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3A5F")),
                               ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9AA5B1")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F7FA")])]))
        return t
    fd = lambda d: d.strftime("%d-%m-%Y %H:%M:%S") if d else "-"
    s = [PageBreak(), Heading("%d. Integrasi Hasil Lintas Alat" % num, h0, 0),
         _P("Bab ini menggabungkan keluaran seluruh alat menjadi satu gambaran. Seluruh isinya adalah INDIKATOR untuk ditelaah "
            "pemeriksa; kecocokan kata kunci atau korelasi bukan bukti dan bukan simpulan pemeriksaan.", st["small"])]
    s += [Heading("Matriks cakupan tema x alat", h1, 1),
          tbl(["Tema", "Alat sumber (status, jumlah rekaman)", "Total rekaman"],
              [(a, b, c) for a, b, c in ig["coverage"]], [.22, .64, .14])]
    s += [Heading("Linimasa terpadu", h1, 1),
          _P("Total %d peristiwa berwaktu dari %d alat; ditampilkan %d terbaru lebih dulu. Data lengkap: Data_Mentah\\Integrasi_Linimasa.csv." % (
              ig["timeline_total"], len(ig["timeline_tools"]), len(ig["timeline"])), st["small"]), Spacer(1, 3)]
    if ig["timeline_tools"]:
        s += [tbl(["Alat", "Kolom waktu", "Rekaman", "Terbaca", "Paling awal", "Paling akhir", "Format tanggal"],
                  [(a, b, c, d, fd(e), fd(f), g) for a, b, c, d, e, f, g in ig["timeline_tools"]], [.17, .15, .08, .08, .15, .15, .22]),
              Spacer(1, 4)]
    if ig["timeline"]:
        s += [tbl(["Waktu", "Alat", "Keterangan"], [(fd(t), a, d) for t, a, d in ig["timeline"]], [.15, .2, .65])]
    else:
        s.append(_P("Tidak ada peristiwa berwaktu yang dapat dibaca.", st["base"]))
    s += [Heading("Korelasi perangkat USB antar alat", h1, 1),
          _P("Pencocokan nomor seri perangkat pada USBDeview, USBDriveLog, dan USBLogView (log pemantauan). "
             "%d perangkat tercatat pada USBDeview dan USBDriveLog sekaligus." % ig["usb_cross_both"], st["small"]), Spacer(1, 3)]
    if ig["usb_cross"]:
        s.append(tbl(["Nomor seri", "Nama perangkat", "USBDeview", "USBDriveLog", "USBLogView", "Waktu tercatat"],
                     ig["usb_cross"][:150], [.2, .3, .1, .11, .11, .18]))
    else:
        s.append(_P("Tidak ada nomor seri perangkat USB yang dapat dikorelasikan.", st["base"]))
    s += [Heading("Jejak akses berkas pada drive removable", h1, 1)]
    if ig["removable_letters"]:
        s.append(_P("Huruf drive removable/USB terdeteksi: %s. Ditemukan %d rekaman pada OpenSaveFilesView, ShellBagsView, "
                    "LastActivityView, dan PreviousFilesRecovery yang merujuk ke drive tersebut (maks. 40 ditampilkan)." % (
                        ", ".join(x + ":" for x in ig["removable_letters"]), ig["ext_hits"]), st["small"]))
        if ig["ext_samples"]:
            s += [Spacer(1, 3), tbl(["Alat", "Rekaman"], ig["ext_samples"], [.2, .8])]
    else:
        s.append(_P("Tidak ada huruf drive removable terdeteksi (DriveLetterView/USBDeview), sehingga korelasi tidak dilakukan.", st["base"]))
    s += [Heading("Indikator kata kunci", h1, 1),
          _P("Pemindaian %d rekaman (riwayat peramban, berkas dibuka/disimpan, aktivitas terakhir, ShellBags, pemulihan berkas, USB) "
             "terhadap daftar kata kunci (%s). Daftar dapat diubah pada indikator_kata_kunci.json." % (
                 ig["records_scanned"], "kustom" if ig["kw_custom"] else "bawaan"), st["small"]), Spacer(1, 3)]
    if ig["keywords"]:
        s.append(tbl(["Kategori", "Rekaman cocok", "Kata kunci terbanyak", "Per alat"],
                     [(k["cat"], k["rows"], ", ".join("%s (%d)" % x for x in k["top"]) or "-",
                       ", ".join("%s: %d" % x for x in k["per_tool"].items()) or "-") for k in ig["keywords"]], [.25, .1, .35, .3]))
        for k in ig["keywords"]:
            if k["samples"]:
                s += [Heading("Contoh: " + k["cat"], h1, 1), tbl(["Alat", "Rekaman"], k["samples"], [.2, .8])]
    ks = ig.get("kasus")
    if ks:
        s += _kasus_sections(ks, W, st, h1, Heading, tbl, fd)
    s.append(Heading("Catatan dan batasan", h1, 1))
    for n in ig["notes"]:
        s.append(_P("- " + n, st["small"]))
    return s


def make_final_pdf(path, case, osi, session, results, max_rows=3000, hw=None, kape=None, integ=None):
    """Satu laporan final: sampul, identitas, daftar isi berhalaman, ringkasan, bab per alat."""
    m = _pdf_modules()
    A4, landscape, mm = m["A4"], m["landscape"], m["mm"]
    BaseDocTemplate, Frame, PageTemplate = m["BaseDocTemplate"], m["Frame"], m["PageTemplate"]
    Spacer, PageBreak, Paragraph = m["Spacer"], m["PageBreak"], m["Paragraph"]
    Table, TableStyle, colors, ParagraphStyle = m["Table"], m["TableStyle"], m["colors"], m["ParagraphStyle"]
    from reportlab.platypus.tableofcontents import TableOfContents
    st = _styles(); F = _register_fonts()
    ps = landscape(A4); W = ps[0] - 30 * mm

    class Heading(Paragraph):
        def __init__(self, text, style, level):
            Paragraph.__init__(self, escape(clean(text)), style); self.toc_level = level; self.toc_text = clean(text)

    class Doc(BaseDocTemplate):
        def __init__(self, *a, **k):
            BaseDocTemplate.__init__(self, *a, **k); self.sections = {}; self._n = 0
        def beforeDocument(self):
            self._n = 0
        def afterFlowable(self, fl):
            if isinstance(fl, Heading):
                self._n += 1; key = "h%d" % self._n
                self.canv.bookmarkPage(key)
                self.canv.addOutlineEntry(fl.toc_text, key, fl.toc_level, 0)
                if fl.toc_level == 0:
                    self.notify("TOCEntry", (0, fl.toc_text, self.page, key))
                if fl.toc_level == 0:
                    self.sections[self.page] = fl.toc_text

    doc = Doc(path, pagesize=ps, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=16 * mm, bottomMargin=17 * mm,
              title="Laporan Final Forensik Digital - %s" % case["nama_wp"], author=", ".join(case["pemeriksa"]),
              subject="NPWP %s" % case["npwp"])
    doc.addPageTemplates([PageTemplate(id="p", frames=[Frame(15 * mm, 17 * mm, W, ps[1] - 33 * mm, id="f")])])

    def NC(*a, **k):
        base = _numbered_canvas(case, osi, "")
        class C(base):
            def _decor(self, n):
                pg = self._pageNumber
                prior = [p for p in doc.sections if p <= pg]
                self._title_override = doc.sections[max(prior)] if prior else "Laporan Final"
                base._decor(self, n)
        c = C(*a, **k); return c

    h0 = ParagraphStyle("H0", fontName=F["bold"], fontSize=16, leading=20, spaceAfter=6, textColor=colors.HexColor("#1F3A5F"))
    h1 = ParagraphStyle("H1", fontName=F["bold"], fontSize=11, leading=14, spaceBefore=10, spaceAfter=4, keepWithNext=1,
                        textColor=colors.HexColor("#1F3A5F"))
    t0 = ParagraphStyle("T0", fontName=F["bold"], fontSize=10.5, leading=15, leftIndent=0)
    t1 = ParagraphStyle("T1", fontName=F["reg"], fontSize=9, leading=12.5, leftIndent=16)
    toc = TableOfContents(); toc.levelStyles = [t0, t1]; toc.dotsMinLevel = 0
    big = ParagraphStyle("big", fontName=F["bold"], fontSize=24, leading=30, textColor=colors.HexColor("#1F3A5F"))

    head = [_P("LAPORAN FINAL", big), _P("Hasil Forensik Digital pada Pemeriksaan Pajak", st["h1"]),
            _P("Direktorat Jenderal Pajak", st["base"]),
            _P("Aplikasi dibuat oleh: %s" % APP_AUTHOR, st["small"])]
    lg = asset("logo_full.jpg")
    if lg:
        try:
            Image = m["Image"]
            ap = asset("app_logo.jpg")
            if ap:
                ht_ = Table([[head, Image(lg, width=44 * mm, height=44 * mm * 804 / 910), Image(ap, width=34 * mm, height=34 * mm * 1109 / 1263)]],
                            colWidths=[W - 84 * mm, 48 * mm, 36 * mm])
            else:
                ht_ = Table([[head, Image(lg, width=52 * mm, height=52 * mm * 804 / 910)]], colWidths=[W - 56 * mm, 56 * mm])
            ht_.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
            head = [ht_]
        except Exception:
            pass
    s = head + [
         Spacer(1, 4), Heading("Identitas Pemeriksaan", h1, 1) if False else _P("Identitas Pemeriksaan", st["h2"]),
         _kv_table(case_rows(case), W, st), _P("Informasi Sistem Aplikasi", st["h2"]),
         _kv_table(sys_rows(osi, session)[:1] + sys_rows(osi, session)[5:7], W, st),
         Spacer(1, 4), _P("Dihasilkan: %s | %d alat dijalankan | Dokumen ini memuat seluruh laporan alat dalam satu berkas." % (
             now().strftime("%d-%m-%Y %H:%M:%S"), len(results)), st["small"]),
         PageBreak(), _P("DAFTAR ISI", h0), toc, PageBreak()]
    # Bab 1 identitas perangkat
    off = 1
    if hw is not None:
        off = 2
        s += [Heading("1. Identitas Perangkat yang Diperiksa", h0, 0),
              _P("Informasi diperoleh otomatis (%s) pada saat pengambilan %s; nama pengguna, jabatan, dan lokasi diisi petugas." % (
                  hw.get("source", "-"), now().strftime("%d-%m-%Y %H:%M:%S")), st["small"]), Spacer(1, 4)]
        rows = [("Pengguna perangkat (diisi petugas)", "Nama: %s\nJabatan: %s\nLokasi: %s" % (
            case["user_nama"], case["user_jabatan"], case["user_lokasi"]))] + \
            hwmod.hardware_rows(hw, osi, session["admin"], case.get("waktu_referensi"))
        data = [[_P("Elemen", st["cellh"]), _P("Informasi yang dicatat", st["cellh"])]] + \
               [[_P(k, st["key"]), _P(v_, st["base"])] for k, v_ in rows]
        ht = Table(data, colWidths=[W * .22, W * .78], repeatRows=1)
        ht.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3A5F")),
                                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9AA5B1")),
                                ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#EEF2F7")),
                                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
        s.append(ht)
        stg = hwmod.storage_rows(hw)
        if stg:
            s += [Heading("Perangkat penyimpanan fisik", h1, 1), _kv_table(stg, W, st)]
        if hw.get("errors"):
            s.append(_P("Catatan pengumpulan: " + "; ".join(hw["errors"]), st["small"]))
        s.append(PageBreak())
    # ringkasan
    s += [Heading("%d. Ringkasan Pelaksanaan" % off, h0, 0)]
    data = [[_P(h, st["cellh"]) for h in ("No", "Alat", "Biner", "Rekaman", "Status")]]
    for i, r in enumerate(results, 1):
        b = r["bin"]
        data.append([_P(str(i + off + (2 if integ else 1)) + ".", st["cell"]), _P(r["title"], st["cell"]),
                     _P("%s-bit%s" % (b["bits"] or "?", "" if b["bits"] == osi["bits"] else " (cadangan)"), st["cell"]),
                     _P(str(len(r["rows"])) if r["rows"] else ("log" if r["raw_text"] else "0"), st["cell"]),
                     _P(r["status"] + ((" - " + r["message"]) if r["message"] else ""), st["cell"])])
    if kape and kape.get("info"):
        kr = kape.get("run")
        data.append([_P(str(len(results) + off + (2 if integ else 1)) + ".", st["cell"]), _P("KAPE", st["cell"]),
                     _P("%s-bit" % (kape["info"]["exe_bits"] or "?"), st["cell"]),
                     _P("%d file" % kr["tfiles"] if kr and kr.get("tfiles") else "-", st["cell"]),
                     _P(("Dijalankan: " + kr["status"] + (" - " + kr["message"] if kr["message"] else "")) if kr else
                        "Kelengkapan diperiksa; eksekusi tidak diminta (%s)" % kmod.summarize(kape["info"]), st["cell"])])
    if integ:
        data.insert(1, [_P(str(off + 1) + ".", st["cell"]), _P("Integrasi lintas alat", st["cell"]),
                     _P("-", st["cell"]), _P("%d peristiwa" % integ["timeline_total"], st["cell"]),
                     _P("Bab sintesis: linimasa, korelasi USB, jejak drive removable, indikator kata kunci", st["cell"])])
    t = Table(data, colWidths=[W * .05, W * .22, W * .13, W * .1, W * .5], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3A5F")),
                           ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9AA5B1")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    s += [t]
    ioff = 0
    if integ:
        ioff = 1
        s += _integ_chapter(integ, off + 1, W, st, h0, h1, Heading, PageBreak)
    # bab per alat
    for i, r in enumerate(results):
        tool = TOOL_BY_KEY[r["key"]]
        s += [PageBreak(), Heading("%d. %s" % (i + off + ioff + 1, tool["title"]), h0, 0),
              _P("Status: %s" % r["status"], st["small"])]
        s += _tool_body(r, tool, W, st, max_rows, sec_h=lambda t_: Heading(t_, h1, 1))
    kn = len(results) + off + ioff + 1
    if kape and kape.get("info"):
        s += _kape_chapter(kape, kn, W, st, h0, h1, Heading, PageBreak)
        kn += 1
    s += [PageBreak(), Heading("%d. Pengesahan" % kn, h0, 0),
          _P("Laporan ini dihasilkan otomatis oleh %s v%s. Data ditampilkan apa adanya sesuai keluaran alat; "
             "simpulan pemeriksaan menjadi tanggung jawab pemeriksa. Pembuat aplikasi: %s." % (APP_NAME, APP_VERSION, APP_AUTHOR), st["base"]),
          _signature(case, st, W)]
    doc.multiBuild(s, canvasmaker=NC)


def make_summary_pdf(path, case, osi, session, results):
    m = _pdf_modules()
    A4, mm, Table, TableStyle, colors = m["A4"], m["mm"], m["Table"], m["TableStyle"], m["colors"]
    BaseDocTemplate, Frame, PageTemplate, Spacer = m["BaseDocTemplate"], m["Frame"], m["PageTemplate"], m["Spacer"]
    st = _styles()
    doc = BaseDocTemplate(path, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=16 * mm,
                          bottomMargin=17 * mm, title="Ringkasan Forensik Digital", author=", ".join(case["pemeriksa"]))
    W = A4[0] - 30 * mm
    doc.addPageTemplates([PageTemplate(id="p", frames=[Frame(15 * mm, 17 * mm, W, A4[1] - 33 * mm, id="f")])])
    s = [_P("RINGKASAN PELAKSANAAN FORENSIK DIGITAL", st["h1"]),
         _P("A. Identitas Pemeriksaan", st["h2"]), _kv_table(case_rows(case), W, st),
         _P("B. Informasi Sistem", st["h2"]), _kv_table(sys_rows(osi, session), W, st),
         _P("C. Status Pelaksanaan Alat", st["h2"])]
    data = [[_P(h, st["cellh"]) for h in ("Alat", "Biner", "Rekaman", "Status")]]
    for r in results:
        b = r["bin"]
        data.append([_P(r["title"], st["cell"]),
                     _P("%s-bit%s" % (b["bits"] or "?", "" if (b["bits"] == osi["bits"]) else " (fallback)"), st["cell"]),
                     _P(str(len(r["rows"])) if r["rows"] else ("log" if r["raw_text"] else "0"), st["cell"]),
                     _P(r["status"] + ((" - " + r["message"]) if r["message"] else ""), st["cell"])])
    t = Table(data, colWidths=[W * .24, W * .14, W * .1, W * .52], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3A5F")),
                           ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9AA5B1")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    s += [t, _signature(case, st, W)]
    doc.build(s, canvasmaker=_numbered_canvas(case, osi, "Ringkasan"))


def write_manifest(root, dirs):
    """Tulis manifest.csv (SHA-256) untuk seluruh hasil kecuali _work dan artefak salinan KAPE."""
    with open(os.path.join(root, "manifest.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f); w.writerow(["berkas", "ukuran_byte", "sha256"])
        for dp, _, fns in os.walk(root):
            if os.path.abspath(dp).startswith(os.path.abspath(dirs["work"])):
                continue
            in_kt = os.path.abspath(dp).startswith(os.path.abspath(dirs["kape_t"]))
            for fn in sorted(fns):
                if fn == "manifest.csv":
                    continue
                if in_kt and not fn.lower().endswith(("_copylog.csv", "_skiplog.csv", "consolelog.txt")):
                    continue   # artefak salinan: hash SHA-1 sudah dicatat KAPE di CopyLog
                p = os.path.join(dp, fn)
                w.writerow([os.path.relpath(p, root), os.path.getsize(p), sha256_file(p)])


def write_state(root, dirs, case_in, osi, session, stamp, results):
    """Simpan keadaan pelaksanaan agar laporan dapat dibangun ulang tanpa menjalankan alat."""
    iso = lambda d: d.isoformat() if d else None
    st = dict(app=APP_NAME, version=APP_VERSION, stamp=stamp, case=case_in, osi=osi,
              session=dict(admin=session["admin"], started=iso(session["started"])),
              tools=[dict(key=r["key"], status=r["status"], message=r["message"], cmd=r["cmd"], exit_code=r["exit_code"],
                          start=iso(r["start"]), end=iso(r["end"]), exe_sha256=r["exe_sha256"], bin=r["bin"],
                          files=[os.path.relpath(x, root) for x in r["files"]]) for r in results])
    with open(os.path.join(dirs["raw"], "_state.json"), "w", encoding="utf-8") as f:
        json.dump(st, f, indent=1, ensure_ascii=False, default=str)


def load_state(root):
    """Muat ulang hasil dari folder pelaksanaan. Mengembalikan (case, osi, session, results, hw)."""
    raw = os.path.join(root, "Data_Mentah")
    st = json.load(open(os.path.join(raw, "_state.json"), encoding="utf-8"))
    err, case = validate_case(st["case"], legacy=True)
    if err:
        raise ValueError("\n".join(err))
    pd = lambda x: dt.datetime.fromisoformat(x) if x else None
    session = dict(admin=st["session"]["admin"], started=pd(st["session"]["started"]))
    results = []
    for t in st["tools"]:
        tool = TOOL_BY_KEY.get(t["key"])
        if not tool:
            continue
        r = dict(key=t["key"], title=tool["title"], status=t["status"], bin=t["bin"], exe_sha256=t["exe_sha256"], cmd=t["cmd"],
                 exit_code=t["exit_code"], start=pd(t["start"]), end=pd(t["end"]), files=[os.path.join(root, x) for x in t["files"]],
                 header=[], rows=[], raw_text="", message=t["message"])
        try:
            if tool["mode"] == "export":
                f = [x for x in r["files"] if x.lower().endswith((".csv", ".txt"))]
                if f and os.path.exists(f[0]):
                    r["header"], r["rows"] = read_csv_rows(f[0], tool.get("delim", ","))
            elif tool["mode"] == "monitor":
                f = [x for x in r["files"] if x.lower().endswith("_log.txt")]
                if f and os.path.exists(f[0]):
                    r["raw_text"] = read_text_auto(f[0])
            else:
                f = [x for x in r["files"] if x.lower().endswith(".csv")]
                if f and os.path.exists(f[0]):
                    h, rows = read_csv_rows(f[0]); r["header"], r["rows"] = ["IP", "Kemunculan", "Sumber"], rows
        except Exception as e:
            r["message"] += " [gagal memuat ulang data: %s]" % e
        results.append(r)
    hw = None
    hp = os.path.join(raw, "Profil_Perangkat.json")
    if os.path.exists(hp):
        hw = json.load(open(hp, encoding="utf-8"))
    return case, st["osi"], session, results, hw


def _kasus_sections(ks, W, st, h1, Heading, tbl, fd):
    """Bagian analisis tingkat-kasus (F20-F22): pengaitan USB, anomali, host/UNC, kata kunci kasus, validasi KAPE."""
    m = _pdf_modules(); Spacer = m["Spacer"]
    s = [Heading("Pengaitan huruf drive ke perangkat dan jejak akses", h1, 1),
         _P("Huruf drive bukan identitas perangkat; identitas ditentukan nomor seri dan volume serial number. Tabel ini mempertemukan "
            "USBDeview/DriveLetterView dengan jejak akses berkas pada OpenSaveFilesView, ShellBagsView, LastActivityView, dan "
            "PreviousFilesRecovery. Data lengkap: Data_Mentah\\Kasus_Pengaitan_USB.csv.", st["small"]), Spacer(1, 3)]
    if ks["usb_rows"]:
        s.append(tbl(["Huruf", "Identitas perangkat (USBDeview)", "DriveLetterView", "Jejak akses", "Awal - akhir", "Alat"],
                     [(r["letter"] + ":", r["ident"], r["dl"], r["n"], "%s -\n%s" % (fd(r["first"]), fd(r["last"])), r["tools"])
                      for r in ks["usb_rows"]], [.06, .34, .13, .08, .17, .22]))
    else:
        s.append(_P("Tidak ada huruf drive non-sistem yang muncul pada perangkat USB maupun jejak akses.", st["base"]))
    s.append(Heading("Anomali dan hal yang perlu dijelaskan", h1, 1))
    if ks["anomalies"]:
        s.append(tbl(["Objek", "Uraian (indikator, bukan simpulan)"], ks["anomalies"], [.14, .86]))
    else:
        s.append(_P("Tidak ada anomali yang terdeteksi oleh aturan aplikasi (created identik, akses sebelum created, huruf dipakai ganda, "
                    "huruf tanpa perangkat, perangkat tanpa huruf, serial tidak unik).", st["base"]))
    s.append(Heading("Host dan share jaringan (UNC)", h1, 1))
    if ks["unc"]:
        s += [_P("Host berupa alamat IP umumnya perangkat jaringan (mis. NAS); nama host umumnya komputer lain. Identifikasi perangkat "
                 "(DHCP/ARP, pemindaian atas dasar kewenangan) dilakukan di luar aplikasi.", st["small"]), Spacer(1, 3),
              tbl(["Host", "Jenis", "Share", "Jejak", "Awal - akhir", "Alat"],
                  [(a["host"], "IP" if a["is_ip"] else "nama host", ", ".join(list(a["shares"])[:4]), a["n"],
                    "%s -\n%s" % (fd(a["first"]), fd(a["last"])), ", ".join(a["tools"])) for a in ks["unc"]], [.17, .08, .25, .06, .2, .24])]
    else:
        s.append(_P("Tidak ditemukan path UNC (\\\\host\\share) pada hasil alat.", st["base"]))
    if ks.get("smb"):
        s += [Heading("Koneksi SMB aktif saat pemeriksaan (CurrPorts)", h1, 1),
              _P("Koneksi ke port 445/139 menunjukkan komputer sedang terhubung ke berbagi berkas jaringan (mis. NAS/komputer lain). "
                 "Ini snapshot saat alat dijalankan, bukan riwayat.", st["small"]), Spacer(1, 3),
              tbl(["Alamat jarak jauh", "Nama host", "Proses", "Status", "Jumlah koneksi"],
                  [(a["addr"], a["host"] or "-", a["proc"], ", ".join(sorted(a["state"])) or "-", a["n"]) for a in ks["smb"]], [.2, .22, .2, .2, .18])]
    s.append(Heading("Penelusuran kata kunci kasus", h1, 1))
    if ks["terms"]:
        s.append(tbl(["Kata kunci", "Jumlah", "Awal - akhir", "Per alat"],
                     [(k["term"], k["n"], "%s -\n%s" % (fd(k["first"]), fd(k["last"])), ", ".join("%s: %d" % kv for kv in k["per"].items()) or "-")
                      for k in ks["case_kw"]], [.22, .08, .22, .48]))
        for k in ks["case_kw"]:
            if k["samples"]:
                s += [Heading("Contoh: " + k["term"], h1, 1), tbl(["Alat", "Rekaman"], k["samples"], [.2, .8])]
    else:
        s.append(_P("Petugas tidak mengisi kata kunci kasus (domain/nama berkas/nama host). Isi pada kolom 'Kata kunci kasus' di aplikasi bila diperlukan.", st["base"]))
    s.append(Heading("Validasi petunjuk ke keluaran KAPE (artefak sumber)", h1, 1))
    v = ks["val"]
    if not v["ran"]:
        s.append(_P("Belum ada keluaran parser KAPE (folder KAPE_Modul kosong/tidak ada), sehingga %d petunjuk NirSoft BELUM tervalidasi ke artefak sumber. "
                    "Jalankan KAPE dengan profil triage/sans/kapetriage (modul !EZParser) lalu bangun ulang laporan." % len(ks["leads"]), st["base"]))
    else:
        ok = sum(1 for x in v["rows"] if x["ok"])
        s += [_P("%d dari %d petunjuk ditemukan sebagai teks pada %d berkas CSV keluaran KAPE (%s)%s. Kecocokan teks hanya indikasi konfirmasi; "
                 "buka artefak asal (LECmd/JLECmd/SBECmd/RECmd/SQLECmd/EvtxECmd) untuk memastikan makna dan waktunya. Data lengkap: "
                 "Data_Mentah\\Kasus_Validasi_KAPE.csv." % (ok, len(v["rows"]), v["files"], _fmt_bytes(v["bytes"]),
                                                              "; sebagian berkas dilewati karena melebihi batas ukuran" if v["truncated"] else ""), st["small"]), Spacer(1, 3)]
        if v["rows"]:
            s.append(tbl(["Jenis", "Petunjuk", "Terkonfirmasi", "Kecocokan", "Modul/berkas keluaran", "Contoh baris"],
                         [(x["kind"], x["lead"][:70], "ya" if x["ok"] else "belum", x["n"], x["mods"], x["sample"][:140]) for x in v["rows"][:80]],
                         [.09, .22, .1, .09, .2, .30]))
    return s


def _lampiran(case, osi, session, hw, ks, W, st, h0, h1, Heading, PageBreak):
    """Lampiran dokumen pendukung (F23): Matriks Uji Bukti, Acquisition Log, Chain of Custody, daftar periksa peer review."""
    m = _pdf_modules(); Table, TableStyle, colors, Spacer = m["Table"], m["TableStyle"], m["colors"], m["Spacer"]
    def tbl(header, rows, widths, minh=None):
        data = [[_P(h, st["cellh"]) for h in header]] + [[_P(str(c), st["cell"]) for c in r] for r in rows]
        t = Table(data, colWidths=[W * w for w in widths], repeatRows=1, rowHeights=None)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3A5F")),
                               ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9AA5B1")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                               ("TOPPADDING", (0, 0), (-1, -1), 4 if minh else 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 8 if minh else 2)]))
        return t
    blank = "______________________"
    s = [PageBreak(), Heading("Lampiran A. Matriks Uji Bukti Digital (terisi sebagian)", h0, 0),
         _P("Disusun mengikuti Template 15.1 modul DART Modern. Kolom Proposisi, Artefak, Hash, Tool+Versi, Attribution, dan Corroboration "
            "diisi otomatis dari data yang tersedia; kolom Kontradiksi diisi sebagian oleh aplikasi dan HARUS dilengkapi pemeriksa "
            "(termasuk menguji pemindaian antivirus/backup, salinan yang mempertahankan stempel waktu, akun bersama, dan zona waktu); "
            "kolom Kesimpulan diisi pemeriksa sesuai rubrik kekuatan kesimpulan (aplikasi tidak menyimpulkan).", st["small"]), Spacer(1, 3)]
    mx = (ks or {}).get("matrix") or []
    rows = [(i, a, b, c_, d, e, f, g or "-", "(diisi pemeriksa)") for i, (a, b, c_, d, e, f, g) in enumerate(mx, 1)]
    for j in range(len(rows) + 1, max(len(rows), 4) + 3):
        rows.append((j, "", "", "", "", "", "", "", ""))
    s.append(tbl(["No", "Proposisi", "Artefak / Sumber", "Hash / Integrity (SHA-256 berkas ekspor)", "Tool + Versi", "Attribution",
                  "Corroboration", "Contradiction", "Kesimpulan"], rows, [.03, .14, .16, .12, .1, .12, .12, .1, .11], minh=True))
    tz = ((hw or {}).get("tz") or {}).get("id") or "tidak diketahui"
    st_, en_ = session.get("started"), now()
    s += [PageBreak(), Heading("Lampiran B. Acquisition Log (Template 4.3 modul)", h0, 0),
          _P("Diisi sebagian dari data aplikasi; kolom bertanda garis diisi petugas. Aplikasi ini melakukan triage live (logis/targeted), bukan "
             "pengimejan fisik; untuk akuisisi media (FTK Imager, write blocker) gunakan formulir tersendiri.", st["small"]), Spacer(1, 3)]
    kv = [("Case / Examination ID", case.get("id_perkara") or blank), ("Evidence ID", blank),
          ("Device / Media", "%s %s" % ((hw or {}).get("manufacturer") or "", (hw or {}).get("model") or "") if hw else blank),
          ("Make / Model", "%s / %s" % ((hw or {}).get("manufacturer") or "-", (hw or {}).get("model") or "-")),
          ("Serial Number", (hw or {}).get("serial") or blank), ("Custodian / Source", "%s, %s, %s" % (case["user_nama"], case["user_jabatan"], case["user_lokasi"])),
          ("Power state", "Menyala (live)"), ("Encryption status", "Lihat Bab 1 (BitLocker) pada Laporan Final"),
          ("Date-Time Start", st_.strftime("%d-%m-%Y %H:%M:%S") if st_ else blank), ("Date-Time End", en_.strftime("%d-%m-%Y %H:%M:%S")),
          ("Timezone", tz), ("Acquisition Tool + Version", "%s v%s (menjalankan alat NirSoft/KAPE; versi tiap alat pada bab alat)" % (APP_NAME, APP_VERSION)),
          ("Acquisition Type", "Live triage logis/targeted (bukan image fisik)"), ("Image Format", "-"),
          ("Source Size / Output Size", blank), ("Output Filename", "Folder hasil pelaksanaan (Data_Mentah, Laporan_PDF, manifest.csv)"),
          ("SHA-256", "Lihat manifest.csv (hash tiap berkas hasil)"), ("Secondary Hash (optional)", "-"),
          ("Examiner", "; ".join(case["pemeriksa"] + case["tenaga_ahli"])), ("Witness/Reviewer", case.get("perwakilan_wp") or blank),
          ("Notes/Anomalies", blank),
          ("Dasar kewenangan / No. surat perintah", "SP2 %s tgl %s; ST %s tgl %s" % (case["sp2_no"], tgl_id(case["sp2_tgl"]), case["st_no"], tgl_id(case["st_tgl"]))),
          ("No. berita acara dan para hadir (termasuk perwakilan WP)", case.get("no_berita_acara") or blank),
          ("Identitas write blocker dan hasil uji", "Tidak berlaku (live triage)"),
          ("Status BitLocker dan custodian kunci pemulihan", blank), ("Hasil verifikasi hash (sumber vs image)", "Tidak berlaku"),
          ("Bad sector / error selama akuisisi", "Lihat log_proses.txt"), ("Data di luar scope yang terpapar dan penanganannya", blank)]
    s.append(_kv_table(kv, W, st))
    s += [PageBreak(), Heading("Lampiran C. Formulir Chain of Custody (Bab V modul)", h0, 0),
          _P("Catat setiap perpindahan penguasaan folder hasil, media penyimpanan hasil, dan salinan kerja. Verifikasi ulang hash pada setiap serah terima "
             "(bandingkan dengan manifest.csv).", st["small"]), Spacer(1, 3)]
    s.append(tbl(["No", "Tanggal / waktu", "Evidence / berkas", "Dari (nama, jabatan)", "Kepada (nama, jabatan)", "Tujuan", "Hash terverifikasi (ya/tidak)", "Paraf pemberi / penerima"],
                 [(i, "", "", "", "", "", "", "") for i in range(1, 8)], [.04, .12, .16, .15, .15, .13, .11, .14], minh=True))
    s += [Spacer(1, 10), Heading("Lampiran D. Daftar Periksa Peer Review (Bab XVII modul)", h1, 1)]
    qs = ["Apakah input evidence dan hash dapat ditelusuri?", "Apakah tool/version dicatat?", "Apakah timestamp/timezone dijelaskan?",
          "Apakah attribution mempunyai dasar?", "Apakah kesimpulan melebihi kemampuan artefak?", "Apakah ada corroboration independen?",
          "Apakah contradictory evidence dicari dan dibahas?", "Apakah langkah dapat direproduksi?", "Apakah data di luar scope diminimalkan?",
          "Apakah screenshot didukung artefak/output mentah?", "Apakah perolehan bukti sah dan dokumen kewenangan terlampir?",
          "Apakah data pribadi di luar scope dilindungi dan tidak dimuat dalam laporan?"]
    s.append(tbl(["No", "Pertanyaan reviewer", "Ya / Tidak", "Catatan"], [(i, q, "", "") for i, q in enumerate(qs, 1)], [.04, .56, .1, .3], minh=True))
    return s


def make_integrasi_pdf(path, case, osi, session, results, hw, integ):
    """Laporan Integrasi mandiri: identitas, status seluruh alat, dan bab integrasi lintas alat."""
    m = _pdf_modules()
    A4, landscape, mm = m["A4"], m["landscape"], m["mm"]
    BaseDocTemplate, Frame, PageTemplate = m["BaseDocTemplate"], m["Frame"], m["PageTemplate"]
    Spacer, PageBreak, Paragraph = m["Spacer"], m["PageBreak"], m["Paragraph"]
    Table, TableStyle, colors, ParagraphStyle = m["Table"], m["TableStyle"], m["colors"], m["ParagraphStyle"]
    st = _styles(); F = _register_fonts()
    ps = landscape(A4); W = ps[0] - 30 * mm
    doc = BaseDocTemplate(path, pagesize=ps, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=16 * mm, bottomMargin=17 * mm,
                          title="Laporan Integrasi Forensik Digital - %s" % case["nama_wp"], author=", ".join(case["pemeriksa"]),
                          subject="NPWP %s" % case["npwp"])
    doc.addPageTemplates([PageTemplate(id="p", frames=[Frame(15 * mm, 17 * mm, W, ps[1] - 33 * mm, id="f")])])
    h0 = ParagraphStyle("H0", fontName=F["bold"], fontSize=16, leading=20, spaceAfter=6, textColor=colors.HexColor("#1F3A5F"))
    h1 = ParagraphStyle("H1", fontName=F["bold"], fontSize=11, leading=14, spaceBefore=10, spaceAfter=4, keepWithNext=1,
                        textColor=colors.HexColor("#1F3A5F"))
    big = ParagraphStyle("big", fontName=F["bold"], fontSize=22, leading=28, textColor=colors.HexColor("#1F3A5F"))
    Heading = lambda text, style, level: Paragraph(escape(clean(text)), style)
    head = [_P("LAPORAN INTEGRASI", big), _P("Gabungan Hasil Seluruh Alat Forensik Digital", st["h1"]),
            _P("Direktorat Jenderal Pajak | Aplikasi dibuat oleh: %s" % APP_AUTHOR, st["small"])]
    lg = asset("logo_full.jpg")
    if lg:
        try:
            ap = asset("app_logo.jpg")
            if ap:
                ht_ = Table([[head, m["Image"](lg, width=38 * mm, height=38 * mm * 804 / 910), m["Image"](ap, width=30 * mm, height=30 * mm * 1109 / 1263)]],
                            colWidths=[W - 74 * mm, 41 * mm, 33 * mm])
            else:
                ht_ = Table([[head, m["Image"](lg, width=44 * mm, height=44 * mm * 804 / 910)]], colWidths=[W - 48 * mm, 48 * mm])
            ht_.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")])); head = [ht_]
        except Exception:
            pass
    s = head + [Spacer(1, 4), _P("Identitas Pemeriksaan", st["h2"]), _kv_table(case_rows(case), W, st)]
    if hw is not None:
        rows = [("Pengguna perangkat", "%s / %s / %s" % (case["user_nama"], case["user_jabatan"], case["user_lokasi"]))] + \
               [x for x in hwmod.hardware_rows(hw, osi, session["admin"], case.get("waktu_referensi"))
                if x[0].split()[0].lower() in ("manufacturer", "product/model", "system", "hostname", "uuid", "os", "operating")]
        s += [_P("Perangkat yang Diperiksa (ringkas)", st["h2"]), _kv_table(rows, W, st)]
    data = [[_P(h, st["cellh"]) for h in ("No", "Alat", "Biner", "Rekaman", "Status")]]
    for i, r in enumerate(results, 1):
        b = r["bin"]
        data.append([_P(str(i), st["cell"]), _P(r["title"], st["cell"]), _P("%s-bit" % (b.get("bits") or "?"), st["cell"]),
                     _P(str(len(r["rows"])) if r["rows"] else ("log" if r["raw_text"] else "0"), st["cell"]),
                     _P(r["status"] + ((" - " + r["message"]) if r["message"] else ""), st["cell"])])
    t = Table(data, colWidths=[W * .05, W * .22, W * .1, W * .1, W * .53], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3A5F")),
                           ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9AA5B1")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    s += [_P("Status Seluruh Alat", st["h2"]), t]
    s += _integ_chapter(integ, 1, W, st, h0, h1, Heading, PageBreak)
    s += _lampiran(case, osi, session, hw, integ.get("kasus"), W, st, h0, h1, Heading, PageBreak)
    s += [PageBreak(), _P("Pengesahan", h0),
          _P("Laporan integrasi ini dihasilkan otomatis oleh %s v%s dan merangkum keluaran seluruh alat; rincian tiap alat ada pada "
             "Laporan Final dan PDF per alat. Simpulan pemeriksaan menjadi tanggung jawab pemeriksa. Pembuat aplikasi: %s." % (
                 APP_NAME, APP_VERSION, APP_AUTHOR), st["base"]), _signature(case, st, W)]
    doc.build(s, canvasmaker=_numbered_canvas(case, osi, "Laporan Integrasi"))


def build_reports(case, osi, session, results, hw, kape, dirs, stamp, log):
    """Analisis integrasi + laporan Final + laporan Integrasi mandiri."""
    integ = None
    try:
        app_dir = os.path.dirname(os.path.abspath(__file__))
        igmod.write_default_keywords(app_dir)
        integ = igmod.analyze(results, hw=hw, app_dir=app_dir, tools_meta={t["key"]: t["cols"] for t in TOOLS})
        try:
            integ["kasus"] = kasmod.analyze_kasus(results, case, integ, kape_m=dirs.get("kape_m"), osi_user=osi.get("user", ""))
            igmod.export_kasus_csv(integ["kasus"], dirs["raw"])
            ks = integ["kasus"]
            log("Analisis kasus: %d huruf drive, %d anomali USB, %d host/UNC, %d kata kunci kasus, validasi KAPE: %s" % (
                len(ks["usb_rows"]), len(ks["anomalies"]), len(ks["unc"]), len(ks["terms"]),
                ("%d/%d petunjuk terkonfirmasi" % (sum(1 for x in ks["val"]["rows"] if x["ok"]), len(ks["val"]["rows"]))) if ks["val"]["ran"] else "KAPE belum dijalankan"))
        except Exception as e:
            integ["kasus"] = None
            log("Analisis kasus gagal: %s: %s" % (type(e).__name__, e))
        igmod.export_csv(integ, dirs["raw"])
        log("Integrasi lintas alat: %d peristiwa berwaktu, %d serial USB, %d jejak drive removable" % (
            integ["timeline_total"], len(integ["usb_cross"]), integ["ext_hits"]))
    except Exception as e:
        integ = None
        log("Integrasi lintas alat gagal: %s: %s" % (type(e).__name__, e))
    try:
        fp = os.path.join(dirs["pdf"], "00_LAPORAN_FINAL_%s.pdf" % stamp)
        make_final_pdf(fp, case, osi, session, results, hw=hw, kape=kape, integ=integ)
        log("LAPORAN FINAL (gabungan, dengan daftar isi): %s" % fp)
    except Exception as e:
        log("GAGAL membuat laporan final: %s: %s" % (type(e).__name__, e))
    if integ:
        try:
            ip_ = os.path.join(dirs["pdf"], "01_LAPORAN_INTEGRASI_%s.pdf" % stamp)
            make_integrasi_pdf(ip_, case, osi, session, results, hw, integ)
            log("LAPORAN INTEGRASI (mandiri): %s" % ip_)
        except Exception as e:
            log("GAGAL membuat laporan integrasi: %s: %s" % (type(e).__name__, e))
    return integ


def rebuild_reports(root, log=print):
    """Bangun ulang Laporan Final + Integrasi dari folder hasil yang sudah ada (tanpa menjalankan alat)."""
    root = os.path.abspath(root)
    case, osi, session, results, hw = load_state(root)
    dirs = dict(root=root, pdf=os.path.join(root, "Laporan_PDF"), raw=os.path.join(root, "Data_Mentah"),
                work=os.path.join(root, "_work"), kape_t=os.path.join(root, "KAPE_Target"), kape_m=os.path.join(root, "KAPE_Modul"))
    os.makedirs(dirs["pdf"], exist_ok=True)
    stamp = "ulang_" + now().strftime("%Y%m%d_%H%M%S")
    log("Membangun ulang laporan dari %s (%d alat dimuat; bab KAPE tidak ikut)" % (root, len(results)))
    build_reports(case, osi, session, results, hw, None, dirs, stamp, log)
    write_manifest(root, dirs)
    with open(os.path.join(root, "log_proses.txt"), "a", encoding="utf-8") as f:
        f.write("\n[%s] Laporan dibangun ulang (%s)\n" % (now().strftime("%H:%M:%S"), stamp))
    return dirs["pdf"], stamp


# ---------------------------------------------------------------- orkestrasi
def run_all(case_in, tools_dir, out_root, selected=None, monitor_seconds=30, log=print, progress=None, use_ntp=True, kape_cfg=None):
    """Jalankan semua alat terpilih. Mengembalikan (folder_hasil, daftar_hasil)."""
    err, case = validate_case(case_in)
    if err:
        raise ValueError("\n".join(err))
    tools_dir, out_root = os.path.abspath(tools_dir), os.path.abspath(out_root)
    osi = detect_os()
    session = dict(admin=is_admin(), started=now())
    stamp = session["started"].strftime("%Y%m%d_%H%M%S")
    root = os.path.join(out_root, "%s_%s" % (case["npwp_digits"], stamp))
    dirs = dict(root=root, pdf=os.path.join(root, "Laporan_PDF"), raw=os.path.join(root, "Data_Mentah"),
                work=os.path.join(root, "_work"))
    for d in dirs.values():
        os.makedirs(d, exist_ok=True)
    dirs["kape_t"] = os.path.join(root, "KAPE_Target")
    dirs["kape_m"] = os.path.join(root, "KAPE_Modul")
    lines = []
    def L(msg):
        line = "[%s] %s" % (now().strftime("%H:%M:%S"), msg)
        lines.append(line); log(line)
    L("%s v%s dimulai | pembuat aplikasi: %s" % (APP_NAME, APP_VERSION, APP_AUTHOR))
    L("Sistem operasi: %s | Python %d-bit | admin=%s" % (os_label(osi), osi["python_bits"], session["admin"]))
    L("Keputusan: OS %d-bit -> %s" % (osi["bits"], "gunakan alat 64-bit bila tersedia" if osi["bits"] == 64
                                       else "gunakan alat 32-bit"))
    if not session["admin"]:
        L("PERINGATAN: tidak berjalan sebagai Administrator; sebagian data bisa kosong.")
    L("Mengumpulkan identitas perangkat (hardware/OS)...")
    hw = hwmod.collect_hardware(use_ntp=use_ntp)
    hwf = os.path.join(dirs["raw"], "Profil_Perangkat.json")
    with open(hwf, "w", encoding="utf-8") as f:
        json.dump(hw, f, indent=2, ensure_ascii=False, default=str)
    L("  perangkat: %s %s | serial %s | sumber %s" % (hw.get("manufacturer"), hw.get("model"), hw.get("serial"), hw.get("source")))
    todo = [t for t in TOOLS if (not selected or t["key"] in selected)]
    results = []
    for i, tool in enumerate(todo):
        if progress:
            progress(i, len(todo), tool["key"], "berjalan")
        binfo = resolve_binary(tools_dir, tool, osi["bits"])
        L("[%d/%d] %s -> %s [%s-bit] %s" % (i + 1, len(todo), tool["title"], binfo["path"] or "-",
                                            binfo["bits"] or "?", binfo["note"]))
        r = run_tool(tool, binfo, dirs, monitor_seconds, lambda x: L(x))
        if tool["mode"] == "manual":
            r = run_manual(tool, r, dirs, results, L)
        L("  status: %s %s" % (r["status"], r["message"]))
        try:
            pdf = os.path.join(dirs["pdf"], "%02d_%s_%s.pdf" % (i + 1, tool["title"], stamp))
            make_tool_pdf(pdf, case, osi, session, r)
            r["pdf"] = pdf
            L("  PDF: %s" % pdf)
        except Exception as e:
            r["pdf"] = None
            L("  GAGAL membuat PDF: %s: %s" % (type(e).__name__, e))
        results.append(r)
        if progress:
            progress(i + 1, len(todo), tool["key"], r["status"])
    # ---- KAPE (pemeriksaan kelengkapan selalu; eksekusi hanya bila diminta & dikonfirmasi)
    kape = None
    kroot = kmod.find_kape(tools_dir)
    if kroot:
        try:
            kinfo = kmod.inspect_kape(kroot)
            kape = dict(info=kinfo, run=None)
            L("KAPE ditemukan: %s" % kmod.summarize(kinfo))
            with open(os.path.join(dirs["raw"], "KAPE_Kelengkapan_Modul.csv"), "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f); w.writerow(["modul", "kelompok", "siap", "biner_kurang", "deskripsi"])
                for m_ in sorted(kinfo["mods"].values(), key=lambda x: (x["group"], x["name"].lower())):
                    if not m_["disabled"]:
                        w.writerow([m_["name"], m_["group"], "ya" if m_.get("ready") else "tidak", "; ".join(m_.get("missing", [])), m_["desc"]])
            if kape_cfg and kape_cfg.get("run"):
                plan = kmod.plan_run(kinfo, kape_cfg.get("profile", "live"), kape_cfg.get("targets", []), kape_cfg.get("modules", []))
                if progress:
                    progress(len(todo), len(todo) + 1, "kape", "berjalan")
                L("KAPE: menjalankan profil '%s' | target=%s | modul=%d | dilewati=%d" % (
                    plan["profile"], plan["targets"], len(plan["modules"]), len(plan["skipped"])))
                try:
                    free = shutil.disk_usage(out_root).free
                    L("  ruang kosong di folder hasil: %.1f GB" % (free / 1024 ** 3))
                except Exception:
                    pass
                kape["run"] = kmod.run_kape(kinfo, plan, kape_cfg.get("source") or (os.environ.get("SystemDrive", "C:")), bool(kape_cfg.get("vss")),
                                            dirs, int(kape_cfg.get("timeout", 14400)), L, session["admin"], dry=bool(kape_cfg.get("dry")))
                L("  KAPE status: %s %s" % (kape["run"]["status"], kape["run"]["message"]))
                if progress:
                    progress(len(todo) + 1, len(todo) + 1, "kape", kape["run"]["status"])
            else:
                L("KAPE: eksekusi tidak diminta (hanya pemeriksaan kelengkapan).")
        except Exception as e:
            L("KAPE: gagal diperiksa/dijalankan: %s: %s" % (type(e).__name__, e))
    else:
        L("KAPE: tidak ditemukan di folder alat.")
    build_reports(case, osi, session, results, hw, kape, dirs, stamp, L)
    write_state(root, dirs, case_in, osi, session, stamp, results)
    write_manifest(root, dirs)
    L("Selesai. Folder hasil: %s" % root)
    with open(os.path.join(root, "log_proses.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return root, results
