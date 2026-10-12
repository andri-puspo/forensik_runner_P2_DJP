# -*- coding: utf-8 -*-
"""Pengumpulan identitas perangkat (hardware/OS) yang diperiksa - otomatis, hanya baca."""
import datetime as dt, json, os, socket, struct, subprocess, sys, tempfile, time

IS_WIN = sys.platform == "win32"
NA = "tidak tersedia"

PS_SCRIPT = r'''
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
function Fmt($d) { if ($d) { try { return ([datetime]$d).ToString('yyyy-MM-dd HH:mm:ss') } catch { return "$d" } } return $null }
$cs   = Get-CimInstance Win32_ComputerSystem
$csp  = Get-CimInstance Win32_ComputerSystemProduct
$bios = Get-CimInstance Win32_BIOS
$bb   = Get-CimInstance Win32_BaseBoard
$os   = Get-CimInstance Win32_OperatingSystem
$cpu  = @(Get-CimInstance Win32_Processor)
$mem  = @(Get-CimInstance Win32_PhysicalMemory)
$dsk  = @(Get-CimInstance Win32_DiskDrive)
$nic  = @(Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true })
$cfg  = @(Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true })
$bt   = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPClass -eq 'Bluetooth' })
$tz   = Get-TimeZone
$r = [ordered]@{}
$r.manufacturer = $cs.Manufacturer
$r.model        = $cs.Model
$r.version      = $csp.Version
$r.serial       = $csp.IdentifyingNumber
$r.uuid         = $csp.UUID
$r.bios = [ordered]@{ serial = $bios.SerialNumber; version = $bios.SMBIOSBIOSVersion; manufacturer = $bios.Manufacturer; release_date = (Fmt $bios.ReleaseDate) }
$r.baseboard = [ordered]@{ manufacturer = $bb.Manufacturer; product = $bb.Product; serial = $bb.SerialNumber }
$r.hostname = $cs.Name
$r.domain = $cs.Domain
$r.part_of_domain = [bool]$cs.PartOfDomain
$r.os = [ordered]@{ caption = $os.Caption; version = $os.Version; build = $os.BuildNumber; arch = $os.OSArchitecture; install_date = (Fmt $os.InstallDate); last_boot = (Fmt $os.LastBootUpTime); registered_user = $os.RegisteredUser; system_drive = $os.SystemDrive }
$r.cpu = @($cpu | ForEach-Object { [ordered]@{ name = "$($_.Name)".Trim(); cores = $_.NumberOfCores; threads = $_.NumberOfLogicalProcessors; arch = $_.Architecture } })
$r.ram_total = $cs.TotalPhysicalMemory
$r.ram_modules = @($mem | ForEach-Object { [ordered]@{ capacity = $_.Capacity; manufacturer = $_.Manufacturer; speed = $_.Speed; part = "$($_.PartNumber)".Trim(); serial = $_.SerialNumber } })
$r.disks = @($dsk | ForEach-Object { [ordered]@{ model = $_.Model; serial = "$($_.SerialNumber)".Trim(); size = $_.Size; iface = $_.InterfaceType } })
$r.nics = @($nic | ForEach-Object { [ordered]@{ name = $_.Name; mac = $_.MACAddress; connection = $_.NetConnectionID; type = $_.AdapterType; enabled = $_.NetEnabled } })
$r.ipcfg = @($cfg | ForEach-Object { [ordered]@{ desc = $_.Description; mac = $_.MACAddress; ip = @($_.IPAddress); subnet = @($_.IPSubnet); gateway = @($_.DefaultIPGateway); dns = @($_.DNSServerSearchOrder); dhcp = $_.DHCPEnabled; dhcp_server = $_.DHCPServer } })
$r.bluetooth = @($bt | ForEach-Object { $_.Name })
$r.tz = [ordered]@{ id = $tz.Id; name = $tz.DisplayName; standard = $tz.StandardName; offset = "$($tz.BaseUtcOffset)"; dst_supported = $tz.SupportsDaylightSavingTime; dst_active = (Get-Date).IsDaylightSavingTime() }
$r.clock_local = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
$r.clock_utc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss.fff')
$sbk = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
if ($sbk) { $r.uefi = $true; $r.secure_boot = [bool]($sbk.UEFISecureBootEnabled -eq 1) } else { $r.uefi = $false; $r.secure_boot = $null }
$t = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm
if ($t) { $r.tpm = [ordered]@{ spec = $t.SpecVersion; enabled = $t.IsEnabled_InitialValue; activated = $t.IsActivated_InitialValue; manufacturer = $t.ManufacturerIdTxt } } else { $r.tpm = $null }
$bl = @(Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume | ForEach-Object { [ordered]@{ drive = $_.DriveLetter; protection = $_.ProtectionStatus; conversion = $_.ConversionStatus; method = $_.EncryptionMethod } })
$r.bitlocker = $bl
$r.bitlocker_readable = ($bl.Count -gt 0)
$r | ConvertTo-Json -Depth 6 -Compress
'''


def aslist(v):
    return [] if v is None else (v if isinstance(v, list) else [v])


def ntp_check(servers=("time.windows.com", "pool.ntp.org"), timeout=3):
    """Bandingkan jam perangkat dengan NTP (SNTP). Mengembalikan dict atau None bila tak ada jaringan."""
    for host in servers:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
            t0 = time.time()
            s.sendto(b"\x1b" + 47 * b"\0", (host, 123))
            data, _ = s.recvfrom(64); t1 = time.time(); s.close()
            sec, frac = struct.unpack("!II", data[40:48])
            ntp = sec - 2208988800 + frac / 2 ** 32
            mid = (t0 + t1) / 2
            return dict(server=host, ntp_utc=dt.datetime.utcfromtimestamp(ntp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        device_utc=dt.datetime.utcfromtimestamp(mid).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        offset_sec=round(mid - ntp, 3), rtt_sec=round(t1 - t0, 3))
        except Exception:
            continue
    return None


def _linux_fallback():
    def rd(p):
        try:
            return open(p).read().strip()
        except Exception:
            return None
    d = "/sys/class/dmi/id/"
    cpu = None
    try:
        for l in open("/proc/cpuinfo"):
            if l.startswith("model name"):
                cpu = l.split(":", 1)[1].strip(); break
    except Exception:
        pass
    ram = None
    try:
        ram = int(open("/proc/meminfo").readline().split()[1]) * 1024
    except Exception:
        pass
    now = dt.datetime.now()
    return dict(manufacturer=rd(d + "sys_vendor"), model=rd(d + "product_name"), version=rd(d + "product_version"),
                serial=rd(d + "product_serial"), uuid=rd(d + "product_uuid"),
                bios=dict(serial=None, version=rd(d + "bios_version"), manufacturer=rd(d + "bios_vendor"),
                          release_date=rd(d + "bios_date")),
                baseboard=dict(manufacturer=rd(d + "board_vendor"), product=rd(d + "board_name"), serial=rd(d + "board_serial")),
                hostname=socket.gethostname(), domain=None, part_of_domain=False,
                os=dict(caption=None, version=None, build=None, arch=None, install_date=None),
                cpu=[dict(name=cpu, cores=os.cpu_count(), threads=os.cpu_count(), arch=None)], ram_total=ram,
                ram_modules=[], disks=[], nics=[], ipcfg=[], bluetooth=[],
                tz=dict(id=time.tzname[0], name=time.tzname[0], offset=str(-time.timezone // 3600), dst_supported=None, dst_active=None),
                clock_local=now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                clock_utc=dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                uefi=os.path.isdir("/sys/firmware/efi"), secure_boot=None, tpm=None, bitlocker=[], bitlocker_readable=False)


def collect_hardware(use_ntp=True, log=print):
    hw = dict(errors=[])
    if IS_WIN:
        try:
            fd, path = tempfile.mkstemp(suffix=".ps1"); os.close(fd)
            open(path, "w", encoding="utf-8-sig").write(PS_SCRIPT)
            p = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path],
                               capture_output=True, timeout=180, creationflags=0x08000000)
            os.remove(path)
            txt = p.stdout.decode("utf-8-sig", "replace").strip()
            hw.update(json.loads(txt))
            hw["source"] = "PowerShell/CIM (WMI)"
        except Exception as e:
            hw["errors"].append("Pengumpulan CIM gagal: %s: %s" % (type(e).__name__, e))
            hw["source"] = "gagal"
    else:
        hw.update(_linux_fallback()); hw["source"] = "sysfs (pengujian non-Windows)"
    hw["ntp"] = ntp_check() if use_ntp else None
    hw["ntp_requested"] = bool(use_ntp)
    return hw


# ------------------------------------------------------------------ format untuk laporan
def _v(x):
    return NA if x in (None, "", [], {}) else str(x)

def _gb(b):
    try:
        return "%.1f GB" % (int(b) / 1024 ** 3)
    except Exception:
        return NA

_ARCH = {0: "x86", 5: "ARM", 9: "x64 (AMD64)", 12: "ARM64"}
_PROT = {0: "TIDAK terproteksi (OFF)", 1: "Terproteksi (ON)", 2: "Status tidak diketahui"}
_CONV = {0: "Tidak terenkripsi", 1: "Terenkripsi penuh", 2: "Enkripsi sedang berjalan", 3: "Dekripsi sedang berjalan",
         4: "Enkripsi dijeda", 5: "Dekripsi dijeda"}

def hardware_rows(hw, osi, is_admin, manual_ref=None):
    """Baris tabel 'Elemen | Informasi yang dicatat'."""
    g = hw.get
    bios, bb, osd, tz = g("bios") or {}, g("baseboard") or {}, g("os") or {}, g("tz") or {}
    R = []
    R.append(("Manufacturer", _v(g("manufacturer"))))
    model = _v(g("model"))
    if g("version"):
        model += "  (versi produk: %s)" % g("version")
    if bb.get("product"):
        model += "\nPapan induk: %s %s" % (bb.get("manufacturer") or "", bb.get("product"))
    R.append(("Product/Model", model))
    R.append(("System Serial Number", _v(g("serial")) + ("\nSerial papan induk: %s" % bb["serial"] if bb.get("serial") else "")))
    mode = {True: "UEFI", False: "Legacy BIOS / tidak terdeteksi UEFI", None: NA}[g("uefi")] if "uefi" in hw else NA
    R.append(("BIOS/UEFI Serial", "%s\nVersi: %s | Produsen: %s | Tanggal rilis: %s | Mode boot: %s" % (
        _v(bios.get("serial")), _v(bios.get("version")), _v(bios.get("manufacturer")), _v(bios.get("release_date")), mode)))
    R.append(("UUID", _v(g("uuid")) + "  (SMBIOS System UUID)"))
    R.append(("Hostname", _v(g("hostname") or osi.get("hostname"))))
    R.append(("OS", "%s\nVersi %s, build %s" % (_v(osd.get("caption") or osi.get("edition")), _v(osd.get("version")), _v(osd.get("build")))
              + ("\nPengguna terdaftar: %s" % osd["registered_user"] if osd.get("registered_user") else "")))
    cpus = aslist(g("cpu"))
    carch = ", ".join(sorted({_ARCH.get(c.get("arch"), str(c.get("arch"))) for c in cpus if c.get("arch") is not None})) or NA
    R.append(("Architecture", "OS %d-bit (%s) - %s\nArsitektur CPU: %s" % (osi["bits"], osi["arch"], _v(osd.get("arch")), carch)))
    R.append(("Installation date", _v(osd.get("install_date")) + "\n(sumber: WMI Win32_OperatingSystem.InstallDate; "
              "perlu diverifikasi silang dengan artefak lain sebelum dijadikan bukti)"))
    R.append(("Time zone", "%s (%s)\nOffset dasar UTC: %s | DST didukung: %s | DST aktif: %s" % (
        _v(tz.get("id")), _v(tz.get("name")), _v(tz.get("offset")), _v(tz.get("dst_supported")), _v(tz.get("dst_active")))))
    clk = "Jam perangkat (lokal): %s\nJam perangkat (UTC): %s" % (_v(g("clock_local")), _v(g("clock_utc")))
    ntp = g("ntp")
    if ntp:
        clk += "\nPembanding NTP (%s): %s UTC\nSelisih perangkat terhadap NTP: %+.3f detik (RTT %.3f dtk)" % (
            ntp["server"], ntp["ntp_utc"], ntp["offset_sec"], ntp["rtt_sec"])
    elif g("ntp_requested"):
        clk += "\nPembanding NTP: tidak dapat dijangkau (tanpa internet)."
    else:
        clk += "\nPembanding NTP: tidak dijalankan."
    if manual_ref:
        clk += "\nWaktu referensi aktual (diisi petugas): %s" % manual_ref
    elif not ntp:
        clk += "\nWaktu referensi aktual: BELUM diisi petugas - selisih jam tidak dapat dihitung."
    R.append(("System clock", clk))
    R.append(("CPU", "\n".join("%s (%s inti / %s thread)" % (_v(c.get("name")), _v(c.get("cores")), _v(c.get("threads"))) for c in cpus) or NA))
    mods = aslist(g("ram_modules"))
    ram = "Total: %s" % _gb(g("ram_total"))
    for m in mods:
        ram += "\n- %s, %s, %s MHz, PN %s" % (_gb(m.get("capacity")), _v(m.get("manufacturer")), _v(m.get("speed")), _v(m.get("part")))
    R.append(("RAM", ram))
    nics = aslist(g("nics")); bt = aslist(g("bluetooth"))
    na = "\n".join("- %s [%s]%s" % (_v(n.get("name")), _v(n.get("connection")),
                                    "" if n.get("enabled") in (None, True) else " (nonaktif/terputus)") for n in nics) or NA
    if bt:
        na += "\nBluetooth: " + "; ".join(str(x) for x in bt)
    R.append(("Network adapter", na))
    R.append(("MAC address", "\n".join("%s  -  %s" % (_v(n.get("mac")), _v(n.get("name"))) for n in nics if n.get("mac")) or NA))
    ips = []
    for c in aslist(g("ipcfg")):
        ips.append("%s\nIP: %s | Subnet: %s | Gateway: %s | DNS: %s | DHCP: %s" % (
            _v(c.get("desc")), ", ".join(map(str, aslist(c.get("ip")))) or NA, ", ".join(map(str, aslist(c.get("subnet")))) or NA,
            ", ".join(map(str, aslist(c.get("gateway")))) or NA, ", ".join(map(str, aslist(c.get("dns")))) or NA, _v(c.get("dhcp"))))
    R.append(("IP configuration", "\n".join(ips) or "Tidak ada antarmuka dengan IP aktif (saat pengambilan)."))
    dom = ("Domain: %s" % _v(g("domain"))) if g("part_of_domain") else ("Workgroup: %s (tidak tergabung domain)" % _v(g("domain")))
    R.append(("Domain/Workgroup", dom))
    bl = aslist(g("bitlocker"))
    if bl:
        enc = "BitLocker:\n" + "\n".join("- %s  %s; %s" % (_v(b.get("drive")), _PROT.get(b.get("protection"), NA),
                                                         _CONV.get(b.get("conversion"), NA)) for b in bl)
    else:
        enc = "BitLocker: " + ("tidak ada volume terenkripsi terbaca" if is_admin else
                               "TIDAK dapat dibaca - jalankan sebagai Administrator") + "\n(FileVault/LUKS: tidak berlaku pada Windows)"
    R.append(("Encryption", enc))
    tpm = g("tpm")
    if tpm:
        t = "TPM: spesifikasi %s | enabled=%s | activated=%s | produsen %s" % (_v(tpm.get("spec")), _v(tpm.get("enabled")),
                                                                           _v(tpm.get("activated")), _v(tpm.get("manufacturer")))
    else:
        t = "TPM: tidak terdeteksi / butuh Administrator"
    sb = g("secure_boot")
    sbt = {True: "AKTIF", False: "NONAKTIF", None: NA}[sb] if isinstance(sb, bool) or sb is None else str(sb)
    R.append(("Secure Boot/TPM", "Secure Boot: %s\n%s" % (sbt, t)))
    return R


def storage_rows(hw):
    return [(_v(d.get("model")), "Serial: %s | Kapasitas: %s | Antarmuka: %s" % (_v(d.get("serial")), _gb(d.get("size")), _v(d.get("iface"))))
            for d in aslist(hw.get("disks"))]
