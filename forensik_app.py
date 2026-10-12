# -*- coding: utf-8 -*-
"""Forensik Runner - GUI (Tkinter) dan CLI.   Pembuat: APH4NC-Dit.P2-DJP-KEMENKEU.  Contoh CLI:
   python forensik_app.py --cli --case case_contoh.json [--tools DIR] [--out DIR] [--only usbdeview,usbdrivelog] [--monitor 30]
   python forensik_app.py --info
"""
import argparse, ctypes, json, os, queue, subprocess, sys, threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import forensik_core as core
import forensik_update as upd


def default_out():
    return os.path.join(os.path.dirname(HERE), "Hasil_Forensik")


def relaunch_as_admin():
    params = " ".join('"%s"' % a for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, HERE, 1)


def cmd_info(tools_dir):
    osi = core.detect_os()
    print("Sistem operasi : %s" % core.os_label(osi))
    print("OS               : %d-bit  (terdeteksi via %s)" % (osi["bits"], osi["via"]))
    print("Python           : %d-bit | Administrator: %s" % (osi["python_bits"], core.is_admin()))
    print("Folder alat      : %s" % tools_dir)
    for t in core.TOOLS:
        b = core.resolve_binary(tools_dir, t, osi["bits"])
        print("  %-24s %-3s-bit  %s" % (t["title"], b["bits"] or "?", b["path"] or "TIDAK DITEMUKAN"))
        if b["note"]:
            print("      %s" % b["note"])


def kape_check(tools_dir):
    root = core.kmod.find_kape(tools_dir)
    if not root:
        print("KAPE tidak ditemukan di %s" % tools_dir); return 2
    info = core.kmod.inspect_kape(root)
    print(core.kmod.readiness_text(info))
    for prof in ("live", "triage", "sans", "kapetriage"):
        pl = core.kmod.plan_run(info, prof)
        print("\n[profil %s] target=%s | modul siap=%d | dilewati=%d" % (prof, pl["targets"], len(pl["modules"]), len(pl["skipped"])))
        for n, why in pl["skipped"]:
            print("   dilewati: %s - %s" % (n, why))
    return 0


def run_cli(a, tools_dir):
    case = json.load(open(a.case, encoding="utf-8"))
    only = set(a.only.split(",")) if a.only else None
    out = a.out or default_out()
    kcfg = None
    if a.kape:
        if a.kape_yes or a.kape_dry:
            kcfg = dict(run=True, profile=a.kape, source=a.kape_source, vss=a.kape_vss, dry=a.kape_dry, timeout=a.kape_timeout,
                        targets=[x for x in (a.kape_targets or "").split(",") if x], modules=[x for x in (a.kape_modules or "").split(",") if x])
        else:
            print("KAPE diminta tetapi belum dikonfirmasi: tambahkan --kape-yes (menyalin artefak ke folder hasil) atau --kape-dry. KAPE dilewati.")
    try:
        root, res = core.run_all(case, tools_dir, out, only, a.monitor, use_ntp=not a.no_ntp, kape_cfg=kcfg)
    except ValueError as e:
        print("Data pemeriksaan belum lengkap:\n" + str(e)); return 2
    print("\nFolder hasil:", root)
    return 0


def run_gui(tools_dir):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    osi = core.detect_os()
    root = tk.Tk()
    root.title("%s v%s - Pemeriksaan Pajak | %s" % (core.APP_NAME, core.APP_VERSION, core.APP_AUTHOR))
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry("%dx%d+%d+%d" % (min(1080, sw - 40), min(960, sh - 90), max(0, (sw - min(1080, sw - 40)) // 2), 10))
    root.minsize(760, 420)
    st = ttk.Style()
    try:
        st.theme_use("vista" if sys.platform == "win32" else "clam")
    except Exception:
        pass
    v = {k: tk.StringVar() for k in ("nama_wp", "npwp", "sp2_no", "sp2_tgl", "st_no", "st_tgl", "tahun_pajak",
                                     "keterangan", "tools", "out", "user_nama", "user_jabatan", "user_lokasi", "waktu_referensi",
                                     "id_perkara", "no_berita_acara", "perwakilan_wp")}
    cfg = core.load_config(HERE)
    v["tools"].set(tools_dir)
    v["out"].set(cfg.get("out") or default_out())
    v_lisan, v_tulis = tk.BooleanVar(value=False), tk.BooleanVar(value=False)
    v["dok_persetujuan"] = tk.StringVar()
    monitor = tk.IntVar(value=30)
    ntp_on = tk.BooleanVar(value=True)

    # banner OS
    ban = tk.Frame(root, bg="#1F3A5F"); ban.pack(fill="x")
    try:
        lg_path = core.asset("logo_gui.png")
        if lg_path:
            root._logo = tk.PhotoImage(file=lg_path)
            tk.Label(ban, image=root._logo, bg="#1F3A5F").pack(side="left", padx=10, pady=4)
            root.iconphoto(True, tk.PhotoImage(file=core.asset("app_logo_gui.png")))
    except Exception:
        pass
    try:
        ap_path = core.asset("app_logo_gui.png")
        if ap_path:
            root._logo2 = tk.PhotoImage(file=ap_path)
            tk.Label(ban, image=root._logo2, bg="#1F3A5F").pack(side="right", padx=10, pady=4)
    except Exception:
        pass
    upd_hook = {"fn": None}
    upd_icon = UpdateIcon(ban, lambda: upd_hook["fn"] and upd_hook["fn"](), "#1F3A5F")
    upd_icon.pack(side="right", padx=(0, 4), pady=2)
    tk.Label(ban, text="Sistem operasi: %s" % core.os_label(osi), bg="#1F3A5F", fg="white",
             font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=10, pady=(6, 0))
    tk.Label(ban, text="Terdeteksi %d-bit  ->  %s" % (
        osi["bits"], "memakai alat 64-bit bila tersedia (cadangan: 32-bit)" if osi["bits"] == 64 else "memakai alat 32-bit"),
        bg="#1F3A5F", fg="#CFE3FF", font=("Segoe UI", 10)).pack(anchor="w", padx=10)
    tk.Label(ban, text="Dibuat oleh: %s" % core.APP_AUTHOR, bg="#1F3A5F", fg="#FFD84D",
             font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=(0, 6))
    if not core.is_admin():
        w = tk.Frame(root, bg="#FFF3CD"); w.pack(fill="x")
        tk.Label(w, text="Belum berjalan sebagai Administrator - sebagian data forensik dapat kosong.",
                 bg="#FFF3CD").pack(side="left", padx=10, pady=4)
        if sys.platform == "win32":
            ttk.Button(w, text="Jalankan ulang sebagai Administrator",
                       command=lambda: (relaunch_as_admin(), root.destroy())).pack(side="right", padx=10)

    tk.Label(root, text="%s v%s  |  Dibuat oleh: %s" % (core.APP_NAME, core.APP_VERSION, core.APP_AUTHOR),
             fg="#555555", font=("Segoe UI", 8)).pack(side="bottom", anchor="e", padx=10, pady=(0, 3))
    # bilah tombol tetap di bawah (selalu terlihat); isi formulir dapat digulir
    bf = ttk.Frame(root, padding=(10, 6)); bf.pack(side="bottom", fill="x")
    bfa = ttk.Frame(bf); bfa.pack(side="top", fill="x")          # baris tombol sekunder
    bfb = ttk.Frame(bf); bfb.pack(side="top", fill="x", pady=(4, 0))  # baris tombol utama
    ttk.Separator(root, orient="horizontal").pack(side="bottom", fill="x")
    cv = tk.Canvas(root, highlightthickness=0)
    vsb = ttk.Scrollbar(root, orient="vertical", command=cv.yview)
    cv.configure(yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y"); cv.pack(side="left", fill="both", expand=True)
    nb = ttk.Frame(cv, padding=10)
    cwin = cv.create_window((0, 0), window=nb, anchor="nw")
    nb.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
    cv.bind("<Configure>", lambda e: cv.itemconfigure(cwin, width=e.width))
    def _wheel(e):
        if e.widget.winfo_class() in ("Text", "Treeview", "Listbox"):
            return
        cv.yview_scroll(int(-1 * (e.delta / 120)), "units")
    root.bind_all("<MouseWheel>", _wheel)
    form = ttk.LabelFrame(nb, text="Identitas pemeriksaan (wajib)", padding=8); form.pack(fill="x")
    def row(r, label, key, width=46):
        ttk.Label(form, text=label).grid(row=r, column=0, sticky="w", pady=2)
        ttk.Entry(form, textvariable=v[key], width=width).grid(row=r, column=1, sticky="w", padx=6)
    row(0, "Nama Wajib Pajak", "nama_wp", 60)
    row(1, "NPWP (15/16 digit)", "npwp")
    row(2, "No. Surat Perintah Pemeriksaan", "sp2_no")
    row(3, "Tanggal SP2 (dd-mm-yyyy)", "sp2_tgl", 16)
    row(4, "No. Surat Tugas", "st_no")
    row(5, "Tanggal Surat Tugas (dd-mm-yyyy)", "st_tgl", 16)
    ttk.Label(form, text="Nama pemeriksa pajak\n(satu nama per baris)").grid(row=0, column=2, sticky="nw", padx=(20, 0))
    t_pem = tk.Text(form, width=36, height=4); t_pem.grid(row=0, column=3, rowspan=3, sticky="w")
    ttk.Label(form, text="Nama tenaga ahli\n(satu nama per baris)").grid(row=3, column=2, sticky="nw", padx=(20, 0))
    t_ahli = tk.Text(form, width=36, height=4); t_ahli.grid(row=3, column=3, rowspan=3, sticky="w")
    ttk.Label(form, text="Tahun/Masa pajak (opsional)").grid(row=6, column=0, sticky="w")
    ttk.Entry(form, textvariable=v["tahun_pajak"], width=20).grid(row=6, column=1, sticky="w", padx=6)
    ttk.Label(form, text="Keterangan perangkat (opsional)").grid(row=6, column=2, sticky="w", padx=(20, 0))
    ttk.Entry(form, textvariable=v["keterangan"], width=38).grid(row=6, column=3, sticky="w")

    uf = ttk.LabelFrame(nb, text="Pengguna & perangkat yang diperiksa (diisi petugas, wajib)", padding=8); uf.pack(fill="x", pady=(6, 0))
    for i, (lbl, k, wd) in enumerate((("Nama pengguna perangkat", "user_nama", 30), ("Jabatan", "user_jabatan", 26),
                                      ("Lokasi perangkat", "user_lokasi", 34))):
        ttk.Label(uf, text=lbl).grid(row=0, column=2 * i, sticky="w", padx=(0 if i == 0 else 12, 4))
        ttk.Entry(uf, textvariable=v[k], width=wd).grid(row=0, column=2 * i + 1, sticky="w")
    ttk.Label(uf, text="Waktu referensi aktual (opsional, dd-mm-yyyy HH:MM:SS)").grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))
    ttk.Entry(uf, textvariable=v["waktu_referensi"], width=24).grid(row=1, column=2, sticky="w", pady=(4, 0))
    ttk.Checkbutton(uf, text="Bandingkan jam dengan NTP (butuh internet)", variable=ntp_on).grid(row=1, column=3, columnspan=3, sticky="w", pady=(4, 0), padx=12)

    pz = ttk.LabelFrame(nb, text="Persetujuan akses perangkat (wajib)", padding=8); pz.pack(fill="x", pady=(6, 0))
    ttk.Checkbutton(pz, variable=v_lisan, text="Akses ke perangkat telah memperoleh persetujuan LISAN dari pengguna perangkat dan pihak Wajib Pajak."
                    ).grid(row=0, column=0, columnspan=3, sticky="w")
    ttk.Checkbutton(pz, variable=v_tulis, text="Akses ke perangkat telah memperoleh persetujuan TERTULIS dari pengguna perangkat dan pihak Wajib Pajak."
                    ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(2, 0))
    ttk.Label(pz, text="No./tanggal dokumen persetujuan tertulis (opsional)").grid(row=2, column=0, sticky="w", pady=(4, 0))
    ttk.Entry(pz, textvariable=v["dok_persetujuan"], width=70).grid(row=2, column=1, sticky="w", padx=6, pady=(4, 0))

    kf2 = ttk.LabelFrame(nb, text="Dokumentasi & kata kunci kasus (opsional)", padding=8); kf2.pack(fill="x", pady=(6, 0))
    for i, (lbl, k, wd) in enumerate((("ID perkara", "id_perkara", 22), ("No. berita acara", "no_berita_acara", 26),
                                      ("Perwakilan WP / saksi", "perwakilan_wp", 30))):
        ttk.Label(kf2, text=lbl).grid(row=0, column=2 * i, sticky="w", padx=(0 if i == 0 else 12, 4))
        ttk.Entry(kf2, textvariable=v[k], width=wd).grid(row=0, column=2 * i + 1, sticky="w")
    ttk.Label(kf2, text="Kata kunci kasus (domain, nama berkas, nama host; satu per baris atau pisah koma), mis. niagakas, Penjualan2024, FENNY-WIREMESH"
              ).grid(row=1, column=0, columnspan=6, sticky="w", pady=(6, 0))
    t_kk = tk.Text(kf2, width=110, height=2); t_kk.grid(row=2, column=0, columnspan=6, sticky="w")

    pf = ttk.LabelFrame(nb, text="Lokasi", padding=8); pf.pack(fill="x", pady=6)
    def pick(key):
        d = filedialog.askdirectory(initialdir=v[key].get() or HERE)
        if d:
            v[key].set(d)
            if key == "tools":
                refresh_bins(); refresh_kape()
    for i, (lbl, k) in enumerate((("Folder alat forensik", "tools"), ("Folder hasil (disarankan media eksternal)", "out"))):
        ttk.Label(pf, text=lbl).grid(row=i, column=0, sticky="w")
        ttk.Entry(pf, textvariable=v[k], width=80).grid(row=i, column=1, padx=6, pady=2)
        ttk.Button(pf, text="Pilih...", command=lambda k=k: pick(k)).grid(row=i, column=2)

    tf = ttk.LabelFrame(nb, text="Alat yang dijalankan", padding=8); tf.pack(fill="both", expand=True)
    tree = ttk.Treeview(tf, columns=("sel", "bin", "status"), height=10)
    tree.heading("#0", text="Alat"); tree.heading("sel", text="Dipilih"); tree.heading("bin", text="Biner (bit)")
    tree.heading("status", text="Status")
    tree.column("#0", width=220); tree.column("sel", width=70, anchor="center")
    tree.column("bin", width=360); tree.column("status", width=260)
    tree.pack(fill="both", expand=True, side="left")
    sel = {t["key"]: True for t in core.TOOLS}
    def refresh_bins():
        for t in core.TOOLS:
            b = core.resolve_binary(v["tools"].get(), t, osi["bits"])
            txt = ("%s-bit%s" % (b["bits"], " (cadangan 32-bit)" if osi["bits"] == 64 and b["bits"] == 32 else "")) \
                if b["path"] else "TIDAK DITEMUKAN"
            tree.set(t["key"], "bin", txt)
    for t in core.TOOLS:
        tree.insert("", "end", iid=t["key"], text=t["title"], values=("Ya", "", "menunggu"))
    refresh_bins()
    def toggle(ev):
        k = tree.identify_row(ev.y)
        if k in sel:
            sel[k] = not sel[k]; tree.set(k, "sel", "Ya" if sel[k] else "Tidak")
    tree.bind("<Double-1>", toggle)
    side = ttk.Frame(tf); side.pack(side="right", fill="y", padx=8)
    ttk.Label(side, text="Klik 2x baris untuk\nmemilih/batal.\n\nPemantauan USBLogView\n(detik):").pack(anchor="w")
    ttk.Spinbox(side, from_=5, to=600, textvariable=monitor, width=6).pack(anchor="w")

    # ---- KAPE
    kf = ttk.LabelFrame(nb, text="KAPE (opsional - koleksi & parsing artefak; butuh Administrator)", padding=8); kf.pack(fill="x", pady=(0, 6))
    kinfo = {"info": None}
    k_run, k_vss = tk.BooleanVar(value=False), tk.BooleanVar(value=False)
    k_src = tk.StringVar(value=os.environ.get("SystemDrive", "C:")); k_tar, k_mod = tk.StringVar(), tk.StringVar()
    k_lbl = {core.kmod.PROFILES[k]["label"]: k for k in core.kmod.PROFILES}
    k_prof = tk.StringVar(value=core.kmod.PROFILES["live"]["label"])
    k_status = ttk.Label(kf, text="", foreground="#1F3A5F"); k_status.grid(row=0, column=0, columnspan=6, sticky="w")
    ttk.Checkbutton(kf, text="Jalankan KAPE", variable=k_run).grid(row=1, column=0, sticky="w")
    ttk.Combobox(kf, textvariable=k_prof, values=list(k_lbl), width=62, state="readonly").grid(row=1, column=1, columnspan=3, sticky="w", padx=6)
    ttk.Label(kf, text="Sumber").grid(row=1, column=4, sticky="e"); ttk.Entry(kf, textvariable=k_src, width=6).grid(row=1, column=5, sticky="w", padx=4)
    ttk.Checkbutton(kf, text="Sertakan VSS (shadow copy)", variable=k_vss).grid(row=2, column=0, columnspan=2, sticky="w")
    ttk.Label(kf, text="Kustom - target (koma)").grid(row=2, column=2, sticky="e"); ttk.Entry(kf, textvariable=k_tar, width=24).grid(row=2, column=3, sticky="w", padx=4)
    ttk.Label(kf, text="modul (koma)").grid(row=2, column=4, sticky="e"); ttk.Entry(kf, textvariable=k_mod, width=24).grid(row=2, column=5, sticky="w", padx=4)
    def refresh_kape():
        root_ = core.kmod.find_kape(v["tools"].get())
        if not root_:
            kinfo["info"] = None; k_status.config(text="KAPE tidak ditemukan di folder alat."); tree.set("kape", "bin", "TIDAK DITEMUKAN"); return
        try:
            kinfo["info"] = core.kmod.inspect_kape(root_)
            k_status.config(text=core.kmod.summarize(kinfo["info"]))
            tree.set("kape", "bin", "%s-bit (header PE) - satu-satunya biner" % (kinfo["info"]["exe_bits"] or "?"))
        except Exception as e:
            k_status.config(text="Gagal memeriksa KAPE: %s" % e)
    def show_kape():
        if not kinfo["info"]:
            messagebox.showinfo("KAPE", "KAPE tidak ditemukan."); return
        w_ = tk.Toplevel(root); w_.title("Kelengkapan KAPE"); w_.geometry("900x600")
        t_ = tk.Text(w_, font=("Consolas", 9), wrap="none"); t_.pack(fill="both", expand=True)
        txt = core.kmod.readiness_text(kinfo["info"])
        for pf in ("live", "triage", "sans", "kapetriage"):
            pl = core.kmod.plan_run(kinfo["info"], pf)
            txt += "\n\n[profil %s] target=%s | modul siap=%d | dilewati=%d" % (pf, pl["targets"], len(pl["modules"]), len(pl["skipped"]))
            txt += "".join("\n   dilewati: %s - %s" % x for x in pl["skipped"])
        t_.insert("1.0", txt); t_.config(state="disabled")
    ttk.Button(kf, text="Lihat kelengkapan KAPE", command=show_kape).grid(row=0, column=5, sticky="e")
    tree.insert("", "end", iid="kape", text="KAPE (opsional)", values=("-", "", "tidak diminta"))
    refresh_kape()

    logbox = tk.Text(nb, height=7, state="disabled", font=("Consolas", 8)); logbox.pack(fill="x", pady=6)
    q = queue.Queue()
    def pump():
        try:
            while True:
                kind, a = q.get_nowait()
                if kind == "log":
                    logbox.config(state="normal"); logbox.insert("end", a + "\n"); logbox.see("end")
                    logbox.config(state="disabled")
                elif kind == "st":
                    tree.set(a[0], "status", a[1])
                elif kind == "done":
                    btn_run.config(state="normal")
                    if a[0]:
                        state["root"] = a[0]
                        messagebox.showinfo("Selesai", "Laporan PDF tersimpan di:\n%s" % os.path.join(a[0], "Laporan_PDF"))
                    else:
                        messagebox.showerror("Gagal", a[1])
        except queue.Empty:
            pass
        root.after(150, pump)
    state = {"root": None}

    def collect():
        return dict(nama_wp=v["nama_wp"].get(), npwp=v["npwp"].get(), sp2_no=v["sp2_no"].get(), sp2_tgl=v["sp2_tgl"].get(),
                    st_no=v["st_no"].get(), st_tgl=v["st_tgl"].get(), pemeriksa=t_pem.get("1.0", "end"),
                    tenaga_ahli=t_ahli.get("1.0", "end"), tahun_pajak=v["tahun_pajak"].get(),
                    keterangan=v["keterangan"].get(), user_nama=v["user_nama"].get(),
                    user_jabatan=v["user_jabatan"].get(), user_lokasi=v["user_lokasi"].get(), waktu_referensi=v["waktu_referensi"].get(),
                    id_perkara=v["id_perkara"].get(), no_berita_acara=v["no_berita_acara"].get(), perwakilan_wp=v["perwakilan_wp"].get(),
                    kata_kunci_kasus=t_kk.get("1.0", "end"), persetujuan_lisan=v_lisan.get(),
                    persetujuan_tertulis=v_tulis.get(), dok_persetujuan=v["dok_persetujuan"].get())
    def apply(c):
        for k in v:
            if k in c: v[k].set(c[k])
        v_lisan.set(bool(c.get("persetujuan_lisan", False))); v_tulis.set(bool(c.get("persetujuan_tertulis", False)))
        t_pem.delete("1.0", "end"); t_pem.insert("1.0", "\n".join(c.get("pemeriksa", [])) if isinstance(c.get("pemeriksa"), list) else c.get("pemeriksa", ""))
        t_ahli.delete("1.0", "end"); t_ahli.insert("1.0", "\n".join(c.get("tenaga_ahli", [])) if isinstance(c.get("tenaga_ahli"), list) else c.get("tenaga_ahli", ""))
        t_kk.delete("1.0", "end"); t_kk.insert("1.0", "\n".join(c.get("kata_kunci_kasus", [])) if isinstance(c.get("kata_kunci_kasus"), list) else c.get("kata_kunci_kasus", ""))
    def save_prof():
        p = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("Profil kasus", "*.json")])
        if p:
            c = collect(); c["pemeriksa"] = c["pemeriksa"].splitlines(); c["tenaga_ahli"] = c["tenaga_ahli"].splitlines()
            c["kata_kunci_kasus"] = [x.strip() for x in c["kata_kunci_kasus"].splitlines() if x.strip()]
            json.dump(c, open(p, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    def load_prof():
        p = filedialog.askopenfilename(filetypes=[("Profil kasus", "*.json")])
        if p: apply(json.load(open(p, encoding="utf-8")))

    def go():
        err, _ = core.validate_case(collect())
        if err:
            messagebox.showerror("Data belum lengkap", "\n".join(err)); return
        keys = {k for k, on in sel.items() if on}
        if not keys:
            messagebox.showerror("Tidak ada alat", "Pilih minimal satu alat."); return
        core.save_config(HERE, dict(core.load_config(HERE), tools=v["tools"].get(), out=v["out"].get()))
        kcfg = None
        if k_run.get():
            if not kinfo["info"]:
                messagebox.showerror("KAPE", "KAPE tidak ditemukan di folder alat."); return
            pk = k_lbl[k_prof.get()]
            pl = core.kmod.plan_run(kinfo["info"], pk, [x.strip() for x in k_tar.get().split(",") if x.strip()],
                                    [x.strip() for x in k_mod.get().split(",") if x.strip()])
            try:
                import shutil as _sh
                os.makedirs(v["out"].get(), exist_ok=True); free = "%.1f GB" % (_sh.disk_usage(v["out"].get()).free / 1024 ** 3)
            except Exception:
                free = "?"
            msg = ("KAPE akan dijalankan:\n\nProfil: %s\nSumber: %s%s\nTarget: %s\nModul siap: %d (dilewati: %d)\n\n"
                   "KAPE MENYALIN artefak sistem (registri, log, riwayat peramban, dll.) ke folder hasil dan dapat memakan "
                   "waktu lama serta ruang disk besar.\nRuang kosong folder hasil: %s\n%s\nLanjutkan?") % (
                pl["label"], k_src.get(), " + VSS" if k_vss.get() else "", ", ".join(pl["targets"]) or "-", len(pl["modules"]),
                len(pl["skipped"]), free, "" if core.is_admin() else "PERINGATAN: bukan Administrator - KAPE akan dilewati.\n")
            if not messagebox.askyesno("Konfirmasi eksekusi KAPE", msg):
                return
            kcfg = dict(run=True, profile=pk, source=k_src.get(), vss=k_vss.get(), timeout=14400,
                        targets=[x.strip() for x in k_tar.get().split(",") if x.strip()],
                        modules=[x.strip() for x in k_mod.get().split(",") if x.strip()])
        btn_run.config(state="disabled")
        for k in keys: tree.set(k, "status", "menunggu")
        def work():
            try:
                r, _ = core.run_all(collect(), v["tools"].get(), v["out"].get(), keys, monitor.get(),
                                    log=lambda m: q.put(("log", m)), use_ntp=ntp_on.get(), kape_cfg=kcfg,
                                    progress=lambda i, n, k, s: q.put(("st", (k, s))))
                q.put(("done", (r, "")))
            except Exception as e:
                q.put(("done", (None, str(e))))
        threading.Thread(target=work, daemon=True).start()


    # ---- pembaruan aplikasi (PRD F30)
    def open_update(autocheck=False):
        cfgu = core.load_config(HERE)
        w = tk.Toplevel(root); w.title("Pembaruan aplikasi"); w.transient(root); w.resizable(False, False)
        f = ttk.Frame(w, padding=12); f.pack(fill="both", expand=True)
        ttk.Label(f, text="Versi terpasang: %s" % core.APP_VERSION, font=("Segoe UI", 10, "bold")).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(f, text="Repositori GitHub (pemilik/nama)").grid(row=1, column=0, sticky="w", pady=(8, 0))
        vr = tk.StringVar(value=cfgu.get("update_repo", upd.DEFAULT_REPO)); ttk.Entry(f, textvariable=vr, width=44).grid(row=1, column=1, pady=(8, 0), padx=6)
        ttk.Label(f, text="Token akses (opsional, repositori privat)").grid(row=2, column=0, sticky="w", pady=(4, 0))
        vt = tk.StringVar(value=cfgu.get("update_token", "")); ttk.Entry(f, textvariable=vt, width=44, show="*").grid(row=2, column=1, pady=(4, 0), padx=6)
        va = tk.BooleanVar(value=bool(cfgu.get("update_cek_otomatis", False)))
        ttk.Checkbutton(f, text="Periksa pembaruan otomatis saat aplikasi dibuka (butuh internet; default mati)", variable=va
                        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 0))
        msg = tk.Text(f, width=78, height=9, state="disabled", wrap="word"); msg.grid(row=4, column=0, columnspan=2, pady=8)
        def say(t):
            msg.config(state="normal"); msg.delete("1.0", "end"); msg.insert("end", t); msg.config(state="disabled")
        say("Aplikasi hanya MENGUNDUH paket dari GitHub (tidak mengirim data kasus). Pembaruan wajib memiliki checksum SHA-256, "
            "berkas lama dicadangkan ke folder _backup_versi, dan data kasus/config/folder alat tidak disentuh.")
        def save_cfg():
            c = core.load_config(HERE)
            c.update(update_repo=vr.get().strip(), update_token=vt.get().strip(), update_cek_otomatis=va.get())
            core.save_config(HERE, c)
        def do_check():
            save_cfg(); say("Memeriksa versi terbaru di GitHub...")
            def work():
                try:
                    info = upd.check(vr.get().strip(), core.APP_VERSION, vt.get().strip())
                    root.after(0, lambda: show_info(info))
                except Exception as e:
                    root.after(0, lambda: say("Gagal: %s" % e))
            threading.Thread(target=work, daemon=True).start()
        def show_info(info):
            if not info["newer"]:
                say("Aplikasi sudah versi terbaru (terpasang %s, rilis GitHub %s)." % (core.APP_VERSION, info["version"])); return
            say("Versi baru tersedia: %s (terpasang %s)\n\nCatatan rilis:\n%s\n\nChecksum SHA-256: %s" % (
                info["version"], core.APP_VERSION, info["notes"] or "-", info["sha256"] or "TIDAK ADA - update akan ditolak"))
            if not info["zip_url"] or not info["sha256"]:
                messagebox.showwarning("Rilis tidak lengkap", "Rilis harus memuat berkas .zip dan checksum SHA-256.", parent=w); return
            if messagebox.askyesno("Pasang pembaruan", "Pasang versi %s sekarang?\n\nBerkas aplikasi lama dicadangkan lebih dulu. "
                                   "Pastikan tidak ada proses pemeriksaan yang sedang berjalan." % info["version"], parent=w):
                say("Mengunduh dan memasang..."); 
                def work2():
                    try:
                        bdir, upd_files, jsons = upd.download_and_apply(info, HERE, core.APP_VERSION, vt.get().strip())
                        root.after(0, lambda: done_ok(info, bdir, upd_files, jsons))
                    except Exception as e:
                        root.after(0, lambda: say("Pembaruan GAGAL, aplikasi lama tidak diubah:\n%s" % e))
                threading.Thread(target=work2, daemon=True).start()
        def done_ok(info, bdir, files, jsons):
            say("Berhasil memasang versi %s (%d berkas). Cadangan: %s%s" % (info["version"], len(files), bdir,
                ("\nBerkas pengaturan baru disimpan sebagai .baru: " + ", ".join(jsons)) if jsons else ""))
            if messagebox.askyesno("Mulai ulang", "Pembaruan terpasang. Mulai ulang aplikasi sekarang?", parent=w):
                restart()
        def restart():
            try:
                bat = os.path.join(HERE, "JALANKAN.bat")
                if sys.platform == "win32" and os.path.exists(bat):
                    subprocess.Popen(["cmd", "/c", "start", "", bat], cwd=HERE)
                else:
                    subprocess.Popen([sys.executable, os.path.join(HERE, "forensik_app.py")], cwd=HERE)
            finally:
                root.destroy()
        def do_rollback():
            b = upd.list_backups(HERE)
            if not b:
                say("Belum ada cadangan versi sebelumnya."); return
            if messagebox.askyesno("Kembalikan versi", "Pulihkan berkas aplikasi dari cadangan terbaru (%s)?\nVersi saat ini akan ditimpa." % b[-1], parent=w):
                try:
                    last, n = upd.rollback(HERE); say("Dipulihkan dari %s (%d berkas). Mulai ulang aplikasi untuk memakai versi tersebut." % (last, n))
                except Exception as e:
                    say("Gagal memulihkan: %s" % e)
        bb = ttk.Frame(f); bb.grid(row=5, column=0, columnspan=2, sticky="e")
        ttk.Button(bb, text="Periksa & pasang pembaruan", command=do_check).pack(side="left")
        ttk.Button(bb, text="Kembalikan versi sebelumnya", command=do_rollback).pack(side="left", padx=6)
        ttk.Button(bb, text="Simpan & tutup", command=lambda: (save_cfg(), w.destroy())).pack(side="left")
        w.grab_set()
        if autocheck and vr.get().strip():
            w.after(200, do_check)

    ttk.Button(bfa, text="Muat profil kasus", command=load_prof).pack(side="left")
    ttk.Button(bfa, text="Simpan profil kasus", command=save_prof).pack(side="left", padx=6)
    ttk.Button(bfa, text="Buka folder hasil", command=lambda: state["root"] and os.startfile(state["root"])
               if sys.platform == "win32" else None).pack(side="left")
    def rebuild():
        init = v["out"].get() if os.path.isdir(v["out"].get()) else HERE
        d = filedialog.askdirectory(title="Pilih folder hasil pelaksanaan (berisi Data_Mentah)", initialdir=state.get("root") or init)
        if not d:
            return
        if not os.path.exists(os.path.join(d, "Data_Mentah", "_state.json")):
            messagebox.showerror("Folder tidak sesuai", "Folder ini tidak memuat Data_Mentah\\_state.json. Pilih folder hasil "
                                 "pelaksanaan (mis. 012345678012000_20261007_103949) yang dibuat oleh versi aplikasi ini.")
            return
        if not messagebox.askyesno("Buat laporan integrasi", "Laporan Final dan Laporan Integrasi baru akan dibuat dari data pada:\n%s\n\n"
                                   "Alat TIDAK dijalankan ulang; laporan lama tidak ditimpa (nama berstempel waktu baru). Lanjutkan?" % d):
            return
        try:
            pdf, stamp = core.rebuild_reports(d, log=lambda m: q.put(("log", m)))
            messagebox.showinfo("Selesai", "Laporan baru dibuat di:\n%s" % pdf)
            if sys.platform == "win32":
                os.startfile(pdf)
        except Exception as e:
            messagebox.showerror("Gagal", "%s: %s" % (type(e).__name__, e))
    ttk.Button(bfa, text="Buat laporan integrasi dari folder hasil...", command=rebuild).pack(side="left", padx=6)
    upd_hook["fn"] = lambda: open_update(True)
    btn_upd = ttk.Button(bfa, text="Pembaruan...", command=open_update); btn_upd.pack(side="left")
    if core.load_config(HERE).get("update_cek_otomatis"):
        def auto_check():
            c = core.load_config(HERE)
            try:
                info = upd.check(c.get("update_repo") or upd.DEFAULT_REPO, core.APP_VERSION, c.get("update_token", ""))
                if info["newer"]:
                    root.after(0, lambda: (btn_upd.config(text="Pembaruan (versi %s tersedia)" % info["version"]), upd_icon.set_available(info["version"])))
            except Exception:
                pass
        threading.Thread(target=auto_check, daemon=True).start()
    btn_run = ModernButton(bfb, text="JALANKAN SEMUA & BUAT LAPORAN PDF", command=go); btn_run.pack(side="right")
    pump(); root.mainloop()


class UpdateIcon(object):
    """Ikon 'Check Update' bundar mencolok untuk banner (oranye-kuning, panah unduh putih, lencana merah bila ada versi baru)."""
    def __init__(self, parent, command, bg, size=80):
        import tkinter as tk
        import tkinter.font as tkfont
        self.cmd, self.bg, self.sz = command, bg, size
        self.hover, self.avail, self.pulse, self.label = False, False, 0, "Check Update"
        self.font = tkfont.Font(family="Segoe UI", size=8, weight="bold")
        self.cv = tk.Canvas(parent, width=96, height=size + 6, highlightthickness=0, bd=0, bg=bg, cursor="hand2")
        self.cv.bind("<Enter>", lambda e: self._set(hover=True)); self.cv.bind("<Leave>", lambda e: self._set(hover=False))
        self.cv.bind("<ButtonRelease-1>", lambda e: self.cmd())
        self.draw()
    def pack(self, **kw): self.cv.pack(**kw)
    def _set(self, **kw):
        for k, v in kw.items(): setattr(self, k, v)
        self.draw()
    def set_available(self, version):
        self.avail = True; self.label = "Update tersedia"; self.draw(); self._tick()
    def _tick(self):
        try:
            self.pulse = (self.pulse + 1) % 8; self.draw(); self.cv.after(250, self._tick)
        except Exception:
            pass
    def draw(self):
        c = self.cv; c.delete("all"); cx, cy, r = 48, 33, 27 + (2 if self.hover else 0)
        c.create_oval(cx - r - 5, cy - r - 5, cx + r + 5, cy + r + 5, fill="#2E4F7C" if not self.hover else "#7A5A18", outline="")   # halo
        c.create_oval(cx - r, cy - r, cx + r, cy + r, fill="#E65100", outline="#FFE082", width=2)
        c.create_oval(cx - r + 3, cy - r + 3, cx + r - 3, cy + r - 6, fill="#FF9800", outline="")
        c.create_oval(cx - r + 8, cy - r + 5, cx + r - 8, cy - 2, fill="#FFB74D", outline="", stipple="gray50")
        # panah unduh putih + baki
        c.create_rectangle(cx - 5, cy - 16, cx + 5, cy + 2, fill="white", outline="")
        c.create_polygon(cx - 14, cy + 1, cx + 14, cy + 1, cx, cy + 16, fill="white", outline="")
        c.create_rectangle(cx - 16, cy + 19, cx + 16, cy + 22, fill="white", outline="")
        if self.avail:
            br = 9 + (1 if self.pulse % 2 else 0)
            c.create_oval(cx + 12 - br, cy - 24 - br + 6, cx + 12 + br, cy - 24 + br + 6, fill="#E53935", outline="white", width=2)
            c.create_text(cx + 12, cy - 18, text="!", fill="white", font=("Segoe UI", 9, "bold"))
        c.create_text(48, self.sz + 0, text=self.label, fill="#FFD84D" if not self.avail else "#FF8A80", font=self.font)


class ModernButton(object):
    """Tombol utama bergaya modern: sudut membulat, gradasi biru, ikon putar, hover/tekan, keadaan nonaktif."""
    def __init__(self, parent, text, command, busy_text="Memproses...", height=46):
        import tkinter as tk
        self._tk, self.text, self.busy_text, self.command, self.h = tk, text, busy_text, command, height
        self.state_, self.hover, self.down = "normal", False, False
        bg = "#F0F0F0"
        try:
            bg = parent.winfo_toplevel().cget("bg")
        except Exception:
            pass
        import tkinter.font as tkfont
        self.font = tkfont.Font(family="Segoe UI", size=11, weight="bold")
        self.w = self.font.measure(text) + 96
        self.cv = tk.Canvas(parent, width=self.w, height=height + 6, highlightthickness=0, bd=0, bg=bg, cursor="hand2")
        self.cv.bind("<Enter>", lambda e: self._set(hover=True)); self.cv.bind("<Leave>", lambda e: self._set(hover=False, down=False))
        self.cv.bind("<ButtonPress-1>", lambda e: self._set(down=True)); self.cv.bind("<ButtonRelease-1>", self._release)
        self.draw()
    def pack(self, **kw): self.cv.pack(**kw)
    def grid(self, **kw): self.cv.grid(**kw)
    def _set(self, **kw):
        for k, val in kw.items(): setattr(self, k, val)
        self.draw()
    def _release(self, e):
        was = self.down; self.down = False; self.draw()
        if was and self.state_ == "normal" and 0 <= e.x <= self.w and 0 <= e.y <= self.h + 6:
            self.command()
    def config(self, state=None, **kw):
        if state:
            self.state_ = state
            self.cv.config(cursor="hand2" if state == "normal" else "arrow")
            self.draw()
    configure = config
    @staticmethod
    def _mix(a, b, t):
        pa = [int(a[i:i + 2], 16) for i in (1, 3, 5)]; pb = [int(b[i:i + 2], 16) for i in (1, 3, 5)]
        return "#%02x%02x%02x" % tuple(int(x + (y - x) * t) for x, y in zip(pa, pb))
    def _round(self, x1, y1, x2, y2, r, **kw):
        pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
               x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
        return self.cv.create_polygon(pts, smooth=True, **kw)
    def draw(self):
        c = self.cv; c.delete("all"); w, h = self.w, self.h
        if self.state_ != "normal":
            top, bot, fg, label = "#B8C2CF", "#A5B0BF", "#F4F6F8", self.busy_text
        elif self.down:
            top, bot, fg, label = "#123A78", "#0C2A59", "white", self.text
        elif self.hover:
            top, bot, fg, label = "#2F7BEA", "#1A55B8", "white", self.text
        else:
            top, bot, fg, label = "#2467D1", "#173F8A", "white", self.text
        off = 2 if self.down else 0
        if self.state_ == "normal" and not self.down:
            self._round(3, 6, w - 3, h + 4, 20, fill="#C9D3E3", outline="")      # bayangan lembut
        r = 20
        self._round(2, 2 + off, w - 2, h - 2 + off, r, fill=bot, outline="")
        self._round(2, 2 + off, w - 2, h * 0.58 + off, r, fill=top, outline="")  # kilau atas (gradasi dua nada)
        c.create_rectangle(r, h * 0.45 + off, w - r, h * 0.62 + off, fill=self._mix(top, bot, .5), outline="")
        self._round(2, 2 + off, w - 2, h - 2 + off, r, fill="", outline=self._mix(bot, "#000000", .15), width=1)
        cy = h / 2 + off
        if self.state_ == "normal":
            ix = 30
            c.create_oval(ix - 13, cy - 13, ix + 13, cy + 13, fill="white", outline="")
            c.create_polygon(ix - 4, cy - 7, ix - 4, cy + 7, ix + 7, cy, fill=bot, outline=bot)
        c.create_text(w / 2 + 14, cy, text=label, fill=fg, font=self.font)


def cmd_update(a):
    cfg = core.load_config(HERE)
    try:
        if a.rollback:
            last, n = upd.rollback(HERE); print("Dipulihkan dari %s (%d berkas). Mulai ulang aplikasi." % (last, n)); return 0
        info = upd.check(cfg.get("update_repo") or upd.DEFAULT_REPO, core.APP_VERSION, cfg.get("update_token", ""))
        print("Terpasang: %s | Rilis terbaru: %s | %s" % (core.APP_VERSION, info["version"], "ADA VERSI BARU" if info["newer"] else "sudah terbaru"))
        if info["newer"]:
            print("Catatan rilis:\n%s\nSHA-256: %s" % (info["notes"] or "-", info["sha256"] or "TIDAK ADA"))
        if a.update and info["newer"]:
            bdir, files, jsons = upd.download_and_apply(info, HERE, core.APP_VERSION, cfg.get("update_token", ""))
            print("Terpasang %d berkas. Cadangan: %s" % (len(files), bdir))
            if jsons: print("Berkas pengaturan baru disimpan sebagai .baru:", ", ".join(jsons))
        return 0
    except upd.UpdateError as e:
        print("Pembaruan gagal:", e); return 2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cli", action="store_true"); ap.add_argument("--info", action="store_true")
    ap.add_argument("--case"); ap.add_argument("--tools"); ap.add_argument("--out")
    ap.add_argument("--kape", choices=["live", "triage", "sans", "kapetriage", "custom"]); ap.add_argument("--kape-yes", action="store_true")
    ap.add_argument("--kape-dry", action="store_true"); ap.add_argument("--kape-check", action="store_true")
    ap.add_argument("--kape-source", default=os.environ.get("SystemDrive", "C:")); ap.add_argument("--kape-vss", action="store_true")
    ap.add_argument("--kape-targets"); ap.add_argument("--kape-modules"); ap.add_argument("--kape-timeout", type=int, default=14400)
    ap.add_argument("--rebuild", metavar="FOLDER_HASIL", help="bangun ulang Laporan Final + Integrasi dari folder hasil (tanpa menjalankan alat)")
    ap.add_argument("--update-check", action="store_true", help="periksa versi terbaru di GitHub (repositori dari config.json: update_repo)")
    ap.add_argument("--update", action="store_true", help="unduh, verifikasi SHA-256, cadangkan, dan pasang versi terbaru")
    ap.add_argument("--rollback", action="store_true", help="pulihkan cadangan versi sebelumnya")
    ap.add_argument("--no-ntp", action="store_true"); ap.add_argument("--only"); ap.add_argument("--monitor", type=int, default=30)
    a = ap.parse_args()
    if a.update_check or a.update or a.rollback:
        return cmd_update(a)
    if a.rebuild:
        try:
            pdf, stamp = core.rebuild_reports(a.rebuild)
        except Exception as e:
            print("Gagal membangun ulang laporan: %s: %s" % (type(e).__name__, e)); return 2
        print("Laporan baru ada di:", pdf); return 0
    tools_dir = a.tools or core.find_tools_dir(HERE, core.load_config(HERE).get("tools"))
    if not tools_dir:
        print("Folder alat tidak ditemukan. Letakkan folder alat (berisi 'usbdeview', '64bit', dst.) di samping/di dalam ForensikRunner, atau pilih manual di aplikasi / pakai --tools.")
        if not (a.cli or a.info):
            tools_dir = HERE
        else:
            return 2
    if a.kape_check:
        return kape_check(tools_dir)
    if a.info:
        cmd_info(tools_dir); return 0
    if a.cli:
        if not a.case:
            print("--case wajib pada mode CLI"); return 2
        return run_cli(a, tools_dir)
    run_gui(tools_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
