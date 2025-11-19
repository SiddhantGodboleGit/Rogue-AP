#!/usr/bin/env python3
"""
gui_client_detector_enhanced.py

Enhanced client-side Rogue AP detector GUI based on your original gui_client_detector.py
Additions:
 - Search / Filter AP list (SSID/BSSID)
 - Save / Load whitelist (JSON)
 - Color-coded suspicious list by severity
 - Indeterminate progress bar when scanning / detecting
 - Right-click menu on AP rows (copy BSSID, set SSID field)
 - Keyboard shortcuts (Ctrl+F focus search, Ctrl+S save whitelist)
 - Double-click behaviors for convenience
 - Small style / layout polish while remaining pure Tkinter/ttk

Drop into same folder as scanner.py, ap_manager.py, client_detector.py and run:
    sudo python3 gui_client_detector_enhanced.py
"""
from pathlib import Path
import os
import sys
import threading
import subprocess
import queue
import time
import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# local detector
try:
    import client_detector as detector
except Exception:
    detector = None

try:
    import scanner
except Exception:
    scanner = None

try:
    from ap_manager import start_ap
except Exception:
    start_ap = None

APP_DIR = Path(__file__).resolve().parent
SCANNER_PATH = APP_DIR / "scanner.py"

class EnhancedGuiClientDetectorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Rogue AP — Client Detector (Enhanced)")
        self.geometry("1200x820")
        self.minsize(1100, 700)

        # ---------- Styling ----------
        self.style = ttk.Style(self)
        try:
            self.style.theme_use('clam')
        except Exception:
            pass

        default_font = ("Garamond", 11)
        try:
            self.option_add("*Font", default_font)
        except Exception:
            pass

        self._bg_primary = "#f6f1e1"
        self._bg_panel = "#fefaf0"
        self._accent = "#b8893f"
        self._accent_dark = "#9a6c2a"
        self._text_main = "#3f2a14"
        self._muted = "#6c5434"
        self.configure(bg=self._bg_primary)

        # Style tweaks
        try:
            self.style.configure('TFrame', background=self._bg_primary)
            self.style.configure('TLabel', background=self._bg_primary, foreground=self._text_main)
            self.style.configure('Header.TLabel', background=self._bg_primary, foreground=self._accent, font=("Garamond", 13, 'bold'))
            self.style.configure('TButton', padding=6, background=self._accent, foreground="white", borderwidth=0)
            self.style.map('TButton', background=[('active', self._accent_dark), ('disabled', '#d4c3a3')],
                                         foreground=[('disabled', '#a99a84')])
            self.style.configure('Treeview', background=self._bg_panel, fieldbackground=self._bg_panel, foreground=self._text_main, rowheight=28)
            self.style.configure('Treeview.Heading', background='#f0e3c7', foreground=self._accent, font=("Garamond", 11, 'bold'))
            self.style.configure('Panel.TFrame', background=self._bg_panel)
            self.style.configure('Status.TLabel', background=self._bg_primary, foreground=self._muted, font=("Garamond", 10, 'italic'))
            self.style.configure('TEntry', fieldbackground=self._bg_panel, foreground=self._text_main)
            self.style.configure('Horizontal.TProgressbar', background=self._accent, troughcolor='#efe5cc', bordercolor='#d4c3a3')
        except Exception:
            pass

        # ---------- State ----------
        self._queue = queue.Queue()
        self._aps_info = {}       # bssid(lower) -> info dict
        self._all_aps = {}        # mirror of _aps_info for filtering/repopulate
        self._suspicious = {}     # bssid(lower) -> result dict

        # ---------- UI ----------
        self._create_toolbar()
        self._create_main_panes()
        self._layout()
        self._bind_shortcuts()

        # Poll queue
        self.after(100, self._process_queue)

    # ---------------------- Toolbar & Filters ----------------------
    def _create_toolbar(self):
        toolbar = ttk.Frame(self, padding=(8,6), style='TFrame')

        ttk.Label(toolbar, text="Interface:", style='Header.TLabel').grid(row=0, column=0, sticky='w')
        self.iface_var = tk.StringVar()
        self.iface_entry = ttk.Entry(toolbar, width=12, textvariable=self.iface_var)
        self.iface_entry.grid(row=0, column=1, padx=(6,8))
        ttk.Button(toolbar, text="Discover", command=self.discover_interfaces).grid(row=0, column=2, padx=4)
        ttk.Button(toolbar, text="Start Monitor", command=self.on_start_monitor).grid(row=0, column=3, padx=4)
        ttk.Button(toolbar, text="Stop Monitor", command=self.on_stop_monitor).grid(row=0, column=4, padx=4)
        ttk.Button(toolbar, text="Scan APs", command=self.on_scan_aps).grid(row=0, column=5, padx=4)

        # Status & progress on right
        self.status_var = tk.StringVar(value="Idle")
        self.progress = ttk.Progressbar(toolbar, mode='indeterminate', style='Horizontal.TProgressbar', length=180)
        self.progress.grid(row=0, column=97, sticky='e', padx=(6,0))
        ttk.Label(toolbar, textvariable=self.status_var, style='Status.TLabel').grid(row=0, column=98, sticky='e', padx=(6,0))
        toolbar.grid_columnconfigure(96, weight=1)
        self.toolbar = toolbar
        toolbar.pack(fill=tk.X)

        # Filters / Whitelist row
        filters = ttk.Frame(self, padding=(8,6), style='TFrame')
        ttk.Label(filters, text="Search (SSID / BSSID):").grid(row=0, column=0, sticky='w')
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(filters, width=36, textvariable=self.search_var)
        self.search_entry.grid(row=0, column=1, padx=(6,4), sticky='w')
        self.search_var.trace_add('write', lambda *a: self._apply_filter())

        ttk.Button(filters, text="Clear", command=self._clear_results).grid(row=0, column=2, padx=(8,4))
        ttk.Separator(filters, orient='vertical').grid(row=0, column=3, padx=8, sticky='ns')

        ttk.Label(filters, text="Whitelist SSIDs (comma):").grid(row=0, column=4, padx=(6,4), sticky='w')
        self.whitelist_ssid_var = tk.StringVar(value="")
        ttk.Entry(filters, width=28, textvariable=self.whitelist_ssid_var).grid(row=0, column=5, sticky='w')

        ttk.Label(filters, text="Whitelist BSSIDs (comma):").grid(row=0, column=6, padx=(12,6), sticky='w')
        self.whitelist_bssid_var = tk.StringVar(value="")
        ttk.Entry(filters, width=24, textvariable=self.whitelist_bssid_var).grid(row=0, column=7, sticky='w')

        ttk.Button(filters, text="Detect Rogue APs", command=self.on_detect).grid(row=0, column=8, padx=(12,0))
        ttk.Button(filters, text="Save Whitelist", command=self.save_whitelist).grid(row=0, column=9, padx=(8,0))
        ttk.Button(filters, text="Load Whitelist", command=self.load_whitelist).grid(row=0, column=10, padx=(4,0))

        filters.pack(fill=tk.X, pady=(2,4))

    # ---------------------- Main panes ----------------------
    def _create_main_panes(self):
        main = ttk.Panedwindow(self, orient=tk.HORIZONTAL)

        # Left: APs
        left = ttk.Frame(main, padding=8)
        ttk.Label(left, text="Access Points", style='Header.TLabel').pack(anchor='w')
        ap_wrap = ttk.Frame(left, style='Panel.TFrame', padding=6)
        cols = ("bssid","ssid","channel")
        self.tree = ttk.Treeview(ap_wrap, columns=cols, show='headings', selectmode='browse', height=20)
        self.tree.heading('bssid', text='BSSID')
        self.tree.heading('ssid', text='SSID')
        self.tree.heading('channel', text='Ch')
        self.tree.column('bssid', width=240, anchor='w', stretch=False)
        self.tree.column('ssid', width=520, anchor='w', stretch=True)
        self.tree.column('channel', width=70, anchor='center', stretch=False)
        # Scrollbars
        ysb = ttk.Scrollbar(ap_wrap, orient='vertical', command=self.tree.yview)
        xsb = ttk.Scrollbar(ap_wrap, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        ysb.grid(row=0, column=1, sticky='ns')
        xsb.grid(row=1, column=0, sticky='ew')
        ap_wrap.grid_columnconfigure(0, weight=1)
        ap_wrap.grid_rowconfigure(0, weight=1)
        ap_wrap.pack(fill=tk.BOTH, expand=True)
        self.tree.bind('<<TreeviewSelect>>', self._on_ap_selected)
        self.tree.bind('<Double-1>', self._on_ap_double)
        self.tree.bind('<Button-3>', self._on_ap_right_click)  # right click

        # Controls under AP table
        ctrl = ttk.Frame(left)
        ttk.Button(ctrl, text="Export CSV", command=self.export_csv).pack(side='left', padx=(0,6))
        ttk.Button(ctrl, text="Copy Selected BSSID", command=self.copy_selected_bssid).pack(side='left')
        ctrl.pack(anchor='w', pady=(6,0))

        # Right: Suspicious APs and details
        right = ttk.Frame(main, padding=8)
        ttk.Label(right, text="Suspicious APs", style='Header.TLabel').pack(anchor='w')
        scol = ("bssid","ssid","severity")
        susp_wrap = ttk.Frame(right, style='Panel.TFrame', padding=6)
        self.susp_tree = ttk.Treeview(susp_wrap, columns=scol, show='headings', height=10)
        self.susp_tree.heading('bssid', text='BSSID')
        self.susp_tree.heading('ssid', text='SSID')
        self.susp_tree.heading('severity', text='Severity')
        self.susp_tree.column('bssid', width=260, anchor='w', stretch=False)
        self.susp_tree.column('ssid', width=300, anchor='w', stretch=True)
        self.susp_tree.column('severity', width=120, anchor='center', stretch=False)
        ysb2 = ttk.Scrollbar(susp_wrap, orient='vertical', command=self.susp_tree.yview)
        self.susp_tree.configure(yscrollcommand=ysb2.set)
        self.susp_tree.grid(row=0, column=0, sticky='nsew')
        ysb2.grid(row=0, column=1, sticky='ns')
        susp_wrap.grid_columnconfigure(0, weight=1)
        susp_wrap.grid_rowconfigure(0, weight=1)
        susp_wrap.pack(fill=tk.BOTH, expand=False)
        self.susp_tree.bind('<<TreeviewSelect>>', self._on_susp_selected)
        self.susp_tree.bind('<Double-1>', self._on_susp_double)

        # Color tags for severity
        try:
            self.tree.tag_configure('benign', background='#e8f7e8')  # soft green
            self.tree.tag_configure('suspicious', background='#fff7e0')  # soft yellow
            self.tree.tag_configure('highly suspicious', background='#ffe3e3')  # soft red
            self.susp_tree.tag_configure('benign', background='#e8f7e8')
            self.susp_tree.tag_configure('suspicious', background='#fff7e0')
            self.susp_tree.tag_configure('highly suspicious', background='#ffe3e3')
        except Exception:
            pass

        # Reasons / Details
        ttk.Label(right, text="Reasons / Details").pack(anchor='w', pady=(8,0))
        self.reasons_text = tk.Text(right, height=18, wrap='word', state='disabled', background=self._bg_panel)
        self.reasons_text.pack(fill=tk.BOTH, expand=True, pady=(4,0))

        main.add(left, weight=3)
        main.add(right, weight=2)
        self.main = main

        # Bottom log
        bottom = ttk.Frame(self, padding=8)
        ttk.Label(bottom, text="Log", style='Header.TLabel').pack(anchor='w')
        log_wrap = ttk.Frame(bottom, style='Panel.TFrame')
        self.log_text = tk.Text(log_wrap, height=10, wrap='none', background=self._bg_panel)
        ysb_log = ttk.Scrollbar(log_wrap, orient='vertical', command=self.log_text.yview)
        xsb_log = ttk.Scrollbar(log_wrap, orient='horizontal', command=self.log_text.xview)
        self.log_text.configure(yscrollcommand=ysb_log.set, xscrollcommand=xsb_log.set)
        self.log_text.grid(row=0, column=0, sticky='nsew')
        ysb_log.grid(row=0, column=1, sticky='ns')
        xsb_log.grid(row=1, column=0, sticky='ew')
        log_wrap.grid_columnconfigure(0, weight=1)
        log_wrap.grid_rowconfigure(0, weight=1)
        log_wrap.pack(fill=tk.BOTH, expand=True)
        self.log_text.configure(state='disabled')

        self.left = left
        self.right = right
        self.bottom = bottom
        self.main.pack(fill=tk.BOTH, expand=True)
        self.bottom.pack(fill=tk.BOTH, expand=False)

    def _layout(self):
        # just ensure toolbar + panes + log are placed
        pass

    # ---------------------- Shortcuts ----------------------
    def _bind_shortcuts(self):
        self.bind_all('<Control-f>', lambda e: self.search_entry.focus_set())
        self.bind_all('<Control-F>', lambda e: self.search_entry.focus_set())
        self.bind_all('<Control-s>', lambda e: self.save_whitelist())
        self.bind_all('<Control-S>', lambda e: self.save_whitelist())

    # ---------------------- Interface discovery / monitor control ----------------------
    def discover_interfaces(self):
        try:
            out = subprocess.check_output(["ip","-o","link"], text=True, stderr=subprocess.DEVNULL)
            ifaces = []
            for line in out.splitlines():
                parts = line.split(':')
                if len(parts) >= 2:
                    ifaces.append(parts[1].strip())
            if ifaces:
                nonloop = [i for i in ifaces if i != 'lo']
                candidates = nonloop if nonloop else ifaces
                wifi = None
                for i in candidates:
                    low = i.lower()
                    if low.startswith(('wlan','wl','wlp')):
                        wifi = i
                        break
                if wifi:
                    self.iface_var.set(wifi)
                self._append_log(f"Discovered interfaces: {', '.join(ifaces)}")
        except Exception as e:
            self._append_log(f"Interface discovery failed: {e}")

    def on_start_monitor(self):
        iface = self.iface_var.get().strip()
        if not iface:
            messagebox.showinfo("Start Monitor","Set an interface first")
            return
        if scanner is None:
            messagebox.showerror("Error","scanner module not available")
            return
        base = self._base_iface(iface)
        if base != iface:
            self.iface_var.set(base)
        t = threading.Thread(target=self._start_monitor_thread, args=(base,), daemon=True)
        t.start()

    def _start_monitor_thread(self, iface):
        try:
            self._append_log(f"Starting monitor mode on {iface}...")
            self.status_var.set("Starting monitor...")
            self.progress.start(10)
            scanner.start_monitor_mode(iface)
            self._append_log("Monitor mode started.")
        except Exception as e:
            self._append_log(f"Failed to start monitor mode: {e}")
        finally:
            self.status_var.set("Idle")
            self.progress.stop()

    def on_stop_monitor(self):
        iface = self.iface_var.get().strip()
        mon = iface + 'mon' if not iface.endswith('mon') else iface
        if scanner is None:
            messagebox.showerror('Error','scanner module not available')
            return
        t = threading.Thread(target=self._stop_monitor_thread, args=(mon,), daemon=True)
        t.start()

    def _stop_monitor_thread(self, mon_iface):
        try:
            self._append_log(f"Stopping monitor mode on {mon_iface}...")
            self.status_var.set("Stopping monitor...")
            self.progress.start(10)
            scanner.stop_monitor_mode(mon_iface)
            self._append_log("Monitor mode stopped.")
        except Exception as e:
            self._append_log(f"Failed to stop monitor mode: {e}")
        finally:
            self.status_var.set("Idle")
            self.progress.stop()

    # ---------------------- Scan APs ----------------------
    def on_scan_aps(self):
        if scanner is None:
            messagebox.showerror("Error","scanner module not available")
            return
        iface = self.iface_var.get().strip()
        if not iface:
            messagebox.showinfo("Scan","Set interface first")
            return
        mon = iface if iface.endswith('mon') else iface + 'mon'
        t = threading.Thread(target=self._scan_aps_thread, args=(mon,15), daemon=True)
        t.start()

    def _scan_aps_thread(self, mon_iface, timeout):
        try:
            self._append_log(f"Scanning for APs on {mon_iface}...")
            seen = set()
            def on_ap(bssid, info):
                bl = bssid.lower()
                if bl in seen:
                    return
                seen.add(bl)
                ssid = info.get('ssid','') if isinstance(info, dict) else str(info)
                ch = info.get('channel','') if isinstance(info, dict) else ''
                # store
                self._aps_info[bl] = info if isinstance(info, dict) else {'ssid': ssid}
                self._all_aps[bl] = self._aps_info[bl]
                self._queue.put(('add_ap', (bssid, ssid, ch)))
            # start progress UI
            self.status_var.set("Scanning...")
            self.progress.start(10)
            aps = scanner.scan_aps(mon_iface, timeout=timeout, on_ap=on_ap)
            # scanner returns dict of aps; ensure all included
            for b, info in (aps or {}).items():
                bl = b.lower()
                if bl not in seen:
                    on_ap(b, info)
            self._append_log(f"Scan complete: {len(self._aps_info)} AP(s) observed")
        except Exception as e:
            self._append_log(f"Scan failed: {e}")
        finally:
            self.status_var.set("Idle")
            self.progress.stop()

    # ---------------------- Process queue ----------------------
    def _process_queue(self):
        try:
            while True:
                item = self._queue.get_nowait()
                kind = item[0]
                if kind == 'add_ap':
                    bssid, ssid, ch = item[1]
                    bl = bssid.lower()
                    # apply current filter when inserting
                    if self._matches_filter(ssid, bl):
                        tag = ''  # default tag; detection may update later
                        if not any(self.tree.set(e,'bssid') == bssid for e in self.tree.get_children()):
                            self.tree.insert('', tk.END, values=(bssid, ssid, ch), tags=(tag,))
                elif kind == 'detection':
                    results = item[1]
                    self._suspicious = results
                    # refresh susp_tree
                    for iid in list(self.susp_tree.get_children()):
                        self.susp_tree.delete(iid)
                    for b, val in results.items():
                        info = val['info']
                        ss = info.get('ssid') if isinstance(info, dict) else ''
                        sev = val.get('severity','suspicious')
                        tag = sev
                        self.susp_tree.insert('', tk.END, values=(b, ss, sev), tags=(tag,))
                    # update AP tree tagging for severity if present
                    self._apply_severity_tags()
                elif kind == 'log':
                    self._append_log(item[1])
        except queue.Empty:
            pass
        finally:
            self.after(100, self._process_queue)

    # ---------------------- Detection ----------------------
    def on_detect(self):
        if detector is None:
            messagebox.showerror("Error","client_detector module not available")
            return
        self.status_var.set("Detecting...")
        self.progress.start(10)
        t = threading.Thread(target=self._detect_thread, daemon=True)
        t.start()

    def _detect_thread(self):
        try:
            self._append_log("Running client-side detection...")
            ssids = [s.strip() for s in (self.whitelist_ssid_var.get() or "").split(",") if s.strip()]
            bssids = [b.strip().lower() for b in (self.whitelist_bssid_var.get() or "").split(",") if b.strip()]
            res = detector.detect_rogue_aps(self._aps_info, whitelist_ssids=ssids, whitelist_bssids=bssids)
            self._queue.put(('detection', res))
            # log top suspicious
            sorted_res = sorted(res.items(), key=lambda x: x[1]['score'], reverse=True)
            for b, val in sorted_res[:6]:
                self._queue.put(('log', f"{b} -> {val['severity']}: {'; '.join(val['reasons'])}"))
            self._append_log("Detection complete.")
        except Exception as e:
            self._append_log(f"Detection failed: {e}")
        finally:
            self.status_var.set("Idle")
            self.progress.stop()

    # ---------------------- Tree interactions ----------------------
    def _on_ap_selected(self, event):
        try:
            sel = self.tree.selection()
            if not sel:
                return
            iid = sel[0]
            vals = self.tree.item(iid,'values')
            bssid = vals[0]
            info = self._all_aps.get(bssid.lower(), {})
            self._show_info_in_details(f"Details for {bssid}:", info)
            # fill SSID field in case user wants to clone
            ssid = info.get('ssid') if isinstance(info, dict) else ''
            # set UI ssid field if available on main gui pattern (compat)
            # (the original had an SSID field in gui.py; here we only set search for convenience)
            self.search_var.set(self.search_var.get())  # no-op to maintain reactive behavior
        except Exception:
            pass

    def _on_ap_double(self, event):
        # double click -> copy bssid to clipboard
        self.copy_selected_bssid()

    def _on_ap_right_click(self, event):
        # context menu on AP list
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Copy BSSID", command=self.copy_selected_bssid)
        menu.add_command(label="Set as Whitelisted BSSID", command=self._set_selected_as_whitelist_bssid)
        menu.add_command(label="Show Details", command=lambda: self._on_ap_selected(None))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _on_susp_selected(self, event):
        try:
            sel = self.susp_tree.selection()
            if not sel:
                return
            iid = sel[0]
            bssid, ssid, sev = self.susp_tree.item(iid,'values')
            rec = self._suspicious.get(bssid.lower())
            title = f"Suspicious AP {bssid} ({ssid})\nSeverity: {sev}\n\nReasons:\n"
            self._show_info_in_details(title, rec.get('info',{}) if rec else {})
            # expand reasons too
            if rec:
                self.reasons_text.configure(state='normal')
                self.reasons_text.insert('end', "\nDetailed reasons:\n")
                for r in rec.get('reasons', []):
                    self.reasons_text.insert('end', f"- {r}\n")
                self.reasons_text.configure(state='disabled')
        except Exception:
            pass

    def _on_susp_double(self, event):
        sel = self.susp_tree.selection()
        if not sel:
            return
        iid = sel[0]
        bssid = self.susp_tree.item(iid,'values')[0]
        # set search to that bssid so user can inspect in AP list
        self.search_var.set(bssid)

    def _show_info_in_details(self, heading, info: dict):
        self.reasons_text.configure(state='normal')
        self.reasons_text.delete(1.0,'end')
        self.reasons_text.insert('end', heading + '\n\n')
        if not info:
            self.reasons_text.insert('end', "(no additional info)\n")
        else:
            for k, v in (info.items() if isinstance(info, dict) else []):
                self.reasons_text.insert('end', f"{k}: {v}\n")
        self.reasons_text.configure(state='disabled')

    # ---------------------- Utilities ----------------------
    def _append_log(self, msg):
        t = time.strftime('%H:%M:%S') + ' - ' + msg + '\n'
        self.log_text.configure(state='normal')
        self.log_text.insert('end', t)
        self.log_text.see('end')
        self.log_text.configure(state='disabled')

    def _clear_results(self):
        for iid in list(self.tree.get_children()):
            self.tree.delete(iid)
        self._aps_info.clear()
        self._all_aps.clear()
        self.search_var.set("")

    def export_csv(self):
        items = []
        for iid in self.tree.get_children():
            bssid, ssid, ch = self.tree.item(iid,'values')
            items.append((bssid, ssid, ch))
        if not items:
            messagebox.showinfo("Export","No results")
            return
        path = filedialog.asksaveasfilename(defaultextension='.csv')
        if not path:
            return
        try:
            with open(path,'w',encoding='utf-8') as f:
                f.write("BSSID,SSID,Channel\n")
                for b,s,c in items:
                    f.write(f'"{b}","{s}","{c}"\n')
            messagebox.showinfo("Export", f"Saved {len(items)} rows to {path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def copy_selected_bssid(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Copy", "Select an AP first")
            return
        iid = sel[0]
        bssid = self.tree.item(iid, 'values')[0]
        try:
            self.clipboard_clear()
            self.clipboard_append(bssid)
            self._append_log(f"Copied BSSID {bssid} to clipboard")
        except Exception:
            pass

    def _set_selected_as_whitelist_bssid(self):
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        bssid = self.tree.item(iid, 'values')[0]
        cur = [b.strip() for b in (self.whitelist_bssid_var.get() or "").split(",") if b.strip()]
        if bssid.lower() not in [x.lower() for x in cur]:
            cur.append(bssid)
            self.whitelist_bssid_var.set(",".join(cur))
            self._append_log(f"Added {bssid} to whitelist BSSIDs")

    def _base_iface(self, iface: str) -> str:
        iface = (iface or '').strip()
        return iface[:-3] if iface.endswith('mon') else iface

    # ---------------------- Filter logic ----------------------
    def _matches_filter(self, ssid, bssid_lower):
        q = (self.search_var.get() or "").strip().lower()
        if not q:
            return True
        return q in (ssid or '').lower() or q in (bssid_lower or '').lower()

    def _apply_filter(self):
        # repopulate AP tree from _all_aps applying filter
        q = (self.search_var.get() or "").strip().lower()
        # clear
        for iid in list(self.tree.get_children()):
            self.tree.delete(iid)
        for b, info in self._all_aps.items():
            ssid = info.get('ssid','') if isinstance(info, dict) else str(info)
            ch = info.get('channel','') if isinstance(info, dict) else ''
            if self._matches_filter(ssid, b):
                # tag severity if detection result exists
                tag = ''
                rec = self._suspicious.get(b)
                if rec:
                    tag = rec.get('severity','')
                self.tree.insert('', tk.END, values=(b, ssid, ch), tags=(tag,))

    def _apply_severity_tags(self):
        # update tree rows with severity tags where available
        for iid in self.tree.get_children():
            vals = self.tree.item(iid, 'values')
            if not vals:
                continue
            b = vals[0].lower()
            rec = self._suspicious.get(b)
            tag = rec.get('severity','') if rec else ''
            try:
                self.tree.item(iid, tags=(tag,))
            except Exception:
                pass

    # ---------------------- Whitelist save/load ----------------------
    def save_whitelist(self, _event=None):
        data = {
            "ssids": [s.strip() for s in (self.whitelist_ssid_var.get() or "").split(",") if s.strip()],
            "bssids": [b.strip() for b in (self.whitelist_bssid_var.get() or "").split(",") if b.strip()]
        }
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files","*.json")])
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            self._append_log(f"Saved whitelist to {path}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def load_whitelist(self):
        path = filedialog.askopenfilename(filetypes=[("JSON files","*.json")])
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            ss = data.get('ssids') or []
            bs = data.get('bssids') or []
            self.whitelist_ssid_var.set(",".join(ss))
            self.whitelist_bssid_var.set(",".join(bs))
            self._append_log(f"Loaded whitelist from {path}")
        except Exception as e:
            messagebox.showerror("Load failed", str(e))

    # ---------------------- Misc / Logs ----------------------
    def _append_log(self, msg):
        t = time.strftime('%H:%M:%S') + ' - ' + msg + '\n'
        self.log_text.configure(state='normal')
        self.log_text.insert('end', t)
        self.log_text.see('end')
        self.log_text.configure(state='disabled')

def main():
    app = EnhancedGuiClientDetectorApp()
    app.mainloop()

if __name__ == "__main__":
    main()
