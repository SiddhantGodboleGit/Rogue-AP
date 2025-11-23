#!/usr/bin/env python3
# gui_client_detector.py (modified)
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
from scapy.all import sniff, RadioTap, Dot11, Dot11Elt, Dot11Beacon
import statistics

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
        # match main GUI start size and minimums for consistent UX
        self.geometry("900x600")
        self.minsize(1800, 1000)

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

        # Use same palette and ttk style settings as main GUI for consistent aesthetics
        self._bg_primary = "#f6f1e1"
        self._bg_panel = "#fefaf0"
        self._accent = "#b8893f"
        self._accent_dark = "#9a6c2a"
        self._text_main = "#3f2a14"
        self._muted = "#6c5434"
        self.configure(bg=self._bg_primary)

        try:
            # mirror gui.py style configuration
            self.style.configure('TFrame', background=self._bg_primary)
            self.style.configure('TLabel', background=self._bg_primary, foreground=self._text_main)
            self.style.configure('Header.TLabel', background=self._bg_primary, foreground=self._accent, font=("Garamond", 12, 'bold'))
            self.style.configure('TButton', padding=6, background=self._accent, foreground="white", borderwidth=0)
            self.style.map('TButton', background=[('active', self._accent_dark), ('disabled', '#d4c3a3')], foreground=[('disabled', '#a99a84')])
            self.style.configure('Treeview', background=self._bg_panel, fieldbackground=self._bg_panel, foreground=self._text_main)
            self.style.configure('Treeview.Heading', background='#f0e3c7', foreground=self._accent, font=("Garamond", 11, 'bold'))
            self.style.map('Treeview', background=[('selected', '#ecd9b0')], foreground=[('selected', self._text_main)])
            self.style.configure('Toolbar.TFrame', background=self._bg_primary)
            self.style.configure('Panel.TFrame', background=self._bg_panel)
            self.style.configure('Status.TLabel', background=self._bg_primary, foreground=self._muted, font=("Garamond", 10, 'italic'))
            self.style.configure('TEntry', fieldbackground=self._bg_panel, foreground=self._text_main)
            self.style.map('TEntry', fieldbackground=[('disabled', '#ede1c7'), ('readonly', '#f2e7d0')])
            self.style.configure('TSpinbox', fieldbackground=self._bg_panel, foreground=self._text_main)
            self.style.map('TSpinbox', fieldbackground=[('disabled', '#ede1c7')])
            self.style.configure('TCheckbutton', background=self._bg_primary, foreground=self._text_main)
            self.style.map('TCheckbutton', foreground=[('disabled', self._muted)])
            self.style.configure('Horizontal.TProgressbar', background=self._accent, troughcolor='#efe5cc', bordercolor='#d4c3a3')
            self.style.configure('TPanedwindow', background=self._bg_primary)
        except Exception:
            pass

        # ---------- State ----------
        self._queue = queue.Queue()
        self._aps_info = {}       # bssid(lower) -> info dict
        self._all_aps = {}        # mirror of _aps_info for filtering/repopulate
        self._suspicious = {}     # bssid(lower) -> result dict

        # Heuristic weights: prefer detector's WEIGHTS if available
        default_weights = {
            'whitelist': -5,
            'duplicate_ssid': 3,
            'vendor_mismatch': 4,
            'channel_spread': 2,
            'missing_vendor_ies': 2,
            'short_beacon': 1,
            'rssi_anomaly': 2,
        }
        try:
            self.heuristic_weights = getattr(detector, 'WEIGHTS', default_weights)
        except Exception:
            self.heuristic_weights = default_weights

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
        # Outer vertical pane to hold top (APs + Suspicious) and bottom (Log)
        outer = ttk.Panedwindow(self, orient=tk.VERTICAL)
        
        # Top horizontal split: APs left, Suspicious right
        main = ttk.Panedwindow(outer, orient=tk.HORIZONTAL)

        # Left: APs
        left = ttk.Frame(main, padding=(10, 8))
        ttk.Label(left, text="Access Points", style='Header.TLabel').pack(anchor='w', pady=(0, 6))
        ap_wrap = ttk.Frame(left, style='Panel.TFrame', padding=4)
        cols = ("bssid","ssid","channel")
        self.tree = ttk.Treeview(ap_wrap, columns=cols, show='headings', selectmode='browse')
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
        ctrl = ttk.Frame(left, style='Panel.TFrame')
        ttk.Button(ctrl, text="Export CSV", command=self.export_csv).pack(side='left', padx=(0,8))
        ttk.Button(ctrl, text="Copy Selected BSSID", command=self.copy_selected_bssid).pack(side='left')
        ctrl.pack(anchor='w', pady=(8,0))

        # Right: Suspicious APs and details
        right = ttk.Frame(main, padding=(10, 8))
        ttk.Label(right, text="Suspicious APs", style='Header.TLabel').pack(anchor='w', pady=(0, 6))
        scol = ("bssid","ssid","score","severity")
        susp_wrap = ttk.Frame(right, style='Panel.TFrame', padding=4)
        self.susp_tree = ttk.Treeview(susp_wrap, columns=scol, show='headings')
        self.susp_tree.heading('bssid', text='BSSID')
        self.susp_tree.heading('ssid', text='SSID')
        self.susp_tree.heading('score', text='Score')
        self.susp_tree.heading('severity', text='Severity')
        self.susp_tree.column('bssid', width=260, anchor='w', stretch=False)
        self.susp_tree.column('ssid', width=240, anchor='w', stretch=True)
        self.susp_tree.column('score', width=80, anchor='center', stretch=False)
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
        ttk.Label(right, text="Reasons / Details", style='Header.TLabel').pack(anchor='w', pady=(10, 4))
        
        # Small weight legend to explain heuristics
        weights_legend = ttk.Frame(right, style='Panel.TFrame', padding=(6, 4))
        ttk.Label(weights_legend, text="Heuristic weights:", font=("Garamond", 10, 'bold')).pack(anchor='w')
        # Build legend text from self.heuristic_weights in a single line for compactness
        legend_items = []
        for k, v in self.heuristic_weights.items():
            legend_items.append(f"{k}={v}")
        ttk.Label(weights_legend, text=", ".join(legend_items), wraplength=400, style='TLabel', font=("Garamond", 9)).pack(anchor='w', pady=(2,0))
        weights_legend.pack(fill='x', pady=(0, 6))

        reasons_wrap = ttk.Frame(right, style='Panel.TFrame', padding=4)
        self.reasons_text = tk.Text(reasons_wrap, wrap='word', state='disabled', 
                                   background=self._bg_panel, fg=self._text_main,
                                   relief='flat', highlightthickness=1,
                                   highlightbackground='#dec79a', highlightcolor='#dec79a')
        reasons_scroll = ttk.Scrollbar(reasons_wrap, orient='vertical', command=self.reasons_text.yview)
        self.reasons_text.configure(yscrollcommand=reasons_scroll.set)
        self.reasons_text.pack(side='left', fill=tk.BOTH, expand=True)
        reasons_scroll.pack(side='right', fill='y')
        reasons_wrap.pack(fill=tk.BOTH, expand=True)

        main.add(left, weight=3)
        main.add(right, weight=2)
        
        # Bottom log (resizable as part of outer pane)
        bottom = ttk.Frame(outer, padding=(10, 8))
        ttk.Label(bottom, text="Log", style='Header.TLabel').pack(anchor='w', pady=(0, 6))
        log_wrap = ttk.Frame(bottom, style='Panel.TFrame', padding=4)
        self.log_text = tk.Text(log_wrap, wrap='none', 
                               background=self._bg_panel, fg=self._text_main,
                               relief='flat', highlightthickness=1,
                               highlightbackground='#dec79a', highlightcolor='#dec79a',
                               insertbackground=self._accent)
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

        # Add to outer pane with proper weights
        outer.add(main, weight=3)
        outer.add(bottom, weight=1)
        
        self.left = left
        self.right = right
        self.bottom = bottom
        self.main = main
        self.pw = outer

    def _layout(self):
        # Pack outer paned window
        self.pw.pack(fill=tk.BOTH, expand=True)

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

            # Helper: stores AP info provided by scanner.scan_aps
            def on_ap(bssid, info):
                bl = bssid.lower()
                if bl in seen:
                    return
                seen.add(bl)
                ssid = info.get('ssid','') if isinstance(info, dict) else str(info)
                ch = info.get('channel','') if isinstance(info, dict) else ''
                # ensure we keep the dict object for later merging of rssi_samples
                self._aps_info[bl] = info if isinstance(info, dict) else {'ssid': ssid}
                self._all_aps[bl] = self._aps_info[bl]
                self._queue.put(('add_ap', (bssid, ssid, ch)))

            # --- RSSI collector via scapy sniff (runs in parallel) ---
            # We'll collect a small number of RSSI samples per BSSID and store them
            rssi_samples_limit = 8

            # thread-safe collector closure
            def rssi_handler(pkt):
                try:
                    if not pkt.haslayer(Dot11):
                        return
                    # only process beacon frames (Dot11Beacon) to match scanner
                    if not pkt.haslayer(Dot11Beacon):
                        return
                    bssid = pkt[Dot11].addr3
                    if not bssid:
                        return
                    bl = bssid.lower()
                    # Extract RSSI defensively from RadioTap
                    rssi_val = None
                    try:
                        if pkt.haslayer(RadioTap):
                            rt = pkt.getlayer(RadioTap)
                            rssi_val = getattr(rt, 'dBm_AntSignal', None)
                        if rssi_val is None:
                            # fallback attempt
                            rssi_val = getattr(pkt, 'dBm_AntSignal', None)
                        if rssi_val is not None:
                            rssi_val = int(rssi_val)
                    except Exception:
                        rssi_val = None

                    if rssi_val is None:
                        return

                    # store into shared _aps_info structure (create if missing)
                    info = self._aps_info.get(bl)
                    if info is None:
                        # keep minimal fields so detector still sees SSID if later present
                        info = {'ssid': '', 'ies_hex': None, 'channel': None, 'beacon_int': None}
                        self._aps_info[bl] = info
                        self._all_aps[bl] = info

                    # use a small list 'rssi_samples' to accumulate values
                    lst = info.get('rssi_samples')
                    if not isinstance(lst, list):
                        lst = []
                        info['rssi_samples'] = lst
                    # append if under limit
                    if len(lst) < rssi_samples_limit:
                        lst.append(rssi_val)
                except Exception:
                    # never allow sniffer to crash the GUI thread
                    return

            # start background sniffing for the same timeout
            sniff_thread = threading.Thread(target=lambda: sniff(iface=mon_iface, prn=rssi_handler, timeout=timeout, store=0), daemon=True)
            sniff_thread.start()
            # --- end RSSI collector ---

            # start progress UI
            self.status_var.set("Scanning...")
            self.progress.start(10)
            # Run the existing scanner which will call on_ap() for each AP found
            aps = scanner.scan_aps(mon_iface, timeout=timeout, on_ap=on_ap)

            # Ensure any APs returned synchronously by scanner are merged into UI if not seen
            for b, info in (aps or {}).items():
                bl = b.lower()
                if bl not in seen:
                    on_ap(b, info)

            # Wait briefly for sniff thread to finish (it should end when timeout elapses)
            try:
                sniff_thread.join(timeout=1.0)
            except Exception:
                pass

            # --- Post-process: compute median RSSI and attach single 'rssi' value for detector ---
            for bl, info in list(self._aps_info.items()):
                try:
                    if isinstance(info, dict):
                        samples = info.get('rssi_samples') or []
                        # if samples present, compute median robustly
                        if samples:
                            try:
                                med = statistics.median(samples)
                                # store median as integer rssi value (detector expects int)
                                info['rssi'] = int(med)
                            except Exception:
                                # fallback: take first sample
                                info['rssi'] = int(samples[0])
                        else:
                            # leave info['rssi'] as None if no samples collected
                            if 'rssi' not in info:
                                info['rssi'] = None
                    # update the mirrored all_aps too
                    self._all_aps[bl] = self._aps_info[bl]
                except Exception:
                    continue

            self._append_log(f"Scan complete: {len(self._aps_info)} AP(s) observed (RSSI samples collected)")
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
                        score = val.get('score', 0)
                        tag = sev
                        # Insert values in order: bssid, ssid, score, severity
                        self.susp_tree.insert('', tk.END, values=(b, ss, score, sev), tags=(tag,))
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
                self._queue.put(('log', f"{b} -> {val['severity']}: {'; '.join(val.get('reasons', []))}"))
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
            # values order: bssid, ssid, score, severity
            vals = self.susp_tree.item(iid,'values')
            if not vals:
                return
            bssid = vals[0]
            ssid = vals[1] if len(vals) > 1 else ''
            sev = vals[3] if len(vals) > 3 else vals[-1]
            rec = self._suspicious.get(bssid.lower())
            if not rec:
                return

            # Header + summary
            header = f"Suspicious AP {bssid} ({ssid})\nSeverity: {rec.get('severity','N/A')}\nScore: {rec.get('score','N/A')}\n\n"

            # If detector returned structured reasons, use them
            detailed = rec.get('detailed_reasons')
            explanation_lines = []
            total_calc = 0
            if isinstance(detailed, list) and detailed:
                for d in detailed:
                    key = d.get('key')
                    w = d.get('weight', 0)
                    text = d.get('text') or d.get('key') or ''
                    explanation_lines.append(f"{text}  →  ({key}, weight={w})")
                    try:
                        total_calc += int(w)
                    except Exception:
                        pass
            else:
                # Fallback: map legacy textual reasons to weights where possible
                for r in (rec.get('reasons') or []):
                    mapped = None
                    rl = r.lower()
                    if 'whitelist' in rl:
                        mapped = 'whitelist'
                    elif 'ssid appears' in rl or 'bssid(s)' in rl or 'appears with' in rl:
                        mapped = 'duplicate_ssid'
                    elif 'vendor ie' in rl and 'differ' in rl:
                        mapped = 'vendor_mismatch'
                    elif 'missing vendor' in rl or 'missing vendor ies' in rl:
                        mapped = 'missing_vendor_ies'
                    elif 'channel' in rl and ('many' in rl or 'channels' in rl):
                        mapped = 'channel_spread'
                    elif 'unusually short' in rl or 'beacon interval' in rl:
                        mapped = 'short_beacon'
                    elif 'rssi' in rl:
                        mapped = 'rssi_anomaly'

                    if mapped:
                        w = self.heuristic_weights.get(mapped, 0)
                        explanation_lines.append(f"{r}  →  ({mapped}, weight={w})")
                        try:
                            total_calc += int(w)
                        except Exception:
                            pass
                    else:
                        explanation_lines.append(f"{r}  →  (weight=N/A)")

            # Build detail text: include raw info as well
            info = rec.get('info', {}) if rec else {}
            info_lines = []
            if isinstance(info, dict):
                # show some useful fields first
                for k in ('ssid','channel','ies_hex','beacon_int','rssi','rssi_samples'):
                    if k in info:
                        info_lines.append(f"{k}: {info.get(k)}")
                # any other fields
                for k,v in info.items():
                    if k not in ('ssid','channel','ies_hex','beacon_int','rssi','rssi_samples'):
                        info_lines.append(f"{k}: {v}")

            # Present everything in the reasons_text widget
            self.reasons_text.configure(state='normal')
            self.reasons_text.delete(1.0,'end')
            self.reasons_text.insert('end', header)
            self.reasons_text.insert('end', "Why this AP was flagged (heuristic -> weight):\n")
            for line in explanation_lines:
                self.reasons_text.insert('end', f"- {line}\n")
            self.reasons_text.insert('end', f"\nCalculated weight sum (from mapped heuristics): {total_calc}\n")
            # show detector's computed score to compare
            self.reasons_text.insert('end', f"Detector reported score: {rec.get('score')}\n\n")
            self.reasons_text.insert('end', "Raw AP info:\n")
            for line in info_lines:
                self.reasons_text.insert('end', f"- {line}\n")
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
