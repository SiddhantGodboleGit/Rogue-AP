#!/usr/bin/env python3
"""
A polished Tkinter GUI for the Rogue AP tools.

Features:
- Menu and toolbar
- Interface selector (auto-discover via `ip link`)
- Run scanner.py as a background subprocess and capture its output
- Indeterminate progress bar while scanning
- Live logging console
- Results table (parses lines like: "BSSID: <bssid>, SSID: <ssid>")

Run with: python3 gui.py

This GUI intentionally runs the scanner as a subprocess instead of importing it
to avoid executing hardware-affecting code at import time.
"""

import os
import sys
import threading
import subprocess
import queue
import time
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Import scanner functions directly so the GUI can call them non-interactively
try:
    import scanner
except Exception:
    scanner = None

try:
    from ap_manager import start_ap
except Exception:
    start_ap = None

try:
    from mitm_attack import MITMAttack
except Exception:
    MITMAttack = None

APP_DIR = Path(__file__).resolve().parent
SCANNER_PATH = APP_DIR / "scanner.py"

class GuiApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Rogue AP — Scanner GUI")
        self.geometry("900x600")
        self.minsize(1800, 1000)

        # Styling
        self.style = ttk.Style(self)
        try:
            self.style.theme_use('clam')
        except Exception:
            pass
        default_font = ("Garamond", 11)
        self.option_add("*Font", default_font)

        self._hacker_mode = tk.BooleanVar(value=False)
        self._set_palette(hacker=False)

        # Work queue for GUI-safe updates
        self._queue = queue.Queue()
        self._proc = None
        self._reader_thread = None
        # Cache of AP details from scanner (bssid -> info dict)
        self._aps_info = {}
        # Deauth attack state
        self.deauth_thread = None
        self.deauth_stop_event = None
        # MITM attack state
        self.mitm_attack = None

        self._create_menu()
        self._create_toolbar()
        self._create_main_panes()
        self._set_palette(self._hacker_mode.get())
        self._layout()

        # Poll queue
        self.after(100, self._process_queue)

    def _set_palette(self, hacker: bool):
        if hacker:
            self._bg_primary = "#263147"
            self._bg_panel = "#2A3E49"
            self._accent = "#148D7D"
            self._accent_dark = "#01b44c"
            self._text_main = "#f2f4f8"
            self._muted = "#8d90a3"
            heading_bg = "#1c1f29"
            panel_border = "#262c38"
            tree_selection = "#2f394d"
            progress_trough = "#161924"
            entry_disabled = "#1c2130"
            entry_readonly = "#181d29"
            btn_disabled_bg = "#1f2432"
            btn_disabled_fg = "#4d5163"
        else:
            self._bg_primary = "#f6f1e1"
            self._bg_panel = "#fefaf0"
            self._accent = "#b8893f"
            self._accent_dark = "#9a6c2a"
            self._text_main = "#3f2a14"
            self._muted = "#6c5434"
            heading_bg = "#f0e3c7"
            panel_border = "#dec79a"
            tree_selection = "#ecd9b0"
            progress_trough = "#efe5cc"
            entry_disabled = "#ede1c7"
            entry_readonly = "#f2e7d0"
            btn_disabled_bg = "#d4c3a3"
            btn_disabled_fg = "#a99a84"

        self.configure(bg=self._bg_primary)
        self.style.configure('TFrame', background=self._bg_primary)
        self.style.configure('TLabel', background=self._bg_primary, foreground=self._text_main)
        self.style.configure('Header.TLabel', background=self._bg_primary, foreground=self._accent, font=("Garamond", 12, 'bold'))
        self.style.configure('TButton', padding=6, background=self._accent, foreground="white", borderwidth=0)
        self.style.map('TButton', background=[('active', self._accent_dark), ('disabled', btn_disabled_bg)], foreground=[('disabled', btn_disabled_fg)])
        self.style.configure('Treeview', background=self._bg_panel, fieldbackground=self._bg_panel, foreground=self._text_main, bordercolor=panel_border)
        self.style.configure('Treeview.Heading', background=heading_bg, foreground=self._accent, font=("Garamond", 11, 'bold'))
        self.style.map('Treeview', background=[('selected', tree_selection)], foreground=[('selected', self._text_main)])
        self.style.configure('Toolbar.TFrame', background=self._bg_primary)
        self.style.configure('Panel.TFrame', background=self._bg_panel)
        self.style.configure('Status.TLabel', background=self._bg_primary, foreground=self._muted, font=("Garamond", 10, 'italic'))
        self.style.configure('TEntry', fieldbackground=self._bg_panel, foreground=self._text_main)
        self.style.map('TEntry', fieldbackground=[('disabled', entry_disabled), ('readonly', entry_readonly)])
        self.style.configure('TSpinbox', fieldbackground=self._bg_panel, foreground=self._text_main)
        self.style.map('TSpinbox', fieldbackground=[('disabled', entry_disabled)])
        self.style.configure('TCheckbutton', background=self._bg_primary, foreground=self._text_main)
        self.style.map('TCheckbutton', foreground=[('disabled', self._muted)])
        self.style.configure('Horizontal.TProgressbar', background=self._accent, troughcolor=progress_trough, bordercolor=panel_border)
        self.style.configure('TPanedwindow', background=self._bg_primary)

        if hasattr(self, 'log_text'):
            self.log_text.configure(
                bg=self._bg_panel,
                fg=self._text_main,
                insertbackground=self._accent,
                highlightbackground=panel_border,
                highlightcolor=panel_border
            )

    def _on_toggle_theme(self):
        hacker_enabled = self._hacker_mode.get()
        self._set_palette(hacker_enabled)
        mode_label = "Hacker" if hacker_enabled else "Classic"
        self._append_log(f"{mode_label} theme {'enabled' if hacker_enabled else 'restored'}.")

    def _create_menu(self):
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="Run scanner.py", command=self.on_run)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def _create_toolbar(self):
        toolbar = ttk.Frame(self, padding=(6, 6, 6, 6), style='Toolbar.TFrame')
        ttk.Label(toolbar, text="Interface:", style='Header.TLabel').pack(side=tk.LEFT, padx=(0, 6))
        self.iface_var = tk.StringVar()
        self.iface_entry = ttk.Entry(toolbar, width=18, textvariable=self.iface_var)
        self.iface_entry.pack(side=tk.LEFT)
        ttk.Button(toolbar, text="Discover", command=self.discover_interfaces).pack(side=tk.LEFT, padx=(6, 4))
        ttk.Button(toolbar, text="Start Monitor", command=self.on_start_monitor).pack(side=tk.LEFT, padx=(4, 4))

        ttk.Button(toolbar, text="Stop Monitor", command=self.on_stop_monitor).pack(side=tk.LEFT, padx=(4, 4))
        ttk.Button(toolbar, text="Scan APs", command=self.on_scan_aps).pack(side=tk.LEFT, padx=(4, 4))
        ttk.Checkbutton(toolbar, text="Dark Theme", variable=self._hacker_mode, command=self._on_toggle_theme).pack(side=tk.LEFT, padx=(12, 6))

        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(toolbar, textvariable=self.status_var, style='Status.TLabel').pack(side=tk.RIGHT)

        self.toolbar = toolbar

    def _create_main_panes(self):
        """Split top horizontally (APs left, Clients right) and place Log spanning full width at the bottom."""
        outer = ttk.Panedwindow(self, orient=tk.VERTICAL)

        # Top horizontal split
        top = ttk.Panedwindow(outer, orient=tk.HORIZONTAL)

        # Left: Access Points and controls
        left = ttk.Frame(top, padding=8)
        ttk.Label(left, text="Access Points", style='Header.TLabel').pack(anchor=tk.W)
        cols = ("bssid", "ssid", "channel")
        ap_wrap = ttk.Frame(left, style='Panel.TFrame')
        self.tree = ttk.Treeview(ap_wrap, columns=cols, show='headings', selectmode='browse')
        ysb_ap = ttk.Scrollbar(ap_wrap, orient='vertical', command=self.tree.yview)
        xsb_ap = ttk.Scrollbar(ap_wrap, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=ysb_ap.set, xscrollcommand=xsb_ap.set)
        self.tree.heading('bssid', text='BSSID')
        self.tree.heading('ssid', text='SSID')
        self.tree.heading('channel', text='Ch')
        self.tree.column('bssid', width=240)
        self.tree.column('ssid', width=420)
        self.tree.column('channel', width=70, anchor=tk.CENTER)
        self.tree.grid(row=0, column=0, sticky='nsew')
        ysb_ap.grid(row=0, column=1, sticky='ns')
        xsb_ap.grid(row=1, column=0, sticky='ew')
        ap_wrap.grid_columnconfigure(0, weight=1)
        ap_wrap.grid_rowconfigure(0, weight=1)
        ap_wrap.pack(fill=tk.BOTH, expand=True, pady=(6, 6))
        self.tree.bind('<<TreeviewSelect>>', self._on_ap_selected)

        # Controls under AP table
        controls = ttk.Frame(left, style='Panel.TFrame')
        ttk.Button(controls, text="Clear", command=self._clear_results).pack(side=tk.LEFT)
        ttk.Button(controls, text="Clear Clients", command=self._clear_clients).pack(side=tk.LEFT, padx=(6,0))
        ttk.Button(controls, text="Export CSV", command=self.export_csv).pack(side=tk.LEFT, padx=(6,6))
        controls.pack(anchor=tk.W, pady=(6,0))

        # Input fields for Rogue AP & attack parameters (no action buttons here)
        action_frame = ttk.Frame(left, style='Panel.TFrame')
        self.upstream_var = tk.StringVar()
        self.timeout_var = tk.IntVar(value=15)
        self.clone_vendor_var = tk.BooleanVar(value=False)
        self.ssid_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        self.show_pass_var = tk.BooleanVar(value=False)

        ttk.Label(action_frame, text="Upstream iface:").pack(side=tk.LEFT, padx=(6,2))
        ttk.Entry(action_frame, width=12, textvariable=self.upstream_var).pack(side=tk.LEFT)
        ttk.Label(action_frame, text="Timeout(s):").pack(side=tk.LEFT, padx=(6,2))
        ttk.Spinbox(action_frame, from_=5, to=300, width=6, textvariable=self.timeout_var).pack(side=tk.LEFT)
        ttk.Checkbutton(action_frame, text='Clone vendor IEs', variable=self.clone_vendor_var).pack(side=tk.LEFT, padx=(8,2))
        ttk.Label(action_frame, text="SSID:").pack(side=tk.LEFT, padx=(8,2))
        ttk.Entry(action_frame, width=16, textvariable=self.ssid_var).pack(side=tk.LEFT)
        ttk.Label(action_frame, text="Pass:").pack(side=tk.LEFT, padx=(6,2))
        self.pass_entry = ttk.Entry(action_frame, width=12, textvariable=self.pass_var, show='*')
        self.pass_entry.pack(side=tk.LEFT)
        ttk.Checkbutton(action_frame, text='Show', variable=self.show_pass_var, command=self._toggle_password).pack(side=tk.LEFT, padx=(4,2))
        action_frame.pack(anchor=tk.W, pady=(6,4))

        # All action buttons grouped below the inputs
        actions_buttons = ttk.Frame(left, style='Panel.TFrame')
        ttk.Button(actions_buttons, text="Start Rogue AP", command=self.on_start_rogue).pack(side=tk.LEFT, padx=(6,2))
        ttk.Button(actions_buttons, text="Stop Rogue AP", command=self.on_stop_rogue).pack(side=tk.LEFT, padx=(6,2))
        ttk.Button(actions_buttons, text="Scan Clients", command=self.on_scan_clients).pack(side=tk.LEFT, padx=(12,2))
        ttk.Button(actions_buttons, text="Deauth Once", command=self.on_deauth_once).pack(side=tk.LEFT, padx=(6,2))
        ttk.Button(actions_buttons, text="Start Deauth", command=self.on_start_deauth).pack(side=tk.LEFT, padx=(6,2))
        ttk.Button(actions_buttons, text="Stop Deauth", command=self.on_stop_deauth).pack(side=tk.LEFT, padx=(6,2))
        actions_buttons.pack(anchor=tk.W, pady=(2,6))
        
        # MITM Attack buttons (separate row for visibility)
        mitm_buttons = ttk.Frame(left, style='Panel.TFrame')
        ttk.Label(mitm_buttons, text="Stealth MITM:", font=("Garamond", 11, 'bold')).pack(side=tk.LEFT, padx=(6,6))
        ttk.Button(mitm_buttons, text="Start MITM Attack", command=self.on_start_mitm).pack(side=tk.LEFT, padx=(6,2))
        ttk.Button(mitm_buttons, text="Stop MITM Attack", command=self.on_stop_mitm).pack(side=tk.LEFT, padx=(6,2))
        ttk.Button(mitm_buttons, text="MITM Stats", command=self.on_mitm_stats).pack(side=tk.LEFT, padx=(6,2))
        mitm_buttons.pack(anchor=tk.W, pady=(2,6))

        # Right: Clients list
        right = ttk.Frame(top, padding=8)
        ttk.Label(right, text="Clients", style='Header.TLabel').pack(anchor=tk.W, pady=(0,6))
        ccols = ("mac",)
        clients_wrap = ttk.Frame(right, style='Panel.TFrame')
        self.clients_tree = ttk.Treeview(clients_wrap, columns=ccols, show='headings', selectmode='none')
        ysb_clients = ttk.Scrollbar(clients_wrap, orient='vertical', command=self.clients_tree.yview)
        xsb_clients = ttk.Scrollbar(clients_wrap, orient='horizontal', command=self.clients_tree.xview)
        self.clients_tree.configure(yscrollcommand=ysb_clients.set, xscrollcommand=xsb_clients.set)
        self.clients_tree.heading('mac', text='Client MAC')
        self.clients_tree.column('mac', width=320)
        self.clients_tree.grid(row=0, column=0, sticky='nsew')
        ysb_clients.grid(row=0, column=1, sticky='ns')
        xsb_clients.grid(row=1, column=0, sticky='ew')
        clients_wrap.grid_columnconfigure(0, weight=1)
        clients_wrap.grid_rowconfigure(0, weight=1)
        clients_wrap.pack(fill=tk.BOTH, expand=True)

        clients_actions = ttk.Frame(right, style='Panel.TFrame')
        ttk.Button(clients_actions, text="Clear Clients", command=self._clear_clients).pack(side=tk.LEFT)
        clients_actions.pack(anchor=tk.W, pady=(6, 0))

        top.add(left, weight=3)
        top.add(right, weight=2)

        # Bottom: Log spanning full width
        bottom = ttk.Frame(outer, padding=8)
        ttk.Label(bottom, text="Log", style='Header.TLabel').pack(anchor=tk.W)
        log_wrap = ttk.Frame(bottom, style='Panel.TFrame')
        self.log_text = tk.Text(
            log_wrap,
            wrap='none',
            height=12,
            bg=self._bg_panel,
            fg=self._text_main,
            insertbackground=self._accent,
            relief='flat',
            highlightthickness=1,
            highlightbackground='#dec79a'
        )
        ysb_log = ttk.Scrollbar(log_wrap, orient='vertical', command=self.log_text.yview)
        xsb_log = ttk.Scrollbar(log_wrap, orient='horizontal', command=self.log_text.xview)
        self.log_text.configure(yscrollcommand=ysb_log.set, xscrollcommand=xsb_log.set)
        self.log_text.grid(row=0, column=0, sticky='nsew')
        ysb_log.grid(row=0, column=1, sticky='ns')
        xsb_log.grid(row=1, column=0, sticky='ew')
        log_wrap.grid_columnconfigure(0, weight=1)
        log_wrap.grid_rowconfigure(0, weight=1)
        log_wrap.pack(fill=tk.BOTH, expand=True, pady=(6,6))
        self.log_text.configure(state='disabled')
        # Progress bar kept for compatibility (start/stop calls) but not packed to hide it
        self.progress = ttk.Progressbar(bottom, mode='indeterminate', style='Horizontal.TProgressbar')

        outer.add(top, weight=3)
        outer.add(bottom, weight=1)
        self.pw = outer

    def _layout(self):
        self.toolbar.pack(fill=tk.X)
        self.pw.pack(fill=tk.BOTH, expand=True)

    def _show_about(self):
        messagebox.showinfo("About", "Rogue AP — Scanner GUI\nA simple Tkinter frontend for scanner.py")

    def _base_iface(self, iface: str) -> str:
        """Return the base interface name by stripping a trailing 'mon' if present."""
        iface = (iface or '').strip()
        return iface[:-3] if iface.endswith('mon') else iface

    def _try_stop_monitor_no_nm(self, mon_iface: str):
        """Try to stop monitor mode without restarting NetworkManager to avoid interfering with hostapd."""
        try:
            if not mon_iface:
                return
            self._append_log(f"Attempting to stop monitor mode on {mon_iface} (no NM restart)...")
            subprocess.run(["sudo", "airmon-ng", "stop", mon_iface], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            self._append_log(f"Non-fatal: failed to stop monitor mode on {mon_iface}: {e}")

    def discover_interfaces(self):
        """Discover network interfaces by parsing `ip link` output (no root required)."""
        try:
            out = subprocess.check_output(["ip", "-o", "link"], stderr=subprocess.DEVNULL, text=True)
            ifaces = []
            for line in out.splitlines():
                # format: '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000'
                parts = line.split(':')
                if len(parts) >= 2:
                    name = parts[1].strip()
                    ifaces.append(name)
            if ifaces:
                # choose a wifi-like iface for scanner (wlan/wl/wlp) and an ethernet-like for upstream (eth/enp/eno)
                nonloop = [i for i in ifaces if i != 'lo']
                candidates = nonloop if nonloop else ifaces
                wifi = None
                eth = None
                for i in candidates:
                    low = i.lower()
                    if low.startswith(('wlan', 'wl', 'wlp')) and wifi is None:
                        wifi = i
                    if low.startswith(('eth', 'enp', 'eno')) and eth is None:
                        eth = i

                # fallback heuristics: prefer an interface that is 'UP' if available
                if wifi is None and candidates:
                    # try to prefer wlan-like but if missing pick first candidate with 'w' in name
                    for i in candidates:
                        if 'w' in i.lower():
                            wifi = i
                            break
                if eth is None and candidates:
                    for i in candidates:
                        if 'e' in i.lower():
                            eth = i
                            break

                # final fallbacks
                if wifi is None:
                    wifi = candidates[0]
                if eth is None:
                    # if only one interface present, set upstream to empty string so user can pick
                    eth = '' if len(candidates) == 1 else (candidates[1] if len(candidates) > 1 else '')

                # populate UI fields
                if wifi:
                    self.iface_var.set(wifi)
                if eth:
                    self.upstream_var.set(eth)

                self._append_log(f"Discovered interfaces: {', '.join(ifaces)} (chosen wifi={wifi}, upstream={eth})")
            else:
                self._append_log("No interfaces discovered.")
        except Exception as e:
            self._append_log(f"Interface discovery failed: {e}")

    def _clear_results(self):
        for iid in list(self.tree.get_children()):
            self.tree.delete(iid)

    def _on_ap_selected(self, event):
        try:
            sel = self.tree.selection()
            if not sel:
                return
            iid = sel[0]
            vals = self.tree.item(iid, 'values')
            if not vals:
                return
            # values expected (bssid, ssid)
            if len(vals) >= 2:
                ssid = vals[1]
            else:
                ssid = vals[0]
            # set SSID field
            self.ssid_var.set(ssid)
            self._append_log(f"AP selected -> SSID field set to: {ssid}")
        except Exception:
            pass

    def _toggle_password(self):
        """Show or hide the password entry based on the checkbox."""
        try:
            if getattr(self, 'show_pass_var', None) and self.show_pass_var.get():
                self.pass_entry.config(show='')
            else:
                self.pass_entry.config(show='*')
        except Exception:
            pass

    def _clear_clients(self):
        for iid in list(self.clients_tree.get_children()):
            self.clients_tree.delete(iid)

    def _get_iface_mac(self, iface: str) -> str:
        """Return the MAC address of an interface or empty string on failure."""
        try:
            p = Path(f"/sys/class/net/{iface}/address")
            if p.exists():
                return p.read_text().strip()
        except Exception:
            pass
        # fallback to ip link parsing
        try:
            out = subprocess.check_output(["ip", "-o", "link", "show", iface], text=True, stderr=subprocess.DEVNULL)
            # format: '3: wlp2s0: <...> ... link/ether 11:22:33:44:55:66 ...'
            for part in out.split():
                if ':' in part and len(part) == 17 and part.count(':') == 5:
                    return part
        except Exception:
            pass
        return ''

    # ------------------ Monitor/scan/rogue AP helpers ------------------
    def on_start_monitor(self):
        iface = self.iface_var.get().strip()
        if not iface:
            messagebox.showinfo('Start Monitor', 'Please set an interface first (e.g., wlan0)')
            return
        if scanner is None:
            messagebox.showerror('Error', 'scanner module not available')
            return
        base = self._base_iface(iface)
        if base != iface:
            self.iface_var.set(base)
        t = threading.Thread(target=self._start_monitor_thread, args=(base,), daemon=True)
        t.start()

    def _start_monitor_thread(self, iface):
        try:
            self._append_log(f'Starting monitor mode on {iface}...')
            scanner.start_monitor_mode(iface)
            self._append_log('Monitor mode started.')
        except Exception as e:
            self._append_log(f'Failed to start monitor mode: {e}')

    def on_stop_monitor(self):
        iface = self.iface_var.get().strip()
        mon = iface + 'mon' if not iface.endswith('mon') else iface
        if scanner is None:
            messagebox.showerror('Error', 'scanner module not available')
            return
        t = threading.Thread(target=self._stop_monitor_thread, args=(mon,), daemon=True)
        t.start()

    def _stop_monitor_thread(self, mon_iface):
        try:
            self._append_log(f'Stopping monitor mode on {mon_iface}...')
            scanner.stop_monitor_mode(mon_iface)
            self._append_log('Monitor mode stopped.')
        except Exception as e:
            self._append_log(f'Failed to stop monitor mode: {e}')

    def on_scan_aps(self):
        if scanner is None:
            messagebox.showerror('Error', 'scanner module not available')
            return
        iface = self.iface_var.get().strip()
        if not iface:
            messagebox.showinfo('Scan', 'Please set an interface first')
            return
        # determine monitor interface name
        mon = iface if iface.endswith('mon') else iface + 'mon'
        timeout = int(self.timeout_var.get() or 15)
        t = threading.Thread(target=self._scan_aps_thread, args=(mon, timeout), daemon=True)
        t.start()

    def _scan_aps_thread(self, mon_iface, timeout):
        try:
            self._append_log(f'Scanning for APs on {mon_iface} for {timeout}s...')
            seen = set()

            def stream_ap(bssid, info):
                if bssid in seen:
                    return
                seen.add(bssid)
                try:
                    if isinstance(info, dict):
                        ssid = info.get('ssid', '')
                        ch = info.get('channel', '')
                        self._aps_info[bssid] = info
                    else:
                        ssid = str(info)
                        ch = ''
                        self._aps_info[bssid] = {'ssid': ssid, 'channel': ch}
                    self._queue.put(('add_ap', (bssid, ssid, ch)))
                except Exception:
                    pass

            aps = scanner.scan_aps(mon_iface, timeout=timeout, on_ap=stream_ap)
            self._append_log(f'Found {len(aps)} AP(s)')
            for bssid, info in aps.items():
                if bssid not in seen:
                    stream_ap(bssid, info)
        except Exception as e:
            self._append_log(f'Scan failed: {e}')

    def on_scan_clients(self):
        """Scan for clients for the selected AP or the running rogue AP."""
        if scanner is None:
            messagebox.showerror('Error', 'scanner module not available')
            return
        # determine BSSID: prefer selected AP
        bssid = self._get_selected_bssid()
        mon_iface = None
        iface = None
        if not bssid:
            # if no selected AP, try to use rogue AP manager iface
            mgr = getattr(self, 'rogue_mgr', None)
            if mgr:
                iface = getattr(mgr, 'iface', None) or self.iface_var.get().strip()
                if iface:
                    # get MAC of iface as BSSID
                    bssid = self._get_iface_mac(iface)
                    # for scanning, use monitor interface (iface + 'mon')
                    mon_iface = iface if iface.endswith('mon') else iface + 'mon'
        else:
            # we have a selected bssid; use monitor iface from UI
            iface = self.iface_var.get().strip()
            mon_iface = iface if iface.endswith('mon') else iface + 'mon'

        if not bssid:
            messagebox.showinfo('Scan Clients', 'No AP selected and no rogue AP detected. Select an AP or start a rogue AP first.')
            return

        timeout = int(self.timeout_var.get() or 20)
        fallback_iface = iface or self.iface_var.get().strip()
        scan_iface = mon_iface or fallback_iface
        t = threading.Thread(target=self._scan_clients_thread, args=(bssid, scan_iface, timeout, True), daemon=True)
        t.start()

    def on_deauth_once(self):
        if scanner is None or not hasattr(scanner, 'send_deauth'):
            messagebox.showerror('Error', 'Deauthentication feature unavailable')
            return
        bssid = self._get_selected_bssid()
        if not bssid:
            messagebox.showinfo('Deauth', 'Select an access point first.')
            return
        iface = self.iface_var.get().strip()
        if not iface:
            messagebox.showinfo('Deauth', 'Set the interface to use for deauth frames (e.g., wlan0mon).')
            return
        t = threading.Thread(target=self._deauth_once_thread, args=(bssid, iface), daemon=True)
        t.start()

    def _get_selected_bssid(self) -> str:
        sel = self.tree.selection()
        if not sel:
            return ''
        iid = sel[0]
        vals = self.tree.item(iid, 'values')
        if not vals:
            return ''
        return vals[0]

    def _scan_clients_thread(self, ap_bssid, mon_iface, timeout, force_local=False):
        try:
            if not mon_iface:
                # default monitor iface derived from UI iface
                iface = self.iface_var.get().strip()
                mon_iface = iface if iface.endswith('mon') else iface + 'mon'
            display_bssid = ap_bssid
            if force_local:
                base = self._base_iface(mon_iface)
                display_bssid = self._get_iface_mac(base) or ap_bssid
            self._append_log(f'Scanning for clients of {display_bssid} on {mon_iface} for {timeout}s...')
            clients = scanner.scan_clients(ap_bssid, interface=mon_iface, timeout=timeout, force_iface_bssid=force_local)
            self._append_log(f'Found {len(clients)} client(s) for {display_bssid}')
            self._queue.put(('clients', list(clients)))
        except Exception as e:
            self._append_log(f'Client scan failed: {e}')

    def _deauth_once_thread(self, ap_bssid, iface):
        try:
            self._append_log(f'Sending single deauth to {ap_bssid} via {iface}...')
            used_iface = scanner.send_deauth(ap_bssid, interface=iface, count=1)
            if used_iface and used_iface != iface:
                self._append_log(f'Deauth frame sent (using {used_iface}).')
            else:
                self._append_log('Deauth frame sent.')
        except Exception as e:
            self._append_log(f'Deauth failed: {e}')

    def on_start_deauth(self):
        """Start continuous deauth against selected AP, targeting all clients."""
        if scanner is None or not hasattr(scanner, 'deauth_all'):
            messagebox.showerror('Error', 'Continuous deauth feature unavailable')
            return
        if self.deauth_thread and self.deauth_thread.is_alive():
            self._append_log('Deauth already running.')
            return
        bssid = self._get_selected_bssid()
        if not bssid:
            messagebox.showinfo('Deauth', 'Select an access point first.')
            return
        iface = self.iface_var.get().strip()
        if not iface:
            messagebox.showinfo('Deauth', 'Set the interface to use (e.g., wlan0 or wlan0mon).')
            return
        info = self._aps_info.get(bssid, {})
        channel = info.get('channel')
        try:
            channel = int(channel) if channel is not None else None
        except Exception:
            channel = None
        self.deauth_stop_event = threading.Event()
        t = threading.Thread(target=self._run_deauth_thread, args=(bssid, iface, channel), daemon=True)
        self.deauth_thread = t
        t.start()

    def _run_deauth_thread(self, bssid, iface, channel):
        try:
            self._append_log(f'Starting continuous deauth on {bssid} (channel={channel})...')
            scanner.deauth_all(
                bssid,
                interface=iface,
                channel=channel,
                pps=35,
                refresh_interval=18,
                client_scan_timeout=6,
                include_broadcast=True,
                stop_event=self.deauth_stop_event,
                log=self._append_log
            )
        except Exception as e:
            self._append_log(f'Deauth error: {e}')

    def on_stop_deauth(self):
        if not self.deauth_thread or not self.deauth_thread.is_alive():
            self._append_log('No deauth running.')
            return
        try:
            self._append_log('Stopping continuous deauth...')
            if self.deauth_stop_event:
                self.deauth_stop_event.set()
            self.deauth_thread.join(timeout=3)
            self._append_log('Deauth stopped.')
        except Exception as e:
            self._append_log(f'Error stopping deauth: {e}')

    def on_start_rogue(self):
        if start_ap is None:
            messagebox.showerror('Error', 'ap_manager.start_ap not available')
            return
        
        iface = self.iface_var.get().strip()
        ssid = self.ssid_var.get().strip()
        passwd = self.pass_var.get().strip()
        upstream = self.upstream_var.get().strip() or None
        if not iface or not ssid or not passwd:
            messagebox.showinfo('Start Rogue AP', 'Please set interface, SSID and passphrase')
            return
        if len(passwd) < 8 or len(passwd) > 63:
            messagebox.showinfo('Start Rogue AP', 'Passphrase must be 8..63 characters for WPA2-PSK')
            return
        # If user selected a monitor interface, strip to base and try to stop monitor mode
        base = self._base_iface(iface)
        if iface != base:
            self._try_stop_monitor_no_nm(iface)
            iface = base
            self.iface_var.set(base)
        t = threading.Thread(target=self._start_rogue_thread, args=(iface, ssid, passwd, upstream), daemon=True)
        t.start()

    def _start_rogue_thread(self, iface, ssid, passwd, upstream):
        try:
            self._append_log(f'Starting rogue AP {ssid} on {iface} (upstream={upstream})')
            selected_bssid = self._get_selected_bssid()
            ies_hex = None
            beacon_int = None
            channel = None
            # print (f"Selected BSSID for rogue AP: {selected_bssid}")
            if selected_bssid:
                info = self._aps_info.get(selected_bssid, {})
                if not ssid:
                    ssid = info.get('ssid', ssid)
                # Only clone vendor IEs if user opted-in
                ies_hex = info.get('ies_hex') if self.clone_vendor_var.get() else None
                beacon_int = info.get('beacon_int')
                channel = info.get('channel')
            bssid_override = self._get_iface_mac(iface)
            if bssid_override:
                self._append_log(f'Using local interface BSSID {bssid_override} for rogue AP broadcast.')
            mgr = start_ap(
                iface,
                ssid,
                passwd,
                upstream_iface=upstream,
                channel=channel if channel else 6,
                beacon_ies=ies_hex,
                beacon_int=beacon_int,
                bssid=bssid_override or None,
            )
            # Show where configs and logs are stored for troubleshooting
            try:
                tmpdir = getattr(mgr, '_tmpdir', None)
                if tmpdir:
                    self._append_log(f'Rogue AP started. Configs/logs: {tmpdir}')
                else:
                    self._append_log('Rogue AP started. Use Stop Rogue AP to terminate.')
            except Exception:
                self._append_log('Rogue AP started. Use Stop Rogue AP to terminate.')
            self.rogue_mgr = mgr
        except Exception as e:
            self._append_log(f'Failed to start rogue AP: {e}')

    def on_stop_rogue(self):
        mgr = getattr(self, 'rogue_mgr', None)
        if not mgr:
            self._append_log('No rogue AP running.')
            return
        t = threading.Thread(target=self._stop_rogue_thread, args=(mgr,), daemon=True)
        t.start()

    def _stop_rogue_thread(self, mgr):
        try:
            self._append_log('Stopping rogue AP...')
            mgr.stop()
            self._append_log('Rogue AP stopped.')
            self.rogue_mgr = None
        except Exception as e:
            self._append_log(f'Error stopping rogue AP: {e}')

    def on_run(self):
        if self._proc and self._proc.poll() is None:
            self._append_log("Scanner already running")
            return
        if not SCANNER_PATH.exists():
            messagebox.showerror("Error", f"scanner.py not found at {SCANNER_PATH}")
            return

        cmd = [sys.executable, str(SCANNER_PATH)]
        # optionally pass interface as env var or argument
        iface = self.iface_var.get().strip()
        if iface:
            # we append as an argument so the script's existing CLI prompts may still work
            cmd.append(iface)

        self._append_log(f"Starting scanner: {' '.join(cmd)}")
        self.status_var.set("Running")
        self.progress.start(10)

        # Start subprocess
        try:
            self._proc = subprocess.Popen(cmd, cwd=str(APP_DIR), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        except Exception as e:
            self._append_log(f"Failed to start scanner: {e}")
            self.status_var.set("Idle")
            self.progress.stop()
            return

        # start a thread to read output without blocking
        self._reader_thread = threading.Thread(target=self._read_process_output, daemon=True)
        self._reader_thread.start()

    def on_stop(self):
        if not self._proc or self._proc.poll() is not None:
            self._append_log("No scanner process running.")
            return
        self._append_log("Stopping scanner process...")
        try:
            self._proc.terminate()
        except Exception:
            pass

    def _read_process_output(self):
        assert self._proc is not None
        for line in self._proc.stdout:
            if not line:
                continue
            # send to GUI thread via queue
            self._queue.put(('line', line.rstrip('\n')))
        # Wait for process to exit
        rc = self._proc.wait()
        self._queue.put(('finished', rc))

    def _process_queue(self):
        try:
            while True:
                item = self._queue.get_nowait()
                kind = item[0]
                if kind == 'line':
                    self._handle_output_line(item[1])
                elif kind == 'add_ap':
                    vals = item[1]
                    if len(vals) == 3:
                        bssid, ssid, ch = vals
                    else:
                        bssid, ssid = vals
                        ch = ''
                    # avoid duplicates
                    existing = self.tree.get_children()
                    if not any(self.tree.set(e, 'bssid') == bssid for e in existing):
                        self.tree.insert('', tk.END, values=(bssid, ssid, ch))
                elif kind == 'clients':
                    clients = item[1]
                    # replace clients list
                    try:
                        for iid in list(self.clients_tree.get_children()):
                            self.clients_tree.delete(iid)
                        for mac in clients:
                            self.clients_tree.insert('', tk.END, values=(mac,))
                    except Exception:
                        pass
                elif kind == 'finished':
                    rc = item[1]
                    self._append_log(f"Scanner exited with code {rc}")
                    self.status_var.set("Idle")
                    self.progress.stop()
                    self._proc = None
        except queue.Empty:
            pass
        finally:
            self.after(100, self._process_queue)

    def _handle_output_line(self, line: str):
        # Display in log
        self._append_log(line)
        # Parse BSSID lines like: "BSSID: <bssid>, SSID: <ssid>" or "BSSID: <bssid>, SSID: <ssid>"
        line = line.strip()
        if line.startswith("BSSID:") or ("BSSID:" in line and "SSID:" in line):
            # crude parsing
            try:
                # Example: BSSID: 11:22:33:44:55:66, SSID: MyNetwork
                parts = [p.strip() for p in line.split(',')]
                bssid = ''
                ssid = ''
                for p in parts:
                    if p.startswith('BSSID:'):
                        bssid = p.split('BSSID:')[1].strip()
                    elif p.startswith('SSID:'):
                        ssid = p.split('SSID:')[1].strip()
                if bssid:
                    # avoid duplicates
                    existing = self.tree.get_children()
                    if not any(self.tree.set(e, 'bssid') == bssid for e in existing):
                        self.tree.insert('', tk.END, values=(bssid, ssid))
            except Exception:
                pass

    def _append_log(self, msg: str):
        t = time.strftime('%H:%M:%S') + ' - ' + msg + '\n'
        self.log_text.configure(state='normal')
        self.log_text.insert('end', t)
        self.log_text.see('end')
        self.log_text.configure(state='disabled')

    def export_csv(self):
        items = []
        for iid in self.tree.get_children():
            vals = self.tree.item(iid, 'values')
            if len(vals) == 3:
                bssid, ssid, ch = vals
            else:
                bssid, ssid = vals
                ch = ''
            items.append((bssid, ssid, ch))
        if not items:
            messagebox.showinfo('Export', 'No results to export')
            return
        path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV files','*.csv')])
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write('BSSID,SSID,Channel\n')
                for b, s, c in items:
                    f.write(f'"{b}","{s}","{c}"\n')
            messagebox.showinfo('Export', f'Exported {len(items)} rows to {path}')
        except Exception as e:
            messagebox.showerror('Export failed', str(e))
    
    # ------------------ MITM Attack Methods ------------------
    def on_start_mitm(self):
        """Start a stealth MITM attack against the selected AP."""
        if MITMAttack is None:
            messagebox.showerror('Error', 'MITM attack module not available')
            return
        
        # Check if already running
        if self.mitm_attack and self.mitm_attack.running:
            messagebox.showinfo('MITM Attack', 'MITM attack already running. Stop it first.')
            return
        
        # Get selected AP
        bssid = self._get_selected_bssid()
        if not bssid:
            messagebox.showinfo('MITM Attack', 'Select a target access point first.')
            return
        
        # Get AP info
        info = self._aps_info.get(bssid, {})
        ssid = info.get('ssid', '')
        channel = info.get('channel')
        vendor_ies = info.get('ies_hex') if self.clone_vendor_var.get() else None
        beacon_int = info.get('beacon_int')
        
        if not ssid:
            messagebox.showinfo('MITM Attack', 'Selected AP has no SSID. Scan APs first.')
            return
        
        if not channel:
            messagebox.showwarning('MITM Attack', 'Channel not detected. Using default channel 6.')
            channel = 6
        
        # Get interface and other parameters
        iface = self.iface_var.get().strip()
        if not iface:
            messagebox.showinfo('MITM Attack', 'Set the interface first (e.g., wlan0)')
            return
        
        # Use base interface (not monitor)
        base = self._base_iface(iface)
        
        # Get password
        passwd = self.pass_var.get().strip()
        if not passwd:
            messagebox.showinfo('MITM Attack', 'Set a WPA password for the rogue AP.')
            return
        
        # Get upstream interface
        upstream = self.upstream_var.get().strip() or None
        
        # Start MITM in thread
        t = threading.Thread(
            target=self._start_mitm_thread,
            args=(base, bssid, ssid, channel, passwd, upstream, vendor_ies, beacon_int),
            daemon=True
        )
        t.start()
    
    def _start_mitm_thread(self, iface, bssid, ssid, channel, password, upstream, vendor_ies, beacon_int):
        """Thread worker to start MITM attack."""
        try:
            self._append_log(f'Starting stealth MITM attack against {ssid} ({bssid})...')
            self._append_log(f'Target channel: {channel}, Cloning vendor IEs: {bool(vendor_ies)}')
            
            self.mitm_attack = MITMAttack(
                interface=iface,
                target_bssid=bssid,
                target_ssid=ssid,
                target_channel=channel,
                password=password,
                upstream_iface=upstream,
                vendor_ies=vendor_ies,
                beacon_interval=beacon_int,
                log_callback=self._append_log
            )
            
            if self.mitm_attack.start():
                self._append_log('✓ MITM attack started successfully!')
                self._append_log('Attack is stealthy: not sending beacons, only responding to probes')
            else:
                self._append_log('✗ Failed to start MITM attack')
                self.mitm_attack = None
        except Exception as e:
            self._append_log(f'Error starting MITM attack: {e}')
            self.mitm_attack = None
    
    def on_stop_mitm(self):
        """Stop the running MITM attack."""
        if not self.mitm_attack:
            self._append_log('No MITM attack running.')
            return
        
        t = threading.Thread(target=self._stop_mitm_thread, daemon=True)
        t.start()
    
    def _stop_mitm_thread(self):
        """Thread worker to stop MITM attack."""
        try:
            self._append_log('Stopping MITM attack...')
            self.mitm_attack.stop()
            self._append_log('MITM attack stopped.')
            self.mitm_attack = None
        except Exception as e:
            self._append_log(f'Error stopping MITM attack: {e}')
    
    def on_mitm_stats(self):
        """Display MITM attack statistics."""
        if not self.mitm_attack:
            messagebox.showinfo('MITM Stats', 'No MITM attack running.')
            return
        
        try:
            stats = self.mitm_attack.get_stats()
            msg = f"""MITM Attack Statistics:

Target SSID: {stats['target_ssid']}
Target BSSID: {stats['target_bssid']}
Target Channel: {stats['target_channel']}

Status: {'Running' if stats['running'] else 'Stopped'}
Probes Received: {stats['probes_received']}
Responses Sent: {stats['responses_sent']}

Attack Mode: Stealth (no beacons, probe responses only)
"""
            messagebox.showinfo('MITM Attack Statistics', msg)
        except Exception as e:
            messagebox.showerror('Error', f'Failed to get stats: {e}')


def main():
    app = GuiApp()
    app.mainloop()

if __name__ == '__main__':
    main()
