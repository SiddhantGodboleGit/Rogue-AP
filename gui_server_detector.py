#!/usr/bin/env python3
"""
GUI for the server-side/local detector with integrated detection engine

Features:
- Interface selector + Discover
- Start / Stop monitor mode (via `scanner` helpers)
- Live packet capture with integrated detection scoring
- Whitelist SSID/BSSID input with save/load
- Suspicious APs panel with color-coded severity and reasons
- AP table populated from local SQLite DB showing score and metadata
- Live logging console

Run with: sudo python3 gui_server_detector.py
"""
from pathlib import Path
import sys
import threading
import subprocess
import queue
import time
import sqlite3
import json
import os
from collections import defaultdict, deque
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

try:
    import scanner
except Exception:
    scanner = None

try:
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, RadioTap
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "ap_local.db"
WHITELIST_FILE = APP_DIR / "whitelist.json"
ALERT_THRESHOLD = 50
RSSI_JUMP_DB = 15
RSSI_JUMP_WINDOW = 5


# Utility functions from server_detector.py
def now_ts():
    return int(time.time())

def iso_ts(ts=None):
    return datetime.utcfromtimestamp(ts or time.time()).isoformat() + "Z"

def normalize_ssid(ssid_raw):
    try:
        s = ssid_raw.strip()
        return s.lower()
    except:
        return ssid_raw

def oui_of_mac(mac):
    if not mac:
        return ""
    return mac.replace(":", "").lower()[:6]

def levenshtein(a, b):
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j-1] + 1, prev[j-1] + cost)
        prev = cur
    return prev[-1]


# DB functions
def init_db(conn):
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS ap_docs (
        id INTEGER PRIMARY KEY,
        ssid_raw TEXT,
        ssid_norm TEXT,
        bssid TEXT,
        first_seen INTEGER,
        last_seen INTEGER,
        sample_rssi INTEGER,
        channel INTEGER,
        rsn_hashes TEXT,
        ouis TEXT,
        beacon_intervals TEXT,
        seq_last INTEGER,
        beacon_ts_hist TEXT,
        seen_count INTEGER DEFAULT 0,
        last_score INTEGER DEFAULT 0
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY,
        ts INTEGER,
        ssid_raw TEXT,
        ssid_norm TEXT,
        bssid TEXT,
        frame_subtype TEXT,
        rssi INTEGER,
        channel INTEGER,
        seq_num INTEGER,
        beacon_ts INTEGER,
        rsn_hash TEXT,
        vendor_summary TEXT
    )
    """)
    conn.commit()


# Scoring engine
class Scorer:
    def __init__(self, conn, whitelist):
        self.conn = conn
        self.whitelist = whitelist
        self.rssi_hist = defaultdict(lambda: deque())

    def update_rssi_hist(self, key, rssi):
        h = self.rssi_hist[key]
        ts = time.time()
        h.append((ts, rssi))
        while h and (ts - h[0][0]) > RSSI_JUMP_WINDOW:
            h.popleft()

    def compute_score(self, ssid_norm, bssid):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM ap_docs WHERE ssid_norm=? AND bssid=?", (ssid_norm, bssid))
        row = cur.fetchone()
        if not row:
            return 0, []
        cols = [c[0] for c in cur.description]
        doc = dict(zip(cols, row))
        evidence = []
        score = 0

        rsn_hashes = set(filter(None, (doc.get("rsn_hashes") or "").split(",")))
        ouis = set(filter(None, (doc.get("ouis") or "").split(",")))
        beacon_intervals = set(filter(None, (doc.get("beacon_intervals") or "").split(",")))

        # Whitelist check
        for item in self.whitelist.get("known_ssids", []):
            if item.get("ssid","").lower() == ssid_norm:
                allowed_ouis = set(o.lower() for o in item.get("ouis", []))
                if ouis and allowed_ouis and ouis.issubset(allowed_ouis):
                    evidence.append("whitelist_match")
                    score = max(score - 20, 0)
                break

        # Check whitelisted BSSIDs
        whitelist_bssids = set(b.lower() for b in self.whitelist.get("known_bssids", []))
        if bssid.lower() in whitelist_bssids:
            evidence.append("whitelisted_bssid")
            score = max(score - 30, 0)

        # Duplicate-SSID detection
        cur.execute("SELECT DISTINCT bssid, rsn_hashes, ouis FROM ap_docs WHERE ssid_norm=?", (ssid_norm,))
        rows = cur.fetchall()
        bssid_list = [r[0] for r in rows]
        if len(bssid_list) > 1:
            # Check if this SSID is whitelisted
            is_ssid_whitelisted = False
            for item in self.whitelist.get("known_ssids", []):
                if item.get("ssid","").lower() == ssid_norm:
                    is_ssid_whitelisted = True
                    break
            
            # Check if ANY BSSID for this SSID is whitelisted
            whitelist_bssids = set(b.lower() for b in self.whitelist.get("known_bssids", []))
            any_bssid_whitelisted = any(b.lower() in whitelist_bssids for b in bssid_list)
            current_bssid_whitelisted = bssid.lower() in whitelist_bssids
            
            rsn_set = set()
            oui_set = set()
            for r in rows:
                rsn_set.update(filter(None, (r[1] or "").split(",")))
                oui_set.update(filter(None, (r[2] or "").split(",")))
            
            # Case 1: One BSSID is whitelisted, but current BSSID is NOT - BIG PENALTY (likely rogue)
            if any_bssid_whitelisted and not current_bssid_whitelisted:
                score += 60  # Major penalty - impersonating whitelisted network
                evidence.append("duplicate_ssid_impersonating_whitelisted_bssid")
                
                if len(rsn_set) > 1:
                    score += 40
                    evidence.append("rogue_ap_different_security_than_legitimate")
                
                if len(oui_set) > 1:
                    score += 40
                    evidence.append("rogue_ap_different_vendor_than_legitimate")
            
            # Case 2: No BSSIDs whitelisted - lesser penalty (could be legitimate multi-AP setup)
            elif not any_bssid_whitelisted and not is_ssid_whitelisted:
                if len(rsn_set) > 1:
                    score += 25
                    evidence.append("duplicate_ssid_rsn_mismatch_not_whitelisted")
                else:
                    score += 15
                    evidence.append("duplicate_ssid_multiple_bssids_not_whitelisted")
                
                if len(oui_set) > 1:
                    score += 20
                    evidence.append("duplicate_ssid_different_vendors")
            
            # Case 3: Current BSSID is whitelisted - minimal penalty
            elif current_bssid_whitelisted or is_ssid_whitelisted:
                if len(rsn_set) > 1:
                    score += 10
                    evidence.append("duplicate_ssid_rsn_mismatch")
                else:
                    score += 5
                    evidence.append("duplicate_ssid_multiple_bssids")

        # Fingerprint mismatch
        if len(ouis) > 1:
            score += 15
            evidence.append("multiple_ouis_for_bssid")

        if len(rsn_hashes) > 1:
            score += 20
            evidence.append("rsn_hashes_multiple_for_bssid")

        # Beacon interval anomalies
        try:
            intervals = [int(x) for x in beacon_intervals if x]
            if intervals:
                for iv in intervals:
                    if iv < 50 or iv > 200:
                        score += 5
                        evidence.append(f"odd_beacon_interval:{iv}")
                        break
        except Exception:
            pass

        # Beacon timestamp monotonicity
        try:
            hist = json.loads(doc.get("beacon_ts_hist") or "[]")
            if len(hist) >= 3:
                monotonic = all(hist[i] <= hist[i+1] for i in range(len(hist)-1))
                if not monotonic:
                    score += 15
                    evidence.append("beacon_timestamp_nonmonotonic")
        except Exception:
            pass

        # RSSI jump detection
        key = f"{ssid_norm}|{bssid}"
        hist = self.rssi_hist.get(key, [])
        if len(hist) >= 2:
            vals = [v for (_, v) in hist]
            if max(vals) - min(vals) > RSSI_JUMP_DB:
                score += 5
                evidence.append("abrupt_rssi_jump")

        # SSID typo/lookalike
        for item in self.whitelist.get("known_ssids", []):
            known = item.get("ssid", "").lower()
            if known and known != ssid_norm:
                d = levenshtein(known, ssid_norm)
                if d <= 2:
                    score += 10
                    evidence.append(f"ssid_typo_like:{known}:{d}")

        # High-entropy SSID
        nonalnum = sum(1 for c in ssid_norm if not c.isalnum())
        if nonalnum > max(3, len(ssid_norm)//4):
            score += 5
            evidence.append("high_entropy_ssid")

        final = min(100, score)
        return final, evidence


# Packet extraction
def extract_beacon_fields(pkt):
    if not pkt.haslayer(Dot11):
        return None
    dot = pkt[Dot11]
    if pkt.type != 0 or dot.subtype not in (8, 5):
        return None

    bssid = dot.addr3
    seq = None
    rssi = None
    try:
        seq = dot.SC >> 4
    except:
        pass
    try:
        if pkt.haslayer(RadioTap) and hasattr(pkt, "dBm_AntSignal"):
            rssi = int(pkt.dBm_AntSignal)
    except:
        pass

    elt = pkt.getlayer(Dot11Elt)
    ssid_raw = ""
    channel = None
    rsn = ""
    vendor_sum = ""
    beacon_interval = None
    beacon_ts = None

    while elt:
        if elt.ID == 0 and hasattr(elt, 'info'):
            try:
                ssid_raw = elt.info.decode(errors='ignore')
            except:
                ssid_raw = str(elt.info)
        if elt.ID == 3:
            try:
                channel = elt.info[0]
            except:
                pass
        if elt.ID == 48:
            try:
                rsn = elt.info.hex()
            except:
                rsn = ""
        if elt.ID == 221:
            try:
                vendor_sum += "v:" + elt.info[:3].hex() + "|"
            except:
                pass
        elt = elt.payload.getlayer(Dot11Elt)

    if pkt.haslayer(Dot11Beacon):
        try:
            beacon_interval = pkt[Dot11Beacon].beacon_interval
            beacon_ts = int(pkt[Dot11Beacon].timestamp)
        except:
            pass

    ssid_norm = normalize_ssid(ssid_raw or "<hidden>")
    return (ssid_raw, ssid_norm, bssid, channel, rssi, seq, beacon_ts, rsn, vendor_sum, beacon_interval)


class GuiServerDetectorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Rogue AP — Server Detector GUI")
        # match main GUI start size and minimums for consistent UX
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

        # Use same palette and ttk style settings as main GUI for consistent aesthetics
        self._bg_primary = "#f6f1e1"
        self._bg_panel = "#fefaf0"
        self._accent = "#b8893f"
        self._accent_dark = "#9a6c2a"
        self._text_main = "#3f2a14"
        self._muted = "#6c5434"
        self.configure(bg=self._bg_primary)

        try:
            self.style.configure('TFrame', background=self._bg_primary)
            self.style.configure('TLabel', background=self._bg_primary, foreground=self._text_main)
            self.style.configure('Header.TLabel', background=self._bg_primary, foreground=self._accent, font=("Garamond", 12, 'bold'))
            self.style.configure('Toolbar.TFrame', background=self._bg_primary)
            self.style.configure('Panel.TFrame', background=self._bg_panel)
            self.style.configure('Status.TLabel', background=self._bg_primary, foreground=self._muted, font=("Garamond", 10, 'italic'))
            self.style.configure('Treeview', background=self._bg_panel, fieldbackground=self._bg_panel, foreground=self._text_main)
            self.style.map('Treeview', background=[('selected', '#ecd9b0')], foreground=[('selected', self._text_main)])
            self.style.configure('Treeview.Heading', background='#f0e3c7', foreground=self._accent, font=("Garamond", 11, 'bold'))
            self.style.configure('TButton', padding=6, background=self._accent, foreground="white", borderwidth=0)
            self.style.map('TButton', background=[('active', self._accent_dark), ('disabled', '#d4c3a3')], foreground=[('disabled', '#a99a84')])
            self.style.configure('TEntry', fieldbackground=self._bg_panel, foreground=self._text_main)
            self.style.map('TEntry', fieldbackground=[('disabled', '#ede1c7'), ('readonly', '#f2e7d0')])
            self.style.configure('Horizontal.TProgressbar', background=self._accent, troughcolor='#efe5cc', bordercolor='#d4c3a3')
            self.style.configure('TPanedwindow', background=self._bg_primary)
        except Exception:
            pass

        # State
        self._queue = queue.Queue()
        self._sniff_thread = None
        self._channel_hop_thread = None
        self._sniffing = False
        self._db_conn = None
        self._scorer = None
        self._suspicious_aps = {}
        self._channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]  # 2.4 GHz channels

        self._create_toolbar()
        self._create_main_panes()
        self._layout()

        # Initialize DB
        self._init_database()
        self._load_whitelist()

        # Poll queue
        self.after(100, self._process_queue)

    def _init_database(self):
        try:
            self._db_conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
            init_db(self._db_conn)
            self._append_log("Database initialized")
        except Exception as e:
            self._append_log(f"DB init failed: {e}")

    def _load_whitelist(self):
        try:
            if WHITELIST_FILE.exists():
                with open(WHITELIST_FILE, 'r') as f:
                    wl = json.load(f)
                    ssids = wl.get('known_ssids', [])
                    bssids = wl.get('known_bssids', [])
                    if ssids:
                        self.whitelist_ssid_var.set(','.join([s['ssid'] if isinstance(s, dict) else s for s in ssids]))
                    if bssids:
                        self.whitelist_bssid_var.set(','.join(bssids))
                    self._append_log(f"Loaded whitelist from {WHITELIST_FILE}")
            else:
                self._append_log("No whitelist file found, starting with empty whitelist")
        except Exception as e:
            self._append_log(f"Whitelist load failed: {e}")

    def _create_toolbar(self):
        toolbar = ttk.Frame(self, padding=(6,6), style='TFrame')
        ttk.Label(toolbar, text="Interface:", style='Header.TLabel').pack(side=tk.LEFT)
        self.iface_var = tk.StringVar()
        self.iface_entry = ttk.Entry(toolbar, width=16, textvariable=self.iface_var)
        self.iface_entry.pack(side=tk.LEFT, padx=(6,4))
        ttk.Button(toolbar, text="Discover", command=self.discover_interfaces).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="Start Monitor", command=self.on_start_monitor).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="Stop Monitor", command=self.on_stop_monitor).pack(side=tk.LEFT, padx=4)
        ttk.Separator(toolbar, orient='vertical').pack(side=tk.LEFT, fill=tk.Y, padx=8)
        ttk.Button(toolbar, text="Start Detection", command=self.on_start_detection).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="Stop Detection", command=self.on_stop_detection).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="Refresh DB", command=self.refresh_db_now).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="Clear DB", command=self.clear_db).pack(side=tk.LEFT, padx=4)

        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(toolbar, textvariable=self.status_var, style='Status.TLabel').pack(side=tk.RIGHT)
        self.toolbar = toolbar

    def _create_main_panes(self):
        outer = ttk.Panedwindow(self, orient=tk.VERTICAL)

        # Whitelist inputs
        wl_frame = ttk.Frame(outer, padding=6)
        ttk.Label(wl_frame, text="Whitelist SSIDs (comma):").grid(row=0, column=0, sticky='w', padx=(0,6))
        self.whitelist_ssid_var = tk.StringVar(value="")
        ttk.Entry(wl_frame, width=40, textvariable=self.whitelist_ssid_var).grid(row=0, column=1, sticky='ew', padx=(0,12))
        
        ttk.Label(wl_frame, text="Whitelist BSSIDs (comma):").grid(row=0, column=2, sticky='w', padx=(0,6))
        self.whitelist_bssid_var = tk.StringVar(value="")
        ttk.Entry(wl_frame, width=36, textvariable=self.whitelist_bssid_var).grid(row=0, column=3, sticky='ew', padx=(0,12))
        
        ttk.Button(wl_frame, text="Save Whitelist", command=self.save_whitelist).grid(row=0, column=4, padx=4)
        ttk.Button(wl_frame, text="Load Whitelist", command=self.load_whitelist).grid(row=0, column=5, padx=4)
        wl_frame.grid_columnconfigure(1, weight=1)
        wl_frame.grid_columnconfigure(3, weight=1)

        # Main split: APs left, Suspicious right
        top = ttk.Panedwindow(outer, orient=tk.HORIZONTAL)

        # Left: APs table
        left = ttk.Frame(top, padding=8)
        ttk.Label(left, text="Access Points (Database)", style='Header.TLabel').pack(anchor=tk.W)
        wrap = ttk.Frame(left, style='Panel.TFrame')
        cols = ("bssid","ssid","score","last_seen","channel","rssi","count")
        self.tree = ttk.Treeview(wrap, columns=cols, show='headings', height=16)
        self.tree.heading('bssid', text='BSSID')
        self.tree.heading('ssid', text='SSID')
        self.tree.heading('score', text='Score')
        self.tree.heading('last_seen', text='Last Seen')
        self.tree.heading('channel', text='Ch')
        self.tree.heading('rssi', text='RSSI')
        self.tree.heading('count', text='Count')
        self.tree.column('bssid', width=240)
        self.tree.column('ssid', width=320)
        self.tree.column('score', width=80, anchor='center')
        self.tree.column('last_seen', width=160)
        self.tree.column('channel', width=60, anchor='center')
        self.tree.column('rssi', width=70, anchor='center')
        self.tree.column('count', width=70, anchor='center')

        ysb = ttk.Scrollbar(wrap, orient='vertical', command=self.tree.yview)
        xsb = ttk.Scrollbar(wrap, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        ysb.grid(row=0, column=1, sticky='ns')
        xsb.grid(row=1, column=0, sticky='ew')
        wrap.grid_columnconfigure(0, weight=1)
        wrap.grid_rowconfigure(0, weight=1)
        wrap.pack(fill=tk.BOTH, expand=True)

        # Color tags for severity
        try:
            self.tree.tag_configure('low', background='#e8f7e8')
            self.tree.tag_configure('medium', background='#fff7e0')
            self.tree.tag_configure('high', background='#ffe3e3')
        except:
            pass

        # Right: Suspicious APs
        right = ttk.Frame(top, padding=8)
        ttk.Label(right, text="Suspicious APs (Score ≥ 50)", style='Header.TLabel').pack(anchor=tk.W)
        susp_wrap = ttk.Frame(right, style='Panel.TFrame')
        scols = ("bssid","ssid","score")
        self.susp_tree = ttk.Treeview(susp_wrap, columns=scols, show='headings', height=10)
        self.susp_tree.heading('bssid', text='BSSID')
        self.susp_tree.heading('ssid', text='SSID')
        self.susp_tree.heading('score', text='Score')
        self.susp_tree.column('bssid', width=240)
        self.susp_tree.column('ssid', width=280)
        self.susp_tree.column('score', width=80, anchor='center')

        ysb2 = ttk.Scrollbar(susp_wrap, orient='vertical', command=self.susp_tree.yview)
        self.susp_tree.configure(yscrollcommand=ysb2.set)
        self.susp_tree.grid(row=0, column=0, sticky='nsew')
        ysb2.grid(row=0, column=1, sticky='ns')
        susp_wrap.grid_columnconfigure(0, weight=1)
        susp_wrap.grid_rowconfigure(0, weight=1)
        susp_wrap.pack(fill=tk.BOTH, expand=False)
        self.susp_tree.bind('<<TreeviewSelect>>', self._on_susp_selected)

        # Color tags
        try:
            self.susp_tree.tag_configure('low', background='#e8f7e8')
            self.susp_tree.tag_configure('medium', background='#fff7e0')
            self.susp_tree.tag_configure('high', background='#ffe3e3')
        except:
            pass

        # Reasons display
        ttk.Label(right, text="Detection Reasons", style='Header.TLabel').pack(anchor=tk.W, pady=(8,4))
        self.reasons_text = tk.Text(right, height=12, wrap='word', state='disabled', background=self._bg_panel, fg=self._text_main)
        self.reasons_text.pack(fill=tk.BOTH, expand=True)

        top.add(left, weight=3)
        top.add(right, weight=2)

        # Bottom: Log
        bottom = ttk.Frame(outer, padding=8)
        ttk.Label(bottom, text="Log", style='Header.TLabel').pack(anchor=tk.W)
        log_wrap = ttk.Frame(bottom, style='Panel.TFrame')
        self.log_text = tk.Text(log_wrap, height=10, wrap='none', bg=self._bg_panel, fg=self._text_main)
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

        outer.add(wl_frame, weight=0)
        outer.add(top, weight=4)
        outer.add(bottom, weight=1)
        self.pw = outer

    def _layout(self):
        self.toolbar.pack(fill=tk.X)
        self.pw.pack(fill=tk.BOTH, expand=True)

    # Interface / Monitor
    def discover_interfaces(self):
        try:
            out = subprocess.check_output(["ip","-o","link"], text=True, stderr=subprocess.DEVNULL)
            ifaces = []
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) >= 2:
                    ifaces.append(parts[1].strip())
            if ifaces:
                nonloop = [i for i in ifaces if i != 'lo']
                candidates = nonloop if nonloop else ifaces
                wifi = None
                for i in candidates:
                    if i.lower().startswith(('wlan','wl','wlp')):
                        wifi = i
                        break
                if wifi:
                    self.iface_var.set(wifi)
                self._append_log(f"Discovered: {', '.join(ifaces)} (chosen {wifi})")
        except Exception as e:
            self._append_log(f"Interface discovery failed: {e}")

    def _base_iface(self, iface: str) -> str:
        iface = (iface or '').strip()
        return iface[:-3] if iface.endswith('mon') else iface

    def on_start_monitor(self):
        iface = self.iface_var.get().strip()
        if not iface:
            messagebox.showinfo('Start Monitor','Please set an interface first')
            return
        if scanner is None:
            messagebox.showerror('Error','scanner module not available')
            return
        base = self._base_iface(iface)
        if base != iface:
            self.iface_var.set(base)
        t = threading.Thread(target=self._start_monitor_thread, args=(base,), daemon=True)
        t.start()

    def _start_monitor_thread(self, iface):
        try:
            self._append_log(f'Starting monitor mode on {iface}...')
            self.status_var.set('Starting monitor...')
            scanner.start_monitor_mode(iface)
            # Update interface to monitor mode name
            mon_iface = iface + 'mon'
            self.iface_var.set(mon_iface)
            self._append_log(f'Monitor mode started. Interface is now {mon_iface}')
        except Exception as e:
            self._append_log(f'Failed to start monitor mode: {e}')
        finally:
            self.status_var.set('Idle')

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
            self._append_log(f'Stopping monitor mode on {mon_iface}...')
            self.status_var.set('Stopping monitor...')
            scanner.stop_monitor_mode(mon_iface)
            # Update interface back to base name
            base = self._base_iface(mon_iface)
            self.iface_var.set(base)
            self._append_log(f'Monitor mode stopped. Interface is now {base}')
        except Exception as e:
            self._append_log(f'Failed to stop monitor mode: {e}')
        finally:
            self.status_var.set('Idle')

    # Detection
    def on_start_detection(self):
        if self._sniffing:
            self._append_log("Detection already running")
            return
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Error", "Scapy not available. Install with: pip install scapy")
            return
        iface = self.iface_var.get().strip()
        if not iface:
            messagebox.showinfo("Start Detection", "Please set an interface first")
            return
        
        # Build whitelist
        whitelist = self._build_whitelist()
        
        if self._db_conn:
            self._scorer = Scorer(self._db_conn, whitelist)
        
        self._sniffing = True
        self.status_var.set("Detecting...")
        self._append_log(f"Starting live detection on {iface} with channel hopping")
        
        # Start channel hopping thread
        hop_thread = threading.Thread(target=self._channel_hop_func, args=(iface,), daemon=True)
        hop_thread.start()
        self._channel_hop_thread = hop_thread
        
        # Start sniffing thread
        t = threading.Thread(target=self._sniff_thread_func, args=(iface,), daemon=True)
        t.start()
        self._sniff_thread = t

    def on_stop_detection(self):
        if not self._sniffing:
            self._append_log("Detection not running")
            return
        self._sniffing = False
        self.status_var.set("Idle")
        self._append_log("Stopping detection...")

    def _build_whitelist(self):
        ssids_str = self.whitelist_ssid_var.get().strip()
        bssids_str = self.whitelist_bssid_var.get().strip()
        
        ssids = [s.strip() for s in ssids_str.split(',') if s.strip()]
        bssids = [b.strip().lower() for b in bssids_str.split(',') if b.strip()]
        
        known_ssids = [{"ssid": s, "ouis": []} for s in ssids]
        
        return {
            "known_ssids": known_ssids,
            "known_bssids": bssids
        }

    def _channel_hop_func(self, iface):
        """Continuously hop through channels to detect APs on all channels"""
        import time
        channel_idx = 0
        while self._sniffing:
            try:
                channel = self._channels[channel_idx]
                # Use iwconfig to change channel
                subprocess.run(['iwconfig', iface, 'channel', str(channel)], 
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                channel_idx = (channel_idx + 1) % len(self._channels)
                time.sleep(0.5)  # Stay on each channel for 0.5 seconds
            except Exception as e:
                # Silently continue if channel switch fails
                pass

    def _sniff_thread_func(self, iface):
        def handle_pkt(pkt):
            if not self._sniffing:
                return
            try:
                data = extract_beacon_fields(pkt)
                if not data:
                    return
                self._process_beacon(data)
            except Exception as e:
                self._queue.put(('log', f"Packet error: {e}"))
        
        try:
            sniff(iface=iface, prn=handle_pkt, store=0, stop_filter=lambda p: not self._sniffing)
        except Exception as e:
            self._queue.put(('log', f"Sniff error: {e}"))
        finally:
            self._sniffing = False
            self.status_var.set("Idle")

    def _process_beacon(self, data):
        (ssid_raw, ssid_norm, bssid, channel, rssi, seq, beacon_ts, rsn, vendsum, bint) = data
        ts = now_ts()
        
        if not self._db_conn or not self._scorer:
            return
        
        cur = self._db_conn.cursor()
        
        # Insert event
        cur.execute("""
            INSERT INTO events (ts, ssid_raw, ssid_norm, bssid, frame_subtype, rssi, channel, seq_num, beacon_ts, rsn_hash, vendor_summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts, ssid_raw, ssid_norm, bssid, "beacon", rssi, channel, seq, beacon_ts, rsn, vendsum))
        
        # Update ap_docs
        cur.execute("SELECT id, rsn_hashes, ouis, beacon_ts_hist, seen_count FROM ap_docs WHERE ssid_norm=? AND bssid=?", (ssid_norm, bssid))
        row = cur.fetchone()
        oui = oui_of_mac(bssid)
        current_count = 1
        
        if row:
            doc_id, rsn_hashes_s, ouis_s, beacon_ts_hist_s, seen_count = row
            rsn_set = set(filter(None, (rsn_hashes_s or "").split(",")))
            if rsn:
                rsn_set.add(rsn)
            ouis_set = set(filter(None, (ouis_s or "").split(",")))
            ouis_set.add(oui)
            seen_count = (seen_count or 0) + 1
            current_count = seen_count
            
            try:
                hist = json.loads(beacon_ts_hist_s or "[]")
            except:
                hist = []
            if beacon_ts is not None:
                hist.append(beacon_ts)
                hist = hist[-10:]
            
            cur.execute("""
                UPDATE ap_docs SET last_seen=?, sample_rssi=?, channel=?, rsn_hashes=?, ouis=?, beacon_intervals=?, seq_last=?, beacon_ts_hist=?, seen_count=?
                WHERE id=?
            """, (ts, rssi or None, channel, ",".join(filter(None, rsn_set)), ",".join(filter(None, ouis_set)), 
                  ",".join(filter(None, map(str, filter(None,[bint])))), seq or None, json.dumps(hist), seen_count, doc_id))
        else:
            rsn_val = rsn or ""
            ouis_val = oui or ""
            hist = [beacon_ts] if beacon_ts is not None else []
            cur.execute("""
                INSERT INTO ap_docs (ssid_raw, ssid_norm, bssid, first_seen, last_seen, sample_rssi, channel, rsn_hashes, ouis, beacon_intervals, seq_last, beacon_ts_hist, seen_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (ssid_raw, ssid_norm, bssid, ts, ts, rssi or None, channel, rsn_val, ouis_val, 
                  str(bint) if bint else "", seq or None, json.dumps(hist), 1))
        
        self._db_conn.commit()
        
        # Score
        key = f"{ssid_norm}|{bssid}"
        self._scorer.update_rssi_hist(key, rssi or 0)
        score, evidence = self._scorer.compute_score(ssid_norm, bssid)
        
        # Update score in DB
        cur.execute("UPDATE ap_docs SET last_score=? WHERE ssid_norm=? AND bssid=?", (score, ssid_norm, bssid))
        self._db_conn.commit()
        
        # Alert if threshold met
        if score >= ALERT_THRESHOLD:
            self._suspicious_aps[bssid] = {
                'ssid': ssid_raw,
                'score': score,
                'evidence': evidence
            }
            self._queue.put(('alert', (bssid, ssid_raw, score, evidence)))
        
        # Queue immediate AP update to UI
        self._queue.put(('ap_update', (bssid, ssid_raw, score, ts, channel, rssi, current_count)))

    # DB Refresh
    def refresh_db_now(self):
        t = threading.Thread(target=self._refresh_db_thread, daemon=True)
        t.start()

    def _refresh_db_thread(self):
        try:
            if not DB_PATH.exists():
                self._append_log(f'DB not found at {DB_PATH}')
                return
            conn = sqlite3.connect(str(DB_PATH))
            cur = conn.cursor()
            cur.execute('SELECT bssid, ssid_raw, last_score, last_seen, channel, sample_rssi, seen_count FROM ap_docs ORDER BY last_score DESC')
            rows = cur.fetchall()
            conn.close()
            self._queue.put(('db_rows', rows))
        except Exception as e:
            self._queue.put(('log', f'Refresh DB failed: {e}'))

    # DB Clear
    def clear_db(self):
        if self._sniffing:
            messagebox.showwarning("Clear DB", "Please stop detection before clearing the database")
            return
        
        result = messagebox.askyesno("Clear Database", 
                                     "Are you sure you want to clear all AP data from the database?\n\nThis action cannot be undone.")
        if not result:
            return
        
        t = threading.Thread(target=self._clear_db_thread, daemon=True)
        t.start()

    def _clear_db_thread(self):
        try:
            if self._db_conn:
                cur = self._db_conn.cursor()
                cur.execute('DELETE FROM ap_docs')
                cur.execute('DELETE FROM events')
                self._db_conn.commit()
                self._queue.put(('log', 'Database cleared successfully'))
                
                # Clear UI
                self._queue.put(('clear_ui', None))
                
                # Clear suspicious APs
                self._suspicious_aps.clear()
            else:
                self._queue.put(('log', 'Database connection not available'))
        except Exception as e:
            self._queue.put(('log', f'Clear DB failed: {e}'))

    # Suspicious AP selection
    def _on_susp_selected(self, event):
        try:
            sel = self.susp_tree.selection()
            if not sel:
                return
            iid = sel[0]
            vals = self.susp_tree.item(iid, 'values')
            bssid = vals[0]
            
            if bssid in self._suspicious_aps:
                info = self._suspicious_aps[bssid]
                self._show_reasons(info['evidence'])
        except Exception:
            pass

    def _show_reasons(self, evidence):
        self.reasons_text.configure(state='normal')
        self.reasons_text.delete(1.0, 'end')
        if not evidence:
            self.reasons_text.insert('end', "No specific reasons detected.\n")
        else:
            for reason in evidence:
                self.reasons_text.insert('end', f"• {reason}\n")
        self.reasons_text.configure(state='disabled')

    # Whitelist save/load
    def save_whitelist(self):
        ssids = [s.strip() for s in self.whitelist_ssid_var.get().split(',') if s.strip()]
        bssids = [b.strip() for b in self.whitelist_bssid_var.get().split(',') if b.strip()]
        
        data = {
            "known_ssids": [{"ssid": s, "ouis": []} for s in ssids],
            "known_bssids": bssids
        }
        
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files","*.json")], initialfile="whitelist.json")
        if not path:
            return
        try:
            with open(path, 'w') as f:
                json.dump(data, f, indent=2)
            self._append_log(f"Saved whitelist to {path}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def load_whitelist(self):
        path = filedialog.askopenfilename(filetypes=[("JSON files","*.json")])
        if not path:
            return
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            ssids = []
            for item in data.get('known_ssids', []):
                if isinstance(item, dict):
                    ssids.append(item.get('ssid', ''))
                else:
                    ssids.append(str(item))
            bssids = data.get('known_bssids', [])
            
            self.whitelist_ssid_var.set(','.join(ssids))
            self.whitelist_bssid_var.set(','.join(bssids))
            self._append_log(f"Loaded whitelist from {path}")
        except Exception as e:
            messagebox.showerror("Load failed", str(e))

    # Queue processing
    def _process_queue(self):
        try:
            refresh_needed = False
            while True:
                item = self._queue.get_nowait()
                kind = item[0]
                
                if kind == 'log':
                    self._append_log(item[1])
                elif kind == 'db_rows':
                    rows = item[1]
                    for iid in list(self.tree.get_children()):
                        self.tree.delete(iid)
                    for r in rows:
                        bssid, ssid_raw, last_score, last_seen, channel, sample_rssi, seen_count = r
                        last_seen_fmt = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(last_seen)) if last_seen else ''
                        
                        # Severity tag
                        tag = ''
                        if last_score >= 70:
                            tag = 'high'
                        elif last_score >= 40:
                            tag = 'medium'
                        elif last_score > 0:
                            tag = 'low'
                        
                        self.tree.insert('', tk.END, values=(bssid or '', ssid_raw or '', last_score or 0, 
                                                             last_seen_fmt, channel or '', sample_rssi or '', seen_count or 0),
                                        tags=(tag,))
                elif kind == 'alert':
                    bssid, ssid, score, evidence = item[1]
                    self._append_log(f"ALERT: {ssid} ({bssid}) - Score: {score}")
                    
                    # Update suspicious tree
                    found = False
                    for iid in self.susp_tree.get_children():
                        if self.susp_tree.item(iid, 'values')[0] == bssid:
                            found = True
                            break
                    
                    tag = ''
                    if score >= 70:
                        tag = 'high'
                    elif score >= 50:
                        tag = 'medium'
                    else:
                        tag = 'low'
                    
                    if not found:
                        self.susp_tree.insert('', tk.END, values=(bssid, ssid, score), tags=(tag,))
                elif kind == 'clear_ui':
                    # Clear all UI elements
                    for iid in list(self.tree.get_children()):
                        self.tree.delete(iid)
                    for iid in list(self.susp_tree.get_children()):
                        self.susp_tree.delete(iid)
                    self.reasons_text.configure(state='normal')
                    self.reasons_text.delete(1.0, 'end')
                    self.reasons_text.configure(state='disabled')
                elif kind == 'ap_update':
                    bssid, ssid, score, last_seen, channel, rssi, count = item[1]
                    last_seen_fmt = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(last_seen)) if last_seen else ''
                    
                    # Severity tag
                    tag = ''
                    if score >= 70:
                        tag = 'high'
                    elif score >= 40:
                        tag = 'medium'
                    elif score > 0:
                        tag = 'low'
                    
                    # Update existing or insert new
                    found = False
                    for iid in self.tree.get_children():
                        if self.tree.item(iid, 'values')[0] == bssid:
                            self.tree.item(iid, values=(bssid, ssid, score, last_seen_fmt, channel or '', rssi or '', count))
                            self.tree.item(iid, tags=(tag,))
                            found = True
                            break
                    
                    if not found:
                        self.tree.insert('', tk.END, values=(bssid, ssid, score, last_seen_fmt, channel or '', rssi or '', count), tags=(tag,))
        except queue.Empty:
            pass
        finally:
            self.after(100, self._process_queue)
            
            # Periodic full refresh when detecting (less frequent now since we have real-time updates)
            if hasattr(self, '_last_refresh'):
                if time.time() - self._last_refresh > 10 and self._sniffing:
                    self.refresh_db_now()
                    self._last_refresh = time.time()
            else:
                self._last_refresh = time.time()

    def _append_log(self, msg: str):
        t = time.strftime('%H:%M:%S') + ' - ' + msg + '\n'
        try:
            self.log_text.configure(state='normal')
            self.log_text.insert('end', t)
            self.log_text.see('end')
            self.log_text.configure(state='disabled')
        except Exception:
            pass


def main():
    app = GuiServerDetectorApp()
    app.mainloop()


if __name__ == '__main__':
    main()
