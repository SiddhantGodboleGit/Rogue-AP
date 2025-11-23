#!/usr/bin/env python3
"""
evil_twin_local_detector.py
Standalone sensor + local aggregator + rule-based scoring.
Run with root and monitor-mode interface.

Usage:
  sudo python3 evil_twin_local_detector.py --iface wlan0mon
"""

import argparse
import os
import time
import json
import sqlite3
import threading
import subprocess
from collections import defaultdict, deque
from datetime import datetime
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, RadioTap

DB_PATH = "ap_local.db"
ALERT_DIR = "alerts"
PCAP_DIR = "pcaps"
WHITELIST_FILE = "whitelist.json"
ALERT_THRESHOLD = 50
PCAP_ON_ALERT = True
PCAP_SECONDS = 12  # capture length when alerting
RSSI_JUMP_DB = 15  # dB jump threshold
RSSI_JUMP_WINDOW = 5  # seconds

# Utility functions ---------------------------------------------------------

def ensure_dirs():
    os.makedirs(ALERT_DIR, exist_ok=True)
    os.makedirs(PCAP_DIR, exist_ok=True)

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

def short_rsn_hash(pkt):
    """Return a short fingerprint of RSN/vendor IEs from Dot11Elt chain"""
    if not pkt.haslayer(Dot11Elt):
        return ""
    cur = pkt.getlayer(Dot11Elt)
    parts = []
    seen_ids = set()
    while cur:
        try:
            if cur.ID == 48:  # RSN
                parts.append("rsn:" + cur.info.hex())
            elif cur.ID == 221:  # vendor-specific
                parts.append("vend:" + cur.info[:3].hex())
            elif cur.ID == 7:  # country
                parts.append("ctry:" + (cur.info[:2].decode(errors='ignore')))
            seen_ids.add(cur.ID)
        except Exception:
            pass
        cur = cur.payload.getlayer(Dot11Elt)
    return "|".join(parts)

# Pure-Python Levenshtein (small & acceptable) --------------------------------
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

# DB functions ----------------------------------------------------------------
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

# Whitelist load -------------------------------------------------------------
def load_whitelist():
    if not os.path.exists(WHITELIST_FILE):
        return {"known_ssids": []}
    with open(WHITELIST_FILE, "r") as f:
        return json.load(f)

# Simple OUI extract
def oui_of_mac(mac):
    if not mac:
        return ""
    return mac.replace(":", "").lower()[:6]

# Forensics PCAP capture (uses tcpdump) --------------------------------------
def capture_pcap(iface, outpath, duration=10):
    # This uses tcpdump and requires root
    try:
        cmd = ["timeout", str(duration), "tcpdump", "-i", iface, "-w", outpath]
        subprocess.Popen(cmd)
        return True
    except Exception as e:
        print("pcap capture failed:", e)
        return False

# Scoring engine --------------------------------------------------------------
class Scorer:
    def __init__(self, conn, whitelist):
        self.conn = conn
        self.whitelist = whitelist
        # keep small in-memory sliding RSSI history per (ssid,bssid)
        self.rssi_hist = defaultdict(lambda: deque())

    def update_rssi_hist(self, key, rssi):
        h = self.rssi_hist[key]
        ts = time.time()
        h.append((ts, rssi))
        # prune older than window
        while h and (ts - h[0][0]) > RSSI_JUMP_WINDOW:
            h.popleft()

    def compute_score(self, ssid_norm, bssid):
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM ap_docs WHERE ssid_norm=? AND bssid=?", (ssid_norm, bssid))
        row = cur.fetchone()
        if not row:
            return 0, []
        # map columns
        cols = [c[0] for c in cur.description]
        doc = dict(zip(cols, row))
        evidence = []
        score = 0

        # parse sets stored as comma lists
        rsn_hashes = set(filter(None, (doc.get("rsn_hashes") or "").split(",")))
        ouis = set(filter(None, (doc.get("ouis") or "").split(",")))
        beacon_intervals = set(filter(None, (doc.get("beacon_intervals") or "").split(",")))

        # WHITELIST: if exact match present, lower confidence
        for item in self.whitelist.get("known_ssids", []):
            if item.get("ssid","").lower() == ssid_norm:
                # check OUI allowance
                allowed_ouis = set(o.lower() for o in item.get("ouis", []))
                if ouis and allowed_ouis and ouis.issubset(allowed_ouis):
                    evidence.append("whitelist_match")
                    score = max(score - 20, 0)
                break

        # Duplicate-SSID detection: multiple BSSIDs for same SSID
        cur.execute("SELECT DISTINCT bssid, rsn_hashes, ouis FROM ap_docs WHERE ssid_norm=?", (ssid_norm,))
        rows = cur.fetchall()
        bssid_list = [r[0] for r in rows]
        if len(bssid_list) > 1:
            # check RSN mismatch across the SSID
            rsn_set = set()
            oui_set = set()
            for r in rows:
                rsn_set.update(filter(None, (r[1] or "").split(",")))
                oui_set.update(filter(None, (r[2] or "").split(",")))
            if len(rsn_set) > 1:
                score += 30
                evidence.append("duplicate_ssid_rsn_mismatch")
            else:
                score += 5
                evidence.append("duplicate_ssid_multiple_bssids")

        # Fingerprint mismatch: multiple OUIs across BSSIDs -> suspicious
        if len(ouis) > 1:
            score += 15
            evidence.append("multiple_ouis_for_bssid")

        if len(rsn_hashes) > 1:
            score += 20
            evidence.append("rsn_hashes_multiple_for_bssid")

        # Management frame anomalies: beacon interval odd
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

        # sequence / timing inconsistencies
        # check beacon timestamp history parsed from doc['beacon_ts_hist'] which we store as JSON list
        try:
            hist = json.loads(doc.get("beacon_ts_hist") or "[]")
            if len(hist) >= 3:
                # check monotonicity
                monotonic = all(hist[i] <= hist[i+1] for i in range(len(hist)-1))
                if not monotonic:
                    score += 15
                    evidence.append("beacon_timestamp_nonmonotonic")
        except Exception:
            pass

        # RSSI abrupt jump detection using in-memory history
        key = f"{ssid_norm}|{bssid}"
        hist = self.rssi_hist.get(key, [])
        if len(hist) >= 2:
            vals = [v for (_, v) in hist]
            if max(vals) - min(vals) > RSSI_JUMP_DB:
                score += 5
                evidence.append("abrupt_rssi_jump")

        # SSID look-alike: compare to whitelist SSIDs
        for item in self.whitelist.get("known_ssids", []):
            known = item.get("ssid", "").lower()
            if known and known != ssid_norm:
                d = levenshtein(known, ssid_norm)
                if d <= 2:
                    score += 10
                    evidence.append(f"ssid_typo_like:{known}:{d}")
                # quick homoglyph-ish detection: same length but different visually similar chars
        # random-entropy check: detect if ssid has many non-alphanumeric characters
        nonalnum = sum(1 for c in ssid_norm if not c.isalnum())
        if nonalnum > max(3, len(ssid_norm)//4):
            score += 5
            evidence.append("high_entropy_ssid")

        final = min(100, score)
        return final, evidence

# Packet handling & main loop ------------------------------------------------
def extract_beacon_fields(pkt):
    """Return extracted tuple: (ssid_raw, ssid_norm, bssid, channel, rssi, seq, beacon_ts, rsn_hash, vendor_summary, beacon_interval)"""
    ssid_raw = ""
    ssid_norm = ""
    bssid = None
    channel = None
    rssi = None
    seq = None
    beacon_ts = None
    rsn = ""
    vendor_sum = ""
    beacon_interval = None

    if not pkt.haslayer(Dot11):
        return None
    dot = pkt[Dot11]
    subtype = dot.subtype
    if pkt.type != 0 or subtype not in (8,5):  # beacon or probe-resp
        return None

    bssid = dot.addr3
    # sequence number
    try:
        seq = dot.SC >> 4
    except:
        seq = None
    # radiotap rssi
    try:
        if pkt.haslayer(RadioTap) and hasattr(pkt, "dBm_AntSignal"):
            rssi = int(pkt.dBm_AntSignal)
    except Exception:
        pass

    # IEs
    elt = pkt.getlayer(Dot11Elt)
    ssid_raw = ""
    vendor_sum = ""
    while elt:
        if elt.ID == 0 and hasattr(elt, 'info'):  # SSID
            try:
                ssid_raw = elt.info.decode(errors='ignore')
            except:
                ssid_raw = str(elt.info)
        if elt.ID == 3:  # DS Params - channel
            try:
                channel = elt.info[0]
            except:
                pass
        if elt.ID == 1:  # supported rates (skip)
            pass
        if elt.ID == 5:  # TIM
            pass
        if elt.ID == 48:  # RSN
            try:
                rsn = elt.info.hex()
            except:
                rsn = ""
        if elt.ID == 221:
            # vendor OUI first 3 bytes
            try:
                vendor_sum += "v:" + elt.info[:3].hex() + "|"
            except:
                pass
        if elt.ID == 11:  # country
            try:
                vendor_sum += "ctry:" + elt.info[:2].decode(errors='ignore') + "|"
            except:
                pass
        # beacon interval handled in Dot11Beacon
        elt = elt.payload.getlayer(Dot11Elt)

    # beacon-specific fields
    if pkt.haslayer(Dot11Beacon):
        try:
            beacon_interval = pkt[Dot11Beacon].beacon_interval
            beacon_ts = int(pkt[Dot11Beacon].timestamp)
        except Exception:
            pass

    ssid_norm = normalize_ssid(ssid_raw or "<hidden>")
    return (ssid_raw, ssid_norm, bssid, channel, rssi, seq, beacon_ts, rsn, vendor_sum, beacon_interval)

def handle_packet(pkt, conn, scorer, iface):
    data = extract_beacon_fields(pkt)
    if not data:
        return
    (ssid_raw, ssid_norm, bssid, channel, rssi, seq, beacon_ts, rsn, vendsum, bint) = data
    ts = now_ts()
    cur = conn.cursor()
    # insert event
    cur.execute("""
        INSERT INTO events (ts, ssid_raw, ssid_norm, bssid, frame_subtype, rssi, channel, seq_num, beacon_ts, rsn_hash, vendor_summary)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (ts, ssid_raw, ssid_norm, bssid, "beacon", rssi, channel, seq, beacon_ts, rsn, vendsum))
    evt_id = cur.lastrowid

    # update ap_docs
    cur.execute("SELECT id, rsn_hashes, ouis, beacon_ts_hist, seen_count FROM ap_docs WHERE ssid_norm=? AND bssid=?", (ssid_norm, bssid))
    row = cur.fetchone()
    oui = oui_of_mac(bssid)
    if row:
        doc_id, rsn_hashes_s, ouis_s, beacon_ts_hist_s, seen_count = row
        rsn_set = set(filter(None, (rsn_hashes_s or "").split(",")))
        rsn_set.add(rsn) if rsn else None
        ouis_set = set(filter(None, (ouis_s or "").split(",")))
        ouis_set.add(oui)
        seen_count = (seen_count or 0) + 1
        # update beacon_ts_hist
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
        """, (ts, rssi or None, channel, ",".join(filter(None, rsn_set)), ",".join(filter(None, ouis_set)), ",".join(filter(None, map(str, filter(None,[bint])))), seq or None, json.dumps(hist), seen_count, doc_id))
    else:
        # insert new
        rsn_val = rsn or ""
        ouis_val = oui or ""
        hist = [beacon_ts] if beacon_ts is not None else []
        cur.execute("""
            INSERT INTO ap_docs (ssid_raw, ssid_norm, bssid, first_seen, last_seen, sample_rssi, channel, rsn_hashes, ouis, beacon_intervals, seq_last, beacon_ts_hist, seen_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ssid_raw, ssid_norm, bssid, ts, ts, rssi or None, channel, rsn_val, ouis_val, str(bint) if bint else "", seq or None, json.dumps(hist), 1))
    conn.commit()

    # update in-memory rssi history and run scoring
    key = f"{ssid_norm}|{bssid}"
    scorer.update_rssi_hist(key, rssi or 0)
    score, evidence = scorer.compute_score(ssid_norm, bssid)

    # update last_score
    cur.execute("UPDATE ap_docs SET last_score=? WHERE ssid_norm=? AND bssid=?", (score, ssid_norm, bssid))
    conn.commit()

    # print / alert
    if score >= ALERT_THRESHOLD:
        alert = {
            "alert_ts": iso_ts(),
            "ssid": ssid_raw,
            "ssid_norm": ssid_norm,
            "bssid": bssid,
            "score": score,
            "evidence": evidence,
            "event_id": evt_id
        }
        # write alert file
        fname = f"{ALERT_DIR}/alert_{int(time.time())}_{bssid.replace(':','')}.json"
        with open(fname, "w") as f:
            json.dump(alert, f, indent=2)
        print("\n*** ALERT ***")
        print(json.dumps(alert, indent=2))
        # optional pcap capture for forensics
        if PCAP_ON_ALERT:
            pcap_name = f"{PCAP_DIR}/pcap_{int(time.time())}_{bssid.replace(':','')}.pcap"
            print(f"Capturing {PCAP_SECONDS}s pcap to {pcap_name} (requires tcpdump).")
            capture_pcap(iface, pcap_name, duration=PCAP_SECONDS)

# Main -----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True, help="monitor-mode interface, e.g., wlan0mon")
    parser.add_argument("--no-pcap", action="store_true", help="disable pcap capture on alerts")
    args = parser.parse_args()
    iface = args.iface
    global PCAP_ON_ALERT
    if args.no_pcap:
        PCAP_ON_ALERT = False

    ensure_dirs()
    whitelist = load_whitelist()
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    init_db(conn)
    scorer = Scorer(conn, whitelist)

    print("Starting standalone detector on iface", iface)
    print("Alert threshold:", ALERT_THRESHOLD)
    # sniff in background thread (scapy sniff is blocking)
    def scapy_prn(pkt):
        try:
            handle_packet(pkt, conn, scorer, iface)
        except Exception as e:
            print("packet handling error:", e)

    sniff(iface=iface, prn=scapy_prn, store=0)

if __name__ == "__main__":
    main()
