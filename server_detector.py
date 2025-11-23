#!/usr/bin/env python3
"""
Core detection engine for the server-side/local detector

This module contains the scoring logic, utility functions, database operations,
and packet extraction functions for rogue AP detection.
"""
import time
import json
import sqlite3
from collections import defaultdict, deque
from datetime import datetime

try:
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# Constants
ALERT_THRESHOLD = 50
RSSI_JUMP_DB = 15
RSSI_JUMP_WINDOW = 5


# Utility functions
def now_ts():
    """Return current timestamp as integer"""
    return int(time.time())


def iso_ts(ts=None):
    """Convert timestamp to ISO format"""
    return datetime.utcfromtimestamp(ts or time.time()).isoformat() + "Z"


def normalize_ssid(ssid_raw):
    """Normalize SSID to lowercase and stripped"""
    try:
        s = ssid_raw.strip()
        return s.lower()
    except:
        return ssid_raw


def oui_of_mac(mac):
    """Extract OUI (first 6 hex digits) from MAC address"""
    if not mac:
        return ""
    return mac.replace(":", "").lower()[:6]


def levenshtein(a, b):
    """Calculate Levenshtein distance between two strings"""
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
    """Initialize database tables for AP tracking and events"""
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
    """
    Main scoring engine for rogue AP detection.
    
    Analyzes AP characteristics and behaviors to compute a risk score (0-100).
    Higher scores indicate higher likelihood of being a rogue AP.
    """
    
    def __init__(self, conn, whitelist):
        """
        Initialize the scorer.
        
        Args:
            conn: SQLite database connection
            whitelist: Dictionary with 'known_ssids' and 'known_bssids' lists
        """
        self.conn = conn
        self.whitelist = whitelist
        self.rssi_hist = defaultdict(lambda: deque())

    def update_rssi_hist(self, key, rssi):
        """
        Update RSSI history for an AP.
        
        Args:
            key: Unique identifier for AP (ssid_norm|bssid)
            rssi: RSSI value to add
        """
        h = self.rssi_hist[key]
        ts = time.time()
        h.append((ts, rssi))
        while h and (ts - h[0][0]) > RSSI_JUMP_WINDOW:
            h.popleft()

    def compute_score(self, ssid_norm, bssid):
        """
        Compute the risk score for an AP.
        
        Args:
            ssid_norm: Normalized SSID
            bssid: BSSID of the AP
            
        Returns:
            Tuple of (score, evidence_list)
            - score: Integer 0-100 indicating risk level
            - evidence_list: List of strings describing detection reasons
        """
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
    """
    Extract relevant fields from a beacon/probe response packet.
    
    Args:
        pkt: Scapy packet object
        
    Returns:
        Tuple of extracted fields or None if packet is not a beacon/probe response:
        (ssid_raw, ssid_norm, bssid, channel, rssi, seq, beacon_ts, rsn, vendor_sum, beacon_interval)
    """
    if not SCAPY_AVAILABLE or not pkt.haslayer(Dot11):
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
