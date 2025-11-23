# server_detector.py - Server-Side Detection Engine

## Overview

Implements continuous behavioral monitoring and scoring for rogue AP detection using SQLite persistence, fingerprint tracking, and temporal analysis.

## Core Components

### Database Schema

#### ap_docs Table
Tracks all observed APs with fingerprints and metadata:
- `ssid_raw`, `ssid_norm`: Original and normalized SSID
- `bssid`: MAC address
- `first_seen`, `last_seen`: Timestamps
- `sample_rssi`, `channel`: Signal and channel info
- `rsn_hashes`: Security configurations seen (comma-separated)
- `ouis`: Vendor OUIs observed (comma-separated)
- `beacon_intervals`: Beacon intervals recorded (comma-separated)
- `beacon_ts_hist`: Beacon timestamps (JSON array)
- `seen_count`: Number of observations
- `last_score`: Most recent risk score

#### events Table
Logs individual packet observations for forensics

---

## Key Functions

### `init_db(conn)`
**Purpose**: Initialize SQLite database schema
**Parameters**: `conn` (sqlite3.Connection)
**Implementation**: Creates tables if not exists

---

### `now_ts() -> int`
**Purpose**: Get current Unix timestamp
**Returns**: Integer timestamp

---

### `iso_ts(ts=None) -> str`
**Purpose**: Convert timestamp to ISO 8601 format
**Parameters**: `ts` (int, optional): Timestamp (default: now)
**Returns**: ISO formatted string (e.g., "2024-11-24T12:34:56Z")

---

### `normalize_ssid(ssid_raw) -> str`
**Purpose**: Normalize SSID for comparison (lowercase, stripped)
**Parameters**: `ssid_raw` (str)
**Returns**: Normalized SSID

---

### `oui_of_mac(mac) -> str`
**Purpose**: Extract OUI (first 3 octets) from MAC address
**Parameters**: `mac` (str): MAC address
**Returns**: 6-character hex string (e.g., "001122")

---

### `levenshtein(a, b) -> int`
**Purpose**: Calculate edit distance between strings
**Parameters**: `a`, `b` (str): Strings to compare
**Returns**: Integer edit distance
**Use Case**: Detect typosquatting SSIDs

---

### `extract_beacon_fields(pkt) -> tuple`
**Purpose**: Parse beacon/probe response packet
**Parameters**: `pkt` (Scapy packet)
**Returns**: Tuple or None if not a beacon:
```python
(ssid_raw, ssid_norm, bssid, channel, rssi, seq, 
 beacon_ts, rsn, vendor_sum, beacon_interval)
```
**Implementation**:
- Filters Dot11 type 0 subtype 8 (beacon) or 5 (probe response)
- Extracts all relevant information elements
- Parses RadioTap for RSSI
- Hashes RSN IE for security fingerprinting

---

## Scorer Class

### `Scorer(conn, whitelist)`
**Purpose**: Main detection engine with scoring logic

**Parameters**:
- `conn` (sqlite3.Connection): Database connection
- `whitelist` (dict): 
  ```python
  {
      'known_ssids': [
          {'ssid': str, 'ouis': [str]}
      ],
      'known_bssids': [str]
  }
  ```

---

### `compute_score(ssid_norm, bssid) -> (int, list[str])`
**Purpose**: Calculate risk score for an AP

**Returns**: 
- `score` (int): 0-100 risk score
- `evidence` (list[str]): Reasons for score

**Scoring Logic**:

#### Whitelist Match (-20 to -30 points)
- Known SSID with matching OUI: -20
- Known BSSID: -30

#### Duplicate SSID Detection
**Different Scenarios**:
1. **Impersonating Whitelisted AP** (+60 base, +40 security diff, +40 vendor diff)
   - One BSSID whitelisted, current is not
   - Likely rogue impersonation attempt
   
2. **Non-Whitelisted Duplicates** (+15 base, +20 vendor diff, +25 security diff)
   - No BSSIDs whitelisted
   - Could be legitimate multi-AP or rogue

3. **Current BSSID Whitelisted** (+5 or +10)
   - Minimal penalty for legitimate multi-AP setups

#### Fingerprint Inconsistency
- Multiple OUIs for same BSSID: +15
- Multiple RSN hashes: +20
- Indicates MAC randomization or impersonation

#### Beacon Anomalies
- Interval <50ms or >200ms: +5 per anomaly

#### Beacon Timestamp Non-Monotonic (+15)
- Timestamps should increase monotonically
- Resets indicate possible AP restart or spoofing

#### RSSI Jump Detection (+5)
- Tracks last 5 RSSI values in 5-second window
- Jump >15dB indicates position change (portable rogue)

#### Typosquatting (+10)
- Levenshtein distance ≤2 from known SSID
- Example: "CampusWiFi" vs "CampusWifi"

#### High-Entropy SSID (+5)
- Many non-alphanumeric characters
- Unusual for legitimate networks

**Final Score**: Capped at 100

---

### `update_rssi_hist(key, rssi)`
**Purpose**: Track RSSI history for jump detection
**Parameters**:
- `key` (str): "ssid_norm|bssid"
- `rssi` (int): RSSI value
**Implementation**: Maintains 5-second sliding window

---

## Constants

```python
ALERT_THRESHOLD = 50     # Score ≥50 triggers alert
RSSI_JUMP_DB = 15        # dB change threshold
RSSI_JUMP_WINDOW = 5     # Seconds to track
```

---

## Usage Examples

### Basic Setup
```python
import sqlite3
from server_detector import init_db, Scorer, extract_beacon_fields

# Initialize database
conn = sqlite3.connect('ap_monitoring.db')
init_db(conn)

# Load whitelist
whitelist = {
    'known_ssids': [
        {'ssid': 'CampusWiFi', 'ouis': ['001122', '334455']}
    ],
    'known_bssids': ['aa:bb:cc:dd:ee:ff']
}

# Create scorer
scorer = Scorer(conn, whitelist)
```

### Live Monitoring
```python
from scapy.all import sniff

def packet_handler(pkt):
    fields = extract_beacon_fields(pkt)
    if not fields:
        return
    
    ssid_raw, ssid_norm, bssid, channel, rssi, seq, \
    beacon_ts, rsn, vendor_sum, beacon_interval = fields
    
    # Update database (add your DB update logic)
    # ...
    
    # Score AP
    score, evidence = scorer.compute_score(ssid_norm, bssid)
    
    if score >= ALERT_THRESHOLD:
        print(f"ALERT: {ssid_raw} ({bssid}) - Score: {score}")
        print(f"Evidence: {', '.join(evidence)}")
        
    # Update RSSI history
    key = f"{ssid_norm}|{bssid}"
    if rssi:
        scorer.update_rssi_hist(key, rssi)

# Start capture
sniff(iface='wlan0mon', prn=packet_handler, store=0)
```

### Query Suspicious APs
```python
cur = conn.cursor()
cur.execute("""
    SELECT bssid, ssid_raw, last_score 
    FROM ap_docs 
    WHERE last_score >= ? 
    ORDER BY last_score DESC
""", (ALERT_THRESHOLD,))

for bssid, ssid, score in cur.fetchall():
    print(f"{ssid} ({bssid}): {score}")
```

---

## Detection Advantages

### vs Client-Side Detection

**Server-Side Strengths**:
1. **Temporal Analysis**: Tracks behavior over time
2. **Persistent State**: Database maintains history
3. **Fingerprint Tracking**: Detects inconsistent hardware signatures
4. **RSSI Monitoring**: Identifies mobile rogues
5. **Deeper Inspection**: Analyzes beacon timestamps, sequence numbers

**Limitations**:
1. **Requires Infrastructure**: Needs deployed sensors
2. **Network Position**: Must be able to monitor target area
3. **Storage**: Database grows over time

---

## Tuning Detection

### Adjust Thresholds
```python
ALERT_THRESHOLD = 40  # More sensitive
RSSI_JUMP_DB = 20     # Less sensitive to movement
```

### Custom Scoring
Modify `Scorer.compute_score()`:
```python
# Add custom check
if some_condition:
    score += 15
    evidence.append("custom_check_failed")
```

---

## Database Maintenance

### Cleanup Old Records
```python
import time

# Remove APs not seen in 7 days
week_ago = int(time.time()) - 7*24*3600
cur.execute("DELETE FROM ap_docs WHERE last_seen < ?", (week_ago,))
cur.execute("DELETE FROM events WHERE ts < ?", (week_ago,))
conn.commit()
```

### Vacuum Database
```python
conn.execute("VACUUM")
```

---

## Performance Considerations

- **Index on SSID/BSSID**: Add indexes for faster queries
- **Batch Commits**: Commit every N packets, not every packet
- **Limit History**: Cap beacon_ts_hist to last 10 entries
- **Prune RSSI History**: Auto-expires after RSSI_JUMP_WINDOW

---

## Related Modules

- **gui_server_detector.py**: GUI implementation using this engine
- **client_detector.py**: Complementary snapshot-based detection
- **scanner.py**: Provides packet capture interface
