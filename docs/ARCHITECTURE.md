# Architecture Overview

This document provides a high-level overview of the Rogue-AP system architecture, design patterns, and component interactions.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Interface Layer                     │
├──────────────┬──────────────────┬──────────────────────────┤
│   gui.py     │ gui_client_      │ gui_server_detector.py   │
│   (Main GUI) │ detector.py      │ (Server Detector GUI)    │
└──────┬───────┴────────┬─────────┴────────┬─────────────────┘
       │                │                  │
       ├────────────────┴──────────────────┤
       │                                   │
┌──────▼───────────────────────────────────▼─────────────────┐
│              Detection & Analysis Layer                     │
├────────────────────────┬────────────────────────────────────┤
│  client_detector.py    │    server_detector.py              │
│  (Client-side heur.)   │    (Server-side scoring)           │
└────────────────────────┴────────────────────────────────────┘
       │                                   │
       │                                   ▼
┌──────▼───────────────────────────────────────────────────┐
│                Core Operations Layer                       │
├──────────────────┬─────────────────┬─────────────────────┤
│   scanner.py     │  ap_manager.py  │  mitm_attack.py     │
│   (Wireless I/O) │  (AP lifecycle) │  (MITM operations)  │
└──────┬───────────┴────────┬────────┴──────────┬──────────┘
       │                    │                   │
       └────────────────────┴───────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────┐
│              System/Hardware Interface                     │
├─────────────┬──────────────┬──────────────┬───────────────┤
│  Scapy      │   hostapd    │   dnsmasq    │  Linux tools  │
│  (packets)  │   (AP mode)  │   (DHCP)     │  (iw, ip)     │
└─────────────┴──────────────┴──────────────┴───────────────┘
```

## Component Overview

### 1. User Interface Layer

#### gui.py
- **Purpose**: Main graphical interface for the toolkit
- **Features**: 
  - Interface discovery and selection
  - AP scanning with live results
  - Rogue AP creation and management
  - Deauthentication attacks
  - MITM attack coordination
  - Live logging console
- **Dependencies**: scanner, ap_manager, mitm_attack modules

#### gui_client_detector.py
- **Purpose**: Client-side rogue AP detection interface
- **Features**:
  - Heuristic-based detection scoring
  - Whitelist management
  - Suspicious AP highlighting
  - Detailed reason reporting
- **Dependencies**: scanner, client_detector modules

#### gui_server_detector.py
- **Purpose**: Server-side continuous monitoring interface
- **Features**:
  - Live packet capture and analysis
  - SQLite database for AP tracking
  - Behavioral anomaly detection
  - Real-time scoring and alerting
- **Dependencies**: scanner, server_detector modules

### 2. Detection & Analysis Layer

#### client_detector.py
- **Purpose**: Client-side detection heuristics
- **Algorithm**: Weight-based scoring system
- **Heuristics**:
  - Whitelist matching (negative weight)
  - Duplicate SSID detection
  - Vendor IE mismatches
  - Channel spread analysis
  - Beacon interval anomalies
  - RSSI outlier detection
- **Output**: Scored results with severity levels and detailed reasons

#### server_detector.py
- **Purpose**: Server-side detection engine
- **Algorithm**: Behavioral analysis with persistent state
- **Features**:
  - SQLite-based AP tracking
  - Fingerprint inconsistency detection
  - Beacon timestamp monotonicity checks
  - RSSI jump detection
  - Typosquatting/lookalike SSID detection
- **Output**: Risk scores (0-100) with evidence lists

### 3. Core Operations Layer

#### scanner.py
- **Purpose**: Low-level wireless operations
- **Capabilities**:
  - Monitor mode management
  - AP discovery with beacon parsing
  - Client enumeration
  - Deauthentication frame injection
  - Channel hopping
  - Vendor IE extraction
- **Implementation**: Scapy-based packet manipulation

#### ap_manager.py
- **Purpose**: Access point lifecycle management
- **Features**:
  - hostapd configuration generation
  - dnsmasq DHCP server setup
  - NAT/forwarding configuration
  - Interface preparation and recovery
  - Beacon customization (IEs, BSSID, interval)
- **Implementation**: Python subprocess control with hostapd/dnsmasq

#### mitm_attack.py
- **Purpose**: Man-in-the-middle attack implementation
- **Strategy**:
  - BSSID cloning
  - Selective probe response (no beacon spam)
  - Aggressive client association
  - Traffic forwarding with NAT
- **Implementation**: Combines ap_manager with custom probe responder

## Data Flow

### Scanning Workflow
```
User → GUI → scanner.start_monitor_mode()
                ↓
         scanner.scan_aps()
                ↓
         Scapy sniff (Dot11Beacon frames)
                ↓
         Parse: SSID, BSSID, channel, vendor IEs, RSSI
                ↓
         Return: {bssid: {ssid, channel, ies_hex, beacon_int}}
                ↓
         GUI displays in TreeView
```

### Client-Side Detection Workflow
```
Scan Results → client_detector.detect_rogue_aps()
                      ↓
               Group APs by SSID
                      ↓
               Apply heuristics (parallel)
                      ↓
               Calculate weighted scores
                      ↓
               Assign severity levels
                      ↓
               Return detailed results
                      ↓
               GUI highlights suspicious APs
```

### Server-Side Detection Workflow
```
Live Capture → extract_beacon_fields()
                      ↓
               Update SQLite (ap_docs, events)
                      ↓
               Scorer.compute_score()
                      ↓
               Check: whitelists, duplicates, fingerprints
                      ↓
               Calculate risk score (0-100)
                      ↓
               If score >= threshold: Alert
                      ↓
               GUI updates suspicious panel
```

### AP Creation Workflow
```
User Input → APManager.__init__()
                   ↓
            Prepare interface (down, assign IP, up)
                   ↓
            Generate hostapd.conf (with beacon customization)
                   ↓
            Generate dnsmasq.conf
                   ↓
            Start hostapd subprocess
                   ↓
            Start dnsmasq subprocess
                   ↓
            Enable NAT (if upstream interface provided)
                   ↓
            AP operational
```

### MITM Attack Workflow
```
Target Selection → MITMAttack.__init__()
                         ↓
                  Prepare interface (managed mode)
                         ↓
                  Spoof MAC to target BSSID
                         ↓
                  Start hostapd (no beacons)
                         ↓
                  Start probe responder thread
                         ↓
                  Monitor Dot11ProbeReq
                         ↓
                  Respond with custom Dot11ProbeResp
                         ↓
                  Clients associate
                         ↓
                  Forward traffic via NAT
```

## Design Patterns

### 1. Facade Pattern
- **APManager** provides simple interface to complex hostapd/dnsmasq setup
- **MITMAttack** wraps multi-step MITM operation

### 2. Observer Pattern
- GUI queue-based updates for thread-safe async operations
- Callback mechanisms for logging (log_callback)

### 3. Strategy Pattern
- Client-side vs server-side detection strategies
- Pluggable heuristics with configurable weights

### 4. State Pattern
- APManager tracks AP lifecycle (not started → running → stopped)
- MITMAttack manages attack state

### 5. Template Method Pattern
- scanner functions provide template for scanning operations
- Customizable via parameters (timeout, channels, callbacks)

## Data Models

### AP Information (scanner.py output)
```python
{
    'bssid': str,           # MAC address (lowercase)
    'ssid': str,            # Network name
    'channel': int,         # WiFi channel number
    'ies_hex': str,         # Vendor IEs (hex string)
    'beacon_int': int,      # Beacon interval (ms)
    'rssi': int             # Signal strength (dBm)
}
```

### Detection Result (client_detector.py output)
```python
{
    'score': int,           # Suspicion score
    'reasons': [str],       # Human-readable reasons
    'detailed_reasons': [   # Structured heuristics
        {
            'key': str,     # Heuristic identifier
            'weight': int,  # Weight contribution
            'text': str     # Description
        }
    ],
    'info': dict,           # Original AP info
    'severity': str         # 'benign' | 'suspicious' | 'highly suspicious'
}
```

### Database Schema (server_detector.py)

#### ap_docs table
```sql
CREATE TABLE ap_docs (
    id INTEGER PRIMARY KEY,
    ssid_raw TEXT,
    ssid_norm TEXT,
    bssid TEXT,
    first_seen INTEGER,
    last_seen INTEGER,
    sample_rssi INTEGER,
    channel INTEGER,
    rsn_hashes TEXT,        -- Comma-separated security hashes
    ouis TEXT,              -- Comma-separated vendor OUIs
    beacon_intervals TEXT,  -- Comma-separated intervals
    seq_last INTEGER,
    beacon_ts_hist TEXT,    -- JSON array
    seen_count INTEGER,
    last_score INTEGER
)
```

#### events table
```sql
CREATE TABLE events (
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
```

### Whitelist Format (whitelist.json)
```json
{
    "known_ssids": [
        {
            "ssid": "MyNetwork",
            "ouis": ["001122", "334455"]
        }
    ],
    "known_bssids": [
        "aa:bb:cc:dd:ee:ff"
    ]
}
```

## Threading Model

### GUI Applications
- **Main Thread**: Tkinter event loop
- **Worker Threads**: 
  - Scanner subprocess reader
  - Live packet capture (server detector)
  - Channel hopping
  - Probe responder (MITM)
  - Deauth sender
- **Synchronization**: Queue-based message passing to main thread

### Thread Safety
- SQLite connections with `check_same_thread=False`
- Queue for GUI updates from worker threads
- Threading.Event for graceful shutdown
- Lock-free design where possible (immutable data sharing)

## Error Handling Strategy

### Levels
1. **Critical**: Require user intervention (interface not found, permission denied)
2. **Recoverable**: Log and continue (single packet processing failure)
3. **Expected**: Normal operation (no APs found during scan)

### Approaches
- Try-except blocks with specific exception handling
- Graceful degradation (continue without optional features)
- User-friendly error messages in GUI
- Detailed logging for debugging

## Security Considerations

### Privilege Management
- Requires root for raw socket access and interface configuration
- Minimal privilege escalation surface
- No persistent root processes

### Input Validation
- BSSID format validation (17 chars, 5 colons)
- SSID sanitization (strip, escape)
- Channel range checking
- Password strength enforcement (AP creation)

### Data Protection
- Temporary files in secure locations (/tmp with mkdtemp)
- Cleanup on exit
- No plaintext password storage (except in-memory)

## Performance Considerations

### Optimization Techniques
1. **Efficient Packet Filtering**: Scapy BPF filters
2. **Deduplication**: Track seen BSSIDs to avoid reprocessing
3. **Database Indexing**: Index on ssid_norm, bssid
4. **Lazy Loading**: Parse IEs only when needed
5. **Batch Operations**: Database commits, frame sending

### Scalability Limits
- ~100-200 APs before GUI becomes sluggish
- ~1000 packets/sec sustainable capture rate
- Database size grows linearly with monitoring time

## Extension Points

### Adding New Heuristics (client_detector.py)
1. Add weight to `WEIGHTS` dict
2. Add description to `HEURISTIC_TEXT` dict
3. Implement detection logic in `detect_rogue_aps()`
4. Append to `detailed_reasons` list

### Adding New Scoring Rules (server_detector.py)
1. Extend `Scorer.compute_score()` method
2. Update database schema if needed (add columns)
3. Append evidence strings to list

### Custom GUI Extensions
1. Inherit from base GUI classes
2. Override `_create_*` methods for custom widgets
3. Add menu items via `_create_menu()`
4. Implement custom styling in `_set_palette()`

## Dependencies Graph

```
gui.py
  ├─→ scanner.py (scapy, subprocess)
  ├─→ ap_manager.py (subprocess)
  └─→ mitm_attack.py
        ├─→ ap_manager.py
        └─→ scapy

gui_client_detector.py
  ├─→ scanner.py
  ├─→ client_detector.py (statistics)
  └─→ tkinter

gui_server_detector.py
  ├─→ scanner.py
  ├─→ server_detector.py
  │     ├─→ sqlite3
  │     └─→ scapy
  └─→ tkinter

All:
  ├─→ Python 3.8+ stdlib
  └─→ Linux system tools (iw, ip, airmon-ng, hostapd, dnsmasq)
```

## Testing Strategy

### Unit Testing
- Individual function testing (heuristics, scoring)
- Mock wireless interfaces
- Database operations

### Integration Testing
- End-to-end scanning workflow
- AP creation and teardown
- Detection accuracy against known rogue APs

### Manual Testing
- Hardware compatibility testing
- GUI usability testing
- Attack effectiveness testing (lab environment)

## Future Enhancements

1. **Machine Learning Detection**: Train models on beacon patterns
2. **5GHz Support**: Extend channel hopping to 5GHz band
3. **Distributed Monitoring**: Multi-sensor deployment
4. **REST API**: Programmatic access to detection engine
5. **Enhanced Fingerprinting**: Device-specific behavior tracking
6. **Automated Remediation**: Auto-deauth rogue APs
7. **Reporting**: Generate PDF/HTML security reports
