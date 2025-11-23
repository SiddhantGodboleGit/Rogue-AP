# GUI Applications Documentation

## Overview

The Rogue-AP toolkit includes three Tkinter-based GUI applications that provide user-friendly interfaces to the underlying detection and attack modules.

---

## gui.py - Main GUI Application

### Purpose
Central interface for wireless operations including scanning, AP creation, and attack coordination.

### Key Features

#### 1. Interface Management
- **Discover**: Auto-detect wireless interfaces
- **Monitor Mode**: Start/stop monitor mode with visual feedback
- **Interface Selection**: Dropdown or manual entry

#### 2. AP Scanning
- **Live Scan**: Background subprocess execution
- **Progress Indicator**: Indeterminate progress bar during scan
- **Results Table**: Displays BSSID, SSID, channel in sortable TreeView
- **Detailed View**: Right-click AP for full information

#### 3. Rogue AP Creation
- **Configuration**: SSID, password, channel, upstream interface
- **Clone Mode**: Copy settings from scanned AP (including vendor IEs)
- **Status Monitoring**: Real-time AP status display
- **Start/Stop**: One-click AP lifecycle management

#### 4. Deauthentication
- **Target Selection**: Pick AP from scan results
- **Parameters**: Reason code, packet rate, refresh interval
- **Continuous Mode**: Runs until manually stopped
- **Statistics**: Shows packets sent and clients affected

#### 5. MITM Attack
- **Stealth Mode**: No-beacon MITM attack
- **Target Cloning**: Preserves BSSID, vendor IEs, channel
- **Traffic Forwarding**: NAT setup for internet access
- **Attack Monitoring**: Live statistics on probes and responses

#### 6. Logging Console
- **Live Updates**: Queue-based thread-safe logging
- **Auto-Scroll**: Follows latest messages
- **Color Coding**: Warnings and errors highlighted
- **Export**: Save logs to file

### UI Components

```
┌─────────────────────────────────────────────────┐
│ Menu Bar: File | Tools | View | Help            │
├─────────────────────────────────────────────────┤
│ Toolbar: [Interface: wlan0▼] [Discover] [Scan] │
│          [Monitor] [Stop] [Theme Toggle]        │
├──────────────────┬──────────────────────────────┤
│  AP Results      │  Controls Panel              │
│  ┌──────────────┐│  ┌──────────────────┐        │
│  │BSSID  SSID   ││  │Create Rogue AP   │        │
│  │aa:bb  Test   ││  │SSID: [_______]   │        │
│  │...    ...    ││  │Pass: [_______]   │        │
│  └──────────────┘│  │[Start AP]        │        │
│                  │  └──────────────────┘        │
│                  │  ┌──────────────────┐        │
│                  │  │Deauth Attack     │        │
│                  │  │Target: [_____]   │        │
│                  │  │[Start] [Stop]    │        │
│                  │  └──────────────────┘        │
├──────────────────┴──────────────────────────────┤
│ Log Console                                     │
│ [12:34:56] Scanning started...                  │
│ [12:35:11] Found 15 APs                         │
│ ...                                              │
└─────────────────────────────────────────────────┘
```

### Usage Example

```python
# Run GUI (requires root for wireless ops)
sudo .venv/bin/python gui.py

# 1. Select interface (wlan0)
# 2. Click "Start Monitor"
# 3. Click "Scan APs"
# 4. Select AP from table
# 5. Configure rogue AP settings
# 6. Click "Start Rogue AP"
```

### Themes

**Light Mode** (default):
- Warm beige/tan color scheme
- High contrast text
- Professional appearance

**Dark Mode** (toggle via menu):
- Dark blue/teal color scheme
- Reduced eye strain
- "Hacker" aesthetic

---

## gui_client_detector.py - Client-Side Detection GUI

### Purpose
Specialized interface for heuristic-based rogue AP detection with whitelist management.

### Key Features

#### 1. Detection Engine
- **Heuristic Scoring**: Weight-based detection algorithm
- **Whitelist Integration**: SSID/BSSID whitelist support
- **Severity Levels**: Color-coded (green/yellow/red) results
- **Detailed Reasons**: Structured explanation of scores

#### 2. AP Management
- **Search/Filter**: Real-time search of SSID/BSSID
- **Sorting**: Click columns to sort results
- **Bulk Operations**: Clear all, export results

#### 3. Suspicious AP Panel
- **Auto-Population**: High-score APs highlighted automatically
- **Evidence Display**: Shows triggered heuristics
- **Severity Colors**:
  - 🟢 Green: Benign (score ≤0)
  - 🟡 Yellow: Suspicious (score 1-50% max)
  - 🔴 Red: Highly suspicious (score >50% max)

#### 4. Whitelist Management
- **Inline Editing**: Comma-separated lists
- **Save/Load**: JSON format persistence
- **Auto-Apply**: Real-time detection updates

#### 5. Heuristic Tuning
- **Weight Editor**: Adjust detection sensitivity
- **Custom Heuristics**: Add new detection rules
- **Export Settings**: Share tuned configurations

### UI Layout

```
┌────────────────────────────────────────────────┐
│ [Interface: wlan0] [Discover] [Scan]          │
├────────────────────────────────────────────────┤
│ Search: [_______] Whitelist: [SSIDs] [BSSIDs]│
├───────────────────────┬────────────────────────┤
│ All APs               │ Suspicious APs         │
│ ┌───────────────────┐ │ ┌────────────────────┐ │
│ │BSSID   SSID   Ch  │ │ │BSSID  Score Reason │ │
│ │aa:bb   Test   6   │ │ │cc:dd  75    Dup... │ │
│ │...     ...    ... │ │ │...    ...   ...    │ │
│ └───────────────────┘ │ └────────────────────┘ │
├───────────────────────┴────────────────────────┤
│ Details: CampusWiFi (aa:bb:cc:dd:ee:ff)       │
│ Score: 65 (Highly Suspicious)                  │
│ Reasons:                                        │
│  - Duplicate SSID (3 BSSIDs) [+3]             │
│  - Vendor mismatch [+4]                        │
│  - RSSI anomaly (-20dBm vs -45dBm avg) [+2]   │
└────────────────────────────────────────────────┘
```

### Usage Workflow

1. **Configure Whitelist**: Enter known SSIDs/BSSIDs
2. **Scan Network**: Click "Scan APs"
3. **Run Detection**: Click "Detect Rogue APs"
4. **Review Results**: Check suspicious panel
5. **Investigate**: Double-click for detailed analysis
6. **Save Settings**: Export whitelist for future use

---

## gui_server_detector.py - Server-Side Detection GUI

### Purpose
Continuous monitoring interface with SQLite persistence and behavioral analysis.

### Key Features

#### 1. Live Monitoring
- **Packet Capture**: Real-time beacon/probe response analysis
- **Database Logging**: Persistent AP tracking
- **Channel Hopping**: Multi-channel coverage
- **Background Thread**: Non-blocking capture

#### 2. Scoring Engine
- **Behavioral Analysis**: Temporal pattern detection
- **Fingerprint Tracking**: RSN, OUI, beacon interval monitoring
- **RSSI History**: Movement detection via signal changes
- **Alert Threshold**: Configurable score trigger

#### 3. AP Database
- **SQLite Backend**: Stores all observations
- **History Tracking**: First seen, last seen, count
- **Metadata**: Channel, RSSI, security, vendor info
- **Query Interface**: Filter by score, SSID, time

#### 4. Suspicious AP Tracking
- **Auto-Alert**: Scores ≥50 highlighted
- **Evidence Log**: Detailed scoring reasons
- **Severity Colors**: Visual risk indication
- **Historical View**: Load past detections on startup

#### 5. Whitelist Management
- **JSON Format**: Compatible with client detector
- **OUI Matching**: Vendor-specific whitelisting
- **Live Updates**: Immediate score recalculation

### UI Layout

```
┌────────────────────────────────────────────────┐
│ [Interface: wlan0mon] [Start Detection] [Stop]│
├────────────────────────────────────────────────┤
│ Whitelist: [SSIDs...] [BSSIDs...]             │
├───────────────────────┬────────────────────────┤
│ AP Database           │ Suspicious APs         │
│ ┌───────────────────┐ │ ┌────────────────────┐ │
│ │BSSID  SSID  Score │ │ │BSSID  SSID  Score  │ │
│ │aa:bb  WiFi  5     │ │ │cc:dd  Evil  85     │ │
│ │...    ...   ...   │ │ │...    ...   ...    │ │
│ └───────────────────┘ │ └────────────────────┘ │
├───────────────────────┴────────────────────────┤
│ Evidence: Evil Twin (cc:dd:ee:ff:11:22)       │
│ - Impersonating whitelisted BSSID [+60]       │
│ - Different security config [+40]              │
│ - Multiple OUIs observed [+15]                 │
│ - RSSI jump detected [+5]                      │
│ Total: 120 → capped at 100                     │
├────────────────────────────────────────────────┤
│ Log:                                            │
│ [12:34:56] Detection started on wlan0mon       │
│ [12:35:10] ALERT: Score 85 for "Evil" (cc:dd) │
└────────────────────────────────────────────────┘
```

### Usage Workflow

1. **Load Whitelist**: Import known networks
2. **Start Monitor**: Enable monitor mode
3. **Start Detection**: Begin live capture
4. **Monitor Alerts**: Watch suspicious panel
5. **Investigate**: Click AP for evidence details
6. **Export Data**: Save database for analysis
7. **Stop Detection**: Graceful shutdown

---

## Common GUI Features

### All GUIs Include:

1. **Keyboard Shortcuts**
   - `Ctrl+Q`: Quit
   - `Ctrl+R`: Refresh
   - `F5`: Scan/Detect

2. **Context Menus**
   - Right-click items for actions
   - Copy BSSID/SSID
   - View raw data

3. **Status Bar**
   - Current operation status
   - Progress indicators
   - Error messages

4. **Thread Safety**
   - Queue-based updates
   - Non-blocking operations
   - Graceful shutdown

5. **Error Handling**
   - User-friendly error dialogs
   - Detailed logs
   - Recovery suggestions

---

## Development Notes

### Styling
All GUIs use consistent styling:
```python
self.style.theme_use('clam')
self._bg_primary = "#f6f1e1"
self._accent = "#b8893f"
# ... more colors
```

### Threading Pattern
```python
def background_task():
    # Heavy work
    result = expensive_operation()
    # Queue result for GUI update
    self._queue.put(('update', result))

def _process_queue(self):
    try:
        while True:
            msg_type, data = self._queue.get_nowait()
            # Update GUI elements
    except queue.Empty:
        pass
    finally:
        self.after(100, self._process_queue)
```

### Resource Cleanup
All GUIs implement:
- `protocol("WM_DELETE_WINDOW", self._on_close)`
- Stop background threads
- Close database connections
- Restore network interfaces

---

## Best Practices

1. **Always Run with sudo**: Required for wireless operations
2. **Use Virtual Environment**: Isolate dependencies
3. **Check Logs**: Monitor console for errors
4. **Save Whitelists**: Backup configurations regularly
5. **Test in Lab**: Never use on production networks

---

## Troubleshooting

### GUI Won't Start
```bash
# Check Python/Tkinter
python3 -c "import tkinter"

# Check Scapy
python3 -c "import scapy"

# Run with sudo
sudo .venv/bin/python gui.py
```

### GUI Freezes
- Background task not properly threaded
- Check logs for exceptions
- Restart application

### No APs Appear
- Verify monitor mode active
- Check interface name correct
- Increase scan timeout

---

## Related Modules

All GUIs depend on:
- **scanner.py**: Wireless operations
- **client_detector.py** / **server_detector.py**: Detection engines
- **ap_manager.py**: AP management
- **mitm_attack.py**: MITM operations
