# Rogue-AP Developer Documentation - Quick Reference

## 📚 Documentation Index

### Getting Started
1. **[Setup Guide](./SETUP.md)** - Installation, dependencies, and configuration
2. **[Architecture Overview](./ARCHITECTURE.md)** - System design and data flow

### Core Modules

#### Wireless Operations
- **[scanner.py](./scanner.md)** - Low-level wireless scanning, monitor mode, deauthentication
  - Functions: `scan_aps()`, `scan_clients()`, `send_deauth()`, `deauth_all()`
  - Monitor mode management
  - Packet injection capabilities

#### AP Management  
- **[ap_manager.py](./ap_manager.md)** - Access point lifecycle with hostapd/dnsmasq
  - Class: `APManager` - Complete AP lifecycle management
  - Functions: `start_ap()` - Convenience wrapper
  - Features: NAT forwarding, beacon customization, BSSID spoofing

#### Detection Engines
- **[client_detector.py](./client_detector.md)** - Heuristic-based snapshot detection
  - Function: `detect_rogue_aps()` - Weight-based scoring
  - 7 detection heuristics with configurable weights
  - Severity classification: benign/suspicious/highly suspicious

- **[server_detector.py](./server_detector.md)** - Behavioral monitoring with persistence
  - Class: `Scorer` - Risk scoring engine
  - Functions: `extract_beacon_fields()`, `init_db()`
  - SQLite database for temporal analysis
  - Fingerprint inconsistency detection

#### Attack Implementations
- **[mitm_attack.py](./mitm_attack.md)** - Stealth MITM attack (no beacons)
  - Class: `MITMAttack` - Coordinate MITM operations
  - Probe response-based client capture
  - BSSID cloning and vendor IE matching

### User Interfaces
- **[GUI Applications](./gui.md)** - All three GUI modules documented together
  - **gui.py** - Main interface (scanning, AP creation, attacks)
  - **gui_client_detector.py** - Heuristic detection interface
  - **gui_server_detector.py** - Continuous monitoring interface

---

## 🔍 Quick Function Reference

### Most Common Operations

```python
# Scanning
from scanner import start_monitor_mode, scan_aps, stop_monitor_mode
start_monitor_mode("wlan0")
aps = scan_aps("wlan0mon", timeout=30)
stop_monitor_mode("wlan0mon")

# Detection (Client-Side)
from client_detector import detect_rogue_aps
results = detect_rogue_aps(aps, whitelist_ssids=['MyNetwork'])

# Detection (Server-Side)
from server_detector import Scorer, init_db
import sqlite3
conn = sqlite3.connect('detection.db')
init_db(conn)
scorer = Scorer(conn, whitelist={'known_ssids': [], 'known_bssids': []})
score, evidence = scorer.compute_score("mynetwork", "aa:bb:cc:dd:ee:ff")

# AP Management
from ap_manager import start_ap
mgr = start_ap("wlan0", "TestAP", "password123", upstream_iface="eth0")
# ... AP running ...
mgr.stop()

# MITM Attack
from mitm_attack import start_mitm_attack
attack = start_mitm_attack(
    "wlan0", "aa:bb:cc:dd:ee:ff", "TargetSSID", 6,
    password="rogue_pass", upstream_iface="eth0"
)
# ... attack running ...
attack.stop()

# Deauthentication
from scanner import send_deauth
send_deauth("aa:bb:cc:dd:ee:ff", count=10)
```

---

## 📊 Module Dependency Graph

```
gui.py ─────────┬──────────> scanner.py ────> scapy
                ├──────────> ap_manager.py ──> hostapd/dnsmasq
                └──────────> mitm_attack.py
                                 └──────────> ap_manager.py

gui_client_detector.py ──┬──> scanner.py
                         └──> client_detector.py

gui_server_detector.py ──┬──> scanner.py
                         └──> server_detector.py ──> sqlite3

All modules ────────────────> Linux tools (iw, ip, airmon-ng)
```

---

## 🎯 Use Case → Module Mapping

| What You Want To Do | Primary Module | Supporting Modules |
|---------------------|----------------|-------------------|
| Scan for nearby APs | scanner.py | - |
| Create a rogue AP | ap_manager.py | scanner.py (for cloning) |
| Detect rogue APs (snapshot) | client_detector.py | scanner.py |
| Monitor network continuously | server_detector.py | scanner.py |
| Deauthenticate clients | scanner.py | - |
| MITM attack | mitm_attack.py | ap_manager.py, scanner.py |
| GUI for all operations | gui.py | All modules |
| GUI for detection only | gui_client_detector.py or gui_server_detector.py | Detection modules |

---

## 🔑 Key Classes

| Class | Module | Purpose |
|-------|--------|---------|
| `APManager` | ap_manager.py | Manage hostapd-based AP lifecycle |
| `Scorer` | server_detector.py | Calculate rogue AP risk scores |
| `MITMAttack` | mitm_attack.py | Coordinate stealth MITM operations |
| `GuiApp` | gui.py | Main GUI application |
| `EnhancedGuiClientDetectorApp` | gui_client_detector.py | Client detection GUI |
| `GuiServerDetectorApp` | gui_server_detector.py | Server detection GUI |

---

## 📖 Function Categories

### Interface Management
- `scanner._iface_exists()` - Check interface existence
- `scanner._iface_mac()` - Get interface MAC address
- `scanner.start_monitor_mode()` - Enable monitor mode
- `scanner.stop_monitor_mode()` - Disable monitor mode

### Scanning & Discovery
- `scanner.scan_aps()` - Discover access points
- `scanner.scan_clients()` - Enumerate connected clients
- `server_detector.extract_beacon_fields()` - Parse beacon packets

### Detection & Analysis
- `client_detector.detect_rogue_aps()` - Heuristic detection
- `server_detector.Scorer.compute_score()` - Behavioral scoring
- `server_detector.levenshtein()` - String similarity (typosquatting)

### Attacks
- `scanner.send_deauth()` - Single deauth burst
- `scanner.deauth_all()` - Continuous deauth attack
- `mitm_attack.MITMAttack.start()` - Begin MITM attack

### AP Management
- `ap_manager.APManager.start()` - Start access point
- `ap_manager.APManager.stop()` - Stop access point
- `ap_manager.start_ap()` - Convenience function

### Database Operations
- `server_detector.init_db()` - Initialize SQLite schema
- `server_detector.now_ts()` - Current timestamp
- `server_detector.iso_ts()` - ISO-8601 timestamp

---

## ⚙️ Configuration Constants

### Detection Thresholds
```python
# client_detector.py
WEIGHTS = {
    'whitelist': -5,
    'duplicate_ssid': 3,
    'vendor_mismatch': 4,
    'channel_spread': 2,
    'missing_vendor_ies': 2,
    'short_beacon': 1,
    'rssi_anomaly': 2,
}

# server_detector.py
ALERT_THRESHOLD = 50     # Score to trigger alert
RSSI_JUMP_DB = 15        # dB change threshold
RSSI_JUMP_WINDOW = 5     # Seconds
```

### Network Settings
```python
# ap_manager.py defaults
ap_ip = "192.168.50.1/24"
dhcp_start = "192.168.50.10"
dhcp_end = "192.168.50.100"
channel = 6
hw_mode = "g"  # or "a" for 5GHz
```

---

## 🛡️ Security Warnings

### Legal Requirements
- ⚠️ Only use on networks you own or have **written permission** to test
- 🚫 Unauthorized use violates:
  - Computer Fraud and Abuse Act (US)
  - EU Cybercrime Directive
  - Local telecommunications laws
- ⚖️ Violations can result in criminal prosecution and civil liability

### Ethical Guidelines
1. **Authorization**: Always get explicit written permission
2. **Scope**: Stay within agreed testing boundaries
3. **Logging**: Document all testing activities
4. **Disclosure**: Report findings responsibly
5. **Cleanup**: Remove all testing artifacts

### Safe Usage
- ✅ Isolated lab environments
- ✅ Personal test networks
- ✅ Authorized penetration testing
- ✅ Academic research (offline)
- ❌ Public WiFi networks
- ❌ Corporate networks (without permission)
- ❌ Neighbor's networks
- ❌ Any network you don't own

---

## 🐛 Common Issues & Solutions

### Monitor Mode Won't Start
```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
```

### Permission Denied
```bash
sudo -E .venv/bin/python script.py
```

### Interface Not Found
```bash
ip link show          # List all interfaces
iw dev                # List wireless interfaces
```

### hostapd Fails
```bash
sudo killall hostapd  # Kill existing instances
sudo systemctl stop hostapd
```

### Database Locked
```python
# Use check_same_thread=False
conn = sqlite3.connect('db.sqlite', check_same_thread=False)
```

---

## 📚 Additional Resources

### External Documentation
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [hostapd Configuration](https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf)
- [IEEE 802.11 Standards](https://standards.ieee.org/standard/802_11-2020.html)
- [dnsmasq Manual](https://thekelleys.org.uk/dnsmasq/doc.html)

### Related Tools
- **aircrack-ng**: Wireless security auditing suite
- **Wireshark**: Packet analysis
- **Kismet**: Wireless detection and monitoring
- **Bettercap**: Network attack framework

---

## 🤝 Contributing

When contributing to the project:
1. Follow existing code style and patterns
2. Document all public functions with docstrings
3. Update relevant .md files in docs/
4. Test in isolated lab environment
5. Never commit credentials or sensitive data

---

## 📝 Documentation Maintenance

### When Adding Features
1. Update relevant module .md file
2. Add function reference to Quick Reference above
3. Update Architecture.md if design changes
4. Add usage examples

### File Organization
```
docs/
├── README.md                  # This file (index)
├── SETUP.md                   # Installation guide
├── ARCHITECTURE.md            # System design
├── scanner.md                 # scanner.py docs
├── ap_manager.md              # ap_manager.py docs
├── client_detector.md         # client_detector.py docs
├── server_detector.md         # server_detector.py docs
├── mitm_attack.md             # mitm_attack.py docs
├── gui.md                     # All GUI applications
├── gui_client_detector.md     # Stub pointing to gui.md
└── gui_server_detector.md     # Stub pointing to gui.md
```

---

## Version Information

**Documentation Version**: 1.0  
**Last Updated**: November 24, 2024  
**Compatible With**: Rogue-AP main branch

For updates and latest documentation, visit the project repository.
