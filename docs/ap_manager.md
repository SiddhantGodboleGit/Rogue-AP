# ap_manager.py - Access Point Management

## Overview

The `ap_manager.py` module provides a high-level Python interface for creating and managing wireless access points using hostapd and dnsmasq. It handles the complete AP lifecycle including interface preparation, configuration generation, service management, and NAT setup.

## Dependencies

- `subprocess` - System command execution
- `tempfile` - Temporary directory/file creation
- `pathlib` - File system operations
- System tools: `hostapd`, `dnsmasq`, `iptables`, `iw`, `ip`, `nmcli`

## Classes

### APManager

**Purpose**: Manage the complete lifecycle of a temporary wireless access point

**Attributes**:
- `iface` (str): Wireless interface name
- `ssid` (str): Network SSID
- `passphrase` (str): WPA2 passphrase
- `ap_ip` (str): AP IP address with netmask (e.g., "192.168.50.1/24")
- `dhcp_start` (str): DHCP range start IP
- `dhcp_end` (str): DHCP range end IP
- `channel` (int): WiFi channel number
- `hw_mode` (str): Hardware mode ('g' for 2.4GHz, 'a' for 5GHz)
- `upstream_iface` (str, optional): Upstream interface for NAT
- `_beacon_ies` (str, optional): Custom beacon IEs (hex string)
- `_beacon_int` (int, optional): Beacon interval in milliseconds
- `_bssid` (str, optional): Custom BSSID to advertise
- `_tmpdir` (Path): Temporary directory for config files
- `_hostapd_proc` (Popen): hostapd process
- `_dnsmasq_proc` (Popen): dnsmasq process
- `_nat_enabled` (bool): NAT forwarding status

---

#### `__init__(iface, ssid, passphrase, ap_ip="192.168.50.1/24", dhcp_start="192.168.50.10", dhcp_end="192.168.50.100", channel=6, hw_mode="g", upstream_iface=None, beacon_ies=None, beacon_int=None, bssid=None)`

**Purpose**: Initialize AP manager with configuration

**Parameters**:
- `iface` (str): Wireless interface (e.g., "wlan0")
- `ssid` (str): Network name
- `passphrase` (str): WPA2 password (8-63 characters)
- `ap_ip` (str): AP IP with CIDR notation (default: "192.168.50.1/24")
- `dhcp_start` (str): DHCP pool start (default: "192.168.50.10")
- `dhcp_end` (str): DHCP pool end (default: "192.168.50.100")
- `channel` (int): WiFi channel (default: 6)
- `hw_mode` (str): 'g' for 2.4GHz, 'a' for 5GHz (default: 'g')
- `upstream_iface` (str, optional): Interface for internet forwarding (e.g., "eth0")
- `beacon_ies` (str, optional): Hex string of vendor IEs to include in beacons
- `beacon_int` (int, optional): Beacon interval in ms (typically 100)
- `bssid` (str, optional): Specific BSSID to advertise

**Implementation**:
- Stores all configuration parameters
- Initializes process handles to None
- Sets NAT status to False
- Does not start AP (call `start()` to begin)

**Example**:
```python
mgr = APManager(
    iface="wlan0",
    ssid="TestAP",
    passphrase="password123",
    channel=6,
    upstream_iface="eth0"
)
```

---

#### `start()`

**Purpose**: Start the access point and all associated services

**Parameters**: None

**Returns**: None

**Raises**:
- `PermissionError` if not running as root
- `RuntimeError` if interface not found or hostapd/dnsmasq fail to start

**Implementation**:
1. Verifies root privileges with `_ensure_root()`
2. Checks AP mode support with `_check_ap_support()`
3. Tells NetworkManager to stop managing interface with `_nm_manage(False)`
4. Prepares interface with `_prepare_interface()`:
   - Recovers from monitor mode if needed
   - Brings interface down
   - Assigns IP address
   - Brings interface up
5. Writes configuration files with `_write_configs()`:
   - hostapd.conf with regulatory domain, security, beacon customization
   - dnsmasq.conf with DHCP settings
6. Starts services with `_start_services()`:
   - Spawns hostapd subprocess
   - Waits 0.5s and checks if still running
   - Spawns dnsmasq subprocess
   - Waits 0.5s and checks if still running
7. Enables NAT with `_enable_nat()` if upstream interface specified
8. Prints status messages

**Example**:
```python
mgr = APManager("wlan0", "TestAP", "password123", upstream_iface="eth0")
mgr.start()
# AP now broadcasting on wlan0
```

**Error Handling**:
- If hostapd fails, logs are written to tmpdir and error includes log path
- If dnsmasq fails, similar logging behavior
- Captures stderr for diagnostic messages

---

#### `stop()`

**Purpose**: Stop the access point and clean up all resources

**Parameters**: None

**Returns**: None

**Implementation**:
1. Disables NAT rules with `_disable_nat()`
2. Stops services with `_stop_services()`:
   - Terminates hostapd process (SIGTERM, then SIGKILL if needed)
   - Terminates dnsmasq process
3. Restores interface with `_restore_interface()`:
   - Sets interface to managed mode
   - Re-enables NetworkManager management
4. Cleans up temporary files with `_cleanup_configs()`
5. Prints confirmation message

**Example**:
```python
mgr.stop()
# AP stopped, interface restored, configs removed
```

**Error Handling**:
- All operations are exception-safe (try-except with pass)
- Ensures cleanup even if individual steps fail

---

### Internal Methods

#### `_run(cmd, check=True, capture=False)`

**Purpose**: Execute system command with logging

**Parameters**:
- `cmd` (list[str]): Command and arguments
- `check` (bool): Raise on non-zero exit (default: True)
- `capture` (bool): Capture stdout/stderr (default: False)

**Returns**: `CompletedProcess` object

**Implementation**:
- Prints command to stdout (for debugging)
- Uses `subprocess.run()`
- Optionally captures output

---

#### `_enable_ip_forwarding()`

**Purpose**: Enable kernel IP forwarding

**Implementation**:
- Executes `sysctl -w net.ipv4.ip_forward=1`
- Suppresses errors (best-effort)

---

#### `_enable_nat()`

**Purpose**: Configure iptables NAT rules for internet forwarding

**Implementation**:
1. Enables IP forwarding
2. Adds iptables rules:
   - `POSTROUTING -o {upstream} -j MASQUERADE` (NAT)
   - `FORWARD -i {iface} -o {upstream} -j ACCEPT` (outbound)
   - `FORWARD -i {upstream} -o {iface} -m state --state RELATED,ESTABLISHED -j ACCEPT` (inbound)
3. Sets `_nat_enabled = True`

**Notes**:
- Rules are not idempotent (may add duplicates if called multiple times)
- Only runs if `upstream_iface` is set

---

#### `_disable_nat()`

**Purpose**: Remove iptables NAT rules

**Implementation**:
- Uses `-D` (delete) instead of `-A` (append) for same rules
- Suppresses errors if rules don't exist
- Sets `_nat_enabled = False`

---

#### `_ensure_root()`

**Purpose**: Verify root privileges

**Raises**: `PermissionError` if EUID != 0

---

#### `_check_ap_support()`

**Purpose**: Warn if wireless adapter may not support AP mode

**Implementation**:
- Runs `iw list` and checks for "AP" in supported modes
- Prints warning if not found (doesn't fail)

---

#### `_detect_country_code() -> str`

**Purpose**: Auto-detect regulatory country code

**Returns**: Two-letter country code (default: "US")

**Implementation**:
1. Checks environment variables: `WIFI_COUNTRY`, `COUNTRY_CODE`
2. Parses `iw reg get` output for current regulatory domain
3. Falls back to "US"

**Example Output**: "US", "GB", "DE", etc.

---

#### `_nm_manage(managed: bool)`

**Purpose**: Tell NetworkManager to manage/unmanage interface

**Parameters**:
- `managed` (bool): True to allow NM management, False to prevent

**Implementation**:
- Executes `nmcli device set {iface} managed {yes|no}`
- Suppresses errors if nmcli not installed

---

#### `_prepare_interface()`

**Purpose**: Prepare wireless interface for AP mode

**Implementation**:
1. Checks if interface exists
2. If not found but `{iface}mon` exists (from monitor mode):
   - Converts monitor interface back to managed
   - Renames to base interface name
3. Brings interface down
4. Flushes IP addresses
5. Assigns AP IP address
6. Brings interface up

**Raises**:
- `RuntimeError` if interface not found or recovery fails

---

#### `_write_configs() -> (Path, Path)`

**Purpose**: Generate hostapd and dnsmasq configuration files

**Returns**: Tuple of (hostapd_conf_path, dnsmasq_conf_path)

**Implementation**:
1. Creates temporary directory with `tempfile.mkdtemp()`
2. Generates hostapd.conf with:
   - Interface, SSID, channel
   - Hardware mode (auto-selected based on channel: >14 = 5GHz 'a', else 2.4GHz 'g')
   - WPA2-PSK security (CCMP/AES)
   - Regulatory domain settings (country code, 802.11d/h)
   - Optional: custom BSSID, beacon interval, vendor IEs
3. Generates dnsmasq.conf with:
   - Interface binding
   - Disabled DNS (port=0)
   - DHCP range and lease time
   - Gateway and DNS server options (1.1.1.1, 8.8.8.8)
4. Sets file permissions to world-readable (for debugging)

**hostapd.conf Example**:
```
interface=wlan0
driver=nl80211
ssid=TestAP
hw_mode=g
channel=6
ieee80211n=1
wmm_enabled=1
auth_algs=1
ignore_broadcast_ssid=0
country_code=US
ieee80211d=1
ieee80211h=1
wpa=2
wpa_passphrase=password123
wpa_key_mgmt=WPA-PSK
ieee80211w=0
wpa_pairwise=CCMP
rsn_pairwise=CCMP
ap_isolate=0
beacon_int=100
bssid=aa:bb:cc:dd:ee:ff
vendor_elements=deadbeefcafebabe
```

**dnsmasq.conf Example**:
```
interface=wlan0
bind-interfaces
port=0
dhcp-range=192.168.50.10,192.168.50.100,12h
dhcp-authoritative
dhcp-option=3,192.168.50.1
dhcp-option=6,1.1.1.1,8.8.8.8
```

---

#### `_start_services(hostapd_conf: Path, dnsmasq_conf: Path)`

**Purpose**: Launch hostapd and dnsmasq subprocesses

**Parameters**:
- `hostapd_conf` (Path): Path to hostapd configuration
- `dnsmasq_conf` (Path): Path to dnsmasq configuration

**Raises**:
- `RuntimeError` if either service fails to start

**Implementation**:
1. Starts hostapd with `subprocess.Popen()`
2. Waits 0.5s and checks if still running
3. If exited: captures stderr, writes logs to tmpdir, raises error
4. Starts dnsmasq similarly
5. Stores process handles

---

#### `_stop_services()`

**Purpose**: Terminate hostapd and dnsmasq processes

**Implementation**:
- For each process:
  - Skip if None
  - If still running: send SIGTERM
  - Wait up to 3 seconds
  - If still alive: send SIGKILL
- Sets process handles to None

---

#### `_restore_interface()`

**Purpose**: Return interface to managed mode and NetworkManager control

**Implementation**:
1. Brings interface down
2. Sets type to managed with `iw {iface} set type managed`
3. Brings interface up
4. Re-enables NetworkManager management

**Error Handling**:
- All commands use `check=False` (best-effort)

---

#### `_cleanup_configs()`

**Purpose**: Remove temporary configuration directory

**Implementation**:
- Uses `shutil.rmtree()` with `ignore_errors=True`
- Sets `_tmpdir` to None

---

## Module-Level Functions

### `start_ap(iface, ssid, password, ap_ip="192.168.50.1/24", dhcp_start="192.168.50.10", dhcp_end="192.168.50.100", channel=6, upstream_iface=None, hw_mode="g", beacon_ies=None, beacon_int=None, bssid=None) -> APManager`

**Purpose**: Convenience function to create and start an AP in one call

**Parameters**: Same as `APManager.__init__()`

**Returns**: `APManager` instance (already started)

**Example**:
```python
from ap_manager import start_ap

# Start AP with internet forwarding
mgr = start_ap(
    iface="wlan0",
    ssid="GuestNetwork",
    password="welcome123",
    channel=11,
    upstream_iface="eth0"
)

# ... AP is now running ...

# Stop when done
mgr.stop()
```

---

## Usage Examples

### Basic AP
```python
from ap_manager import APManager

mgr = APManager("wlan0", "MyTestAP", "testpass123")
mgr.start()

input("Press Enter to stop AP...")
mgr.stop()
```

### AP with Internet Forwarding
```python
mgr = APManager(
    iface="wlan0",
    ssid="PublicWiFi",
    passphrase="password123",
    upstream_iface="eth0",  # Forward to ethernet
    channel=6
)
mgr.start()
# Clients can now access internet through AP
```

### Cloning Existing AP
```python
from scanner import scan_aps
from ap_manager import start_ap

# Scan for target
aps = scan_aps("wlan0mon", timeout=10)
target_bssid = "aa:bb:cc:dd:ee:ff"
target_info = aps[target_bssid]

# Clone with same characteristics
mgr = start_ap(
    iface="wlan0",
    ssid=target_info['ssid'],
    password="password123",
    channel=target_info['channel'],
    beacon_ies=target_info['ies_hex'],
    beacon_int=target_info['beacon_int'],
    bssid=target_bssid,  # Spoof BSSID
    upstream_iface="eth0"
)
```

### Custom IP Range
```python
mgr = APManager(
    iface="wlan0",
    ssid="CustomAP",
    passphrase="secure_pass",
    ap_ip="10.0.0.1/24",
    dhcp_start="10.0.0.100",
    dhcp_end="10.0.0.200"
)
mgr.start()
```

---

## Beacon Customization

The module supports advanced beacon customization for AP cloning:

### Custom Beacon Interval
```python
mgr = APManager(
    "wlan0", "TestAP", "pass123",
    beacon_int=100  # milliseconds
)
```

### Custom BSSID
```python
mgr = APManager(
    "wlan0", "TestAP", "pass123",
    bssid="aa:bb:cc:dd:ee:ff"  # MAC to advertise
)
```

### Vendor Information Elements
```python
# Hex string of vendor IEs to include in beacons
vendor_ies = "dd0900037f01010000ff7f"  # Example WMM IE
mgr = APManager(
    "wlan0", "TestAP", "pass123",
    beacon_ies=vendor_ies
)
```

**Note**: Only vendor-specific IEs (ID=221/0xDD) should be included in `beacon_ies`. Other IE types are auto-generated by hostapd.

---

## Troubleshooting

### hostapd Fails to Start

**Symptom**: `RuntimeError: hostapd failed to start`

**Common Causes**:
1. Interface doesn't support AP mode
2. Interface still in monitor mode
3. hostapd already running
4. Invalid configuration

**Solutions**:
```bash
# Check AP support
iw list | grep -A 10 "Supported interface modes"

# Kill existing hostapd
sudo killall hostapd

# Manually reset interface
sudo ip link set wlan0 down
sudo iw wlan0 set type managed
sudo ip link set wlan0 up

# Check logs in tmpdir (printed in error message)
cat /tmp/pyap_xyz/hostapd.stderr.log
```

### dnsmasq Fails to Start

**Symptom**: `RuntimeError: dnsmasq failed to start`

**Common Causes**:
1. Port 67 (DHCP) already in use
2. Another DHCP server running
3. Invalid IP range

**Solutions**:
```bash
# Check for conflicting services
sudo systemctl stop dnsmasq
sudo killall dnsmasq

# Verify no other DHCP servers
sudo netstat -ulnp | grep :67
```

### Interface Not Found

**Symptom**: `RuntimeError: Wireless interface 'wlan0' not found`

**Solutions**:
```bash
# List interfaces
ip link show
iw dev

# If in monitor mode (wlan0mon), stop it first
sudo airmon-ng stop wlan0mon

# Or use the monitor interface name directly
# APManager will auto-recover
```

### NAT Not Working

**Symptom**: Clients can't access internet

**Solutions**:
```bash
# Verify IP forwarding
sysctl net.ipv4.ip_forward

# Check iptables rules
sudo iptables -t nat -L -n -v
sudo iptables -L FORWARD -n -v

# Manually enable forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Add masquerade rule
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

### Permission Denied

**Symptom**: `PermissionError: This script must be run as root`

**Solution**:
```bash
# Run with sudo
sudo python3 your_script.py

# Or use sudo -E to preserve environment
sudo -E .venv/bin/python your_script.py
```

---

## Security Considerations

### Passphrase Requirements
- Minimum 8 characters (WPA2 requirement)
- Maximum 63 characters
- Avoid dictionary words
- Use strong passphrases for production

### BSSID Spoofing
- Changing MAC address may not work on all hardware
- Some drivers don't support MAC override
- Intel chipsets often require specific firmware versions

### Beacon Injection
- Custom vendor IEs can be detected by intrusion detection systems
- Only use in controlled lab environments
- May violate FCC Part 15 regulations if used maliciously

### NAT Security
- No firewall rules beyond basic forwarding
- All AP clients can access upstream network
- Consider adding restrictive iptables rules for production

---

## Performance Considerations

### Channel Selection
- 2.4GHz: Channels 1, 6, 11 are non-overlapping (best choice)
- 5GHz: More non-overlapping channels available
- Use site survey to avoid congestion

### Hardware Mode
- 'g' mode: 2.4GHz, compatible but slower
- 'a' mode: 5GHz, faster but shorter range
- Enable 802.11n for better throughput (already included)
- 802.11ac requires 5GHz ('a' mode with channel >14)

### DHCP Pool Size
- Default: 90 addresses (10-100)
- Increase for more clients
- Decrease for tighter IP management

### Process Management
- hostapd and dnsmasq run as separate processes
- Monitor with `ps aux | grep -E 'hostapd|dnsmasq'`
- Resource usage is minimal (<1% CPU, ~10MB RAM each)

---

## Related Modules

- **scanner.py**: Provides AP scanning for cloning targets
- **mitm_attack.py**: Uses APManager for MITM attacks
- **gui.py**: GUI wrapper for APManager
