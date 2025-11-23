# Setup Guide

This guide covers the installation and setup of the Rogue-AP toolkit.

## System Requirements

### Operating System
- Linux (Ubuntu 20.04+, Debian 11+, Arch, or similar)
- Kernel with wireless extensions support
- Root/sudo access

### Hardware
- Wireless network interface that supports:
  - Monitor mode
  - Packet injection
  - AP mode (for access point management)
- Common compatible chipsets:
  - Atheros (ath9k, ath10k)
  - Ralink/MediaTek (rt2800usb, mt76)
  - Realtek (rtl8812au, rtl8188eus)
  - Intel (some models with iwlwifi)

### Software Dependencies

#### Python
- Python 3.8 or newer (3.10+ recommended)
- pip (Python package manager)
- venv module for virtual environments

#### System Packages

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y \
    python3 python3-pip python3-venv \
    hostapd dnsmasq \
    aircrack-ng \
    iw wireless-tools net-tools \
    iptables

# Arch Linux
sudo pacman -S \
    python python-pip \
    hostapd dnsmasq \
    aircrack-ng \
    iw wireless_tools net-tools \
    iptables

# Fedora/RHEL
sudo dnf install -y \
    python3 python3-pip \
    hostapd dnsmasq \
    aircrack-ng \
    iw wireless-tools net-tools \
    iptables
```

#### Python Packages
- `scapy` - Packet manipulation and network scanning
- `tkinter` - GUI framework (usually included with Python)

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/SiddhantGodboleGit/Rogue-AP.git
cd Rogue-AP
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Verify activation (should show .venv path)
which python
```

### 3. Install Python Dependencies

```bash
# Upgrade pip
pip install --upgrade pip

# Install required packages
pip install scapy

# Verify installation
python -c "import scapy; print(scapy.__version__)"
```

### 4. Verify Wireless Interface

```bash
# List wireless interfaces
ip link show
# or
iw dev

# Check if your interface supports monitor mode
iw list | grep -A 10 "Supported interface modes"

# Example output should include:
#   * monitor
#   * AP
```

### 5. Test Monitor Mode (Optional)

```bash
# Replace wlan0 with your interface name
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# Verify monitor interface created
iw dev
# Should show wlan0mon in monitor mode

# Stop monitor mode
sudo airmon-ng stop wlan0mon
```

## Running the Applications

### Main GUI

```bash
# Activate virtual environment if not already active
source .venv/bin/activate

# Run with sudo (required for wireless operations)
sudo .venv/bin/python gui.py
```

### Client-Side Detector GUI

```bash
sudo .venv/bin/python gui_client_detector.py
```

### Server-Side Detector GUI

```bash
sudo .venv/bin/python gui_server_detector.py
```

### Command-Line Scanner

```bash
# Basic scan
sudo .venv/bin/python scanner.py

# The script will prompt for interface name and other parameters
```

## Configuration

### Whitelist Configuration

Create or edit `whitelist.json` in the project root:

```json
{
  "known_ssids": [
    {
      "ssid": "MyNetwork",
      "ouis": ["00:11:22", "33:44:55"]
    }
  ],
  "known_bssids": [
    "aa:bb:cc:dd:ee:ff",
    "11:22:33:44:55:66"
  ]
}
```

### Network Interface Configuration

Edit your interface name in the GUI or pass it as a parameter to command-line tools.

Common interface names:
- `wlan0` - First wireless interface
- `wlan1` - Second wireless interface
- `wlp3s0` - PCI wireless interface (newer naming)

## Troubleshooting

### Interface Not Found
```bash
# List all network interfaces
ip link show

# Check wireless interfaces specifically
iw dev
```

### Permission Denied
```bash
# Ensure you're running with sudo
sudo -E .venv/bin/python gui.py

# Check if user is in necessary groups (alternative to sudo)
sudo usermod -aG netdev $USER
# Log out and back in for group changes to take effect
```

### Monitor Mode Fails
```bash
# Kill interfering processes
sudo airmon-ng check kill

# Manually set monitor mode
sudo ip link set wlan0 down
sudo iw wlan0 set monitor none
sudo ip link set wlan0 up
```

### hostapd Won't Start
```bash
# Check if hostapd is already running
sudo systemctl stop hostapd
sudo killall hostapd

# Verify interface is not in use
sudo airmon-ng check

# Check interface supports AP mode
iw list | grep -A 10 "Supported interface modes"
```

### Dependencies Missing
```bash
# Reinstall system packages
sudo apt install --reinstall hostapd dnsmasq aircrack-ng

# Reinstall Python packages
pip install --force-reinstall scapy
```

### Virtual Environment Issues
```bash
# Remove and recreate virtual environment
deactivate  # if currently active
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
pip install scapy
```

## Performance Tips

1. **Use Compatible Hardware**: Chipsets like Atheros ath9k work best
2. **Stop Network Manager**: May interfere with operations
   ```bash
   sudo systemctl stop NetworkManager
   ```
3. **Disable Power Management**: 
   ```bash
   sudo iwconfig wlan0 power off
   ```
4. **Use 2.4GHz Band**: More widely supported than 5GHz
5. **Close Background Apps**: Free up system resources

## Security Considerations

1. **Run in Isolated Environment**: Use a dedicated test machine or VM
2. **Lab Network Only**: Never use on production networks
3. **Legal Compliance**: Obtain written permission before testing
4. **Secure Storage**: Keep logs and pcap files encrypted
5. **Clean Up**: Remove temporary files and reset interfaces after use

## Uninstallation

```bash
# Stop any running processes
sudo killall hostapd dnsmasq

# Stop monitor mode
sudo airmon-ng stop wlan0mon

# Restart NetworkManager
sudo systemctl start NetworkManager

# Remove virtual environment
deactivate
rm -rf .venv

# Remove project directory
cd ..
rm -rf Rogue-AP
```

## Next Steps

- Read [Architecture Overview](./ARCHITECTURE.md) to understand system design
- Review module documentation for specific components
- Start with [scanner.py](./scanner.md) for basic wireless scanning
- Explore [client_detector.py](./client_detector.md) for rogue AP detection
