# Rogue-AP Developer Documentation

Welcome to the Rogue-AP developer documentation. This directory contains comprehensive technical documentation for all components of the Rogue-AP detection and management system.

## 🚀 Quick Start

**[→ Quick Reference & Function Index](./INDEX.md)** - Start here for fast navigation!

## 📖 Documentation Structure

### Essential Guides
- **[Setup Guide](./SETUP.md)** - Installation, requirements, and how to run the project
- **[Architecture Overview](./ARCHITECTURE.md)** - System architecture and design patterns
- **[Quick Reference](./INDEX.md)** - Function index, use case mapping, and troubleshooting

### Module Documentation
- **[scanner.py](./scanner.md)** - Wireless scanning and deauthentication
- **[ap_manager.py](./ap_manager.md)** - Access Point management with hostapd
- **[client_detector.py](./client_detector.md)** - Client-side rogue AP detection
- **[server_detector.py](./server_detector.md)** - Server-side detection engine
- **[mitm_attack.py](./mitm_attack.md)** - MITM attack implementation
- **[gui.py](./gui.md)** - All three GUI applications (main, client detector, server detector)

## Quick Start

```bash
# Clone and setup
git clone <repo-url>
cd Rogue-AP
python3 -m venv .venv
source .venv/bin/activate
pip install scapy

# Run main GUI (requires root for wireless operations)
sudo .venv/bin/python gui.py

# Run client-side detector
sudo .venv/bin/python gui_client_detector.py

# Run server-side detector
sudo .venv/bin/python gui_server_detector.py
```

## Project Purpose

Rogue-AP is an educational toolkit for:
- Learning wireless security concepts
- Understanding rogue AP detection techniques
- Experimenting with wireless access point management
- Testing network security in controlled lab environments

**⚠️ LEGAL WARNING:** Only use this toolkit on networks you own or have explicit written permission to test. Unauthorized wireless scanning or interference is illegal in most jurisdictions.

## Key Features

1. **Wireless Scanning** - Discover nearby access points with detailed metadata
2. **Rogue AP Detection** - Both client-side and server-side detection engines
3. **AP Management** - Create and manage wireless access points using hostapd
4. **MITM Capabilities** - Educational MITM attack implementations
5. **GUI Applications** - User-friendly interfaces for all major features
6. **Deauthentication** - IEEE 802.11 deauth frame injection

## Technology Stack

- **Language:** Python 3.8+
- **Key Libraries:** Scapy, tkinter, sqlite3
- **System Tools:** hostapd, dnsmasq, airmon-ng, iw, iptables
- **Platform:** Linux with wireless network interface support

## Development Guidelines

### Code Style
- Follow PEP 8 conventions
- Use type hints where practical
- Document all public functions and classes
- Keep functions focused and single-purpose

### Testing
- Always test in isolated lab environments
- Never test on production networks
- Verify wireless interface compatibility
- Test with different hardware/drivers

### Security Considerations
- Requires root privileges for wireless operations
- Handle credentials securely
- Validate all user inputs
- Implement proper error handling

## Contributing

This is an educational project. Contributions should:
- Enhance learning value
- Improve code clarity and documentation
- Add educational features
- Fix bugs and security issues

## License

Educational and research purposes only. See LICENSE file for details.
