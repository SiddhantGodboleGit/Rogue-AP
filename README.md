# Rogue-AP

Rogue-AP is a small Python project for experimenting with wireless access point scanning and basic rogue AP detection techniques. It contains simple tooling (a scanner and an access-point manager) intended for learning and lab use only.

IMPORTANT: This repository is provided for educational purposes. Only use these tools on networks you own or have explicit permission to test. Unauthorized wireless scanning or interference may be illegal in your jurisdiction.

## Contents

- `scanner.py` — script to scan for nearby wireless access points and collect basic information.
- `ap_manager.py` — helper/manager utilities for working with detected APs.
- `client_detector.py` — script used to detect Rogue AP from client-side.

## Requirements

- Python 3.8+ (3.10 or 3.11 recommended)
- A virtual environment (highly recommended)
- hostapd, dnsmasq, Linux with wireless tools / permissions to access wireless interfaces (monitor mode may be required depending on scanner implementation)
- Root privileges for raw interface access (some functionality may require sudo)

## Installation / Setup

1. Clone the repository and change into the project directory:

```bash
git clone <repo-url>
cd Rogue-AP
```

2. Create and activate a virtual environment (recommended):

```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. (Optional) Install any Python dependencies:

```bash
pip install scapy
```

4. Ensure you run scanning commands with the necessary privileges when required (some scanners need root to open raw sockets or put the wireless card into monitor mode):

```bash
# use following command to run the ui for setting up rogue ap
sudo .venv/bin/python gui.py

# use following command to run the ui for client side rogue ap detection
sudo .venv/bin/python gui_client_detector.py
```

## Usage

Basic usage examples using the included scripts:

- Run the scanner (may require sudo):

```bash
sudo .venv/bin/python scanner.py
```

The scanner will print a list of detected access points and basic metadata to stdout. 

## Safety & Legal

Only scan Wi‑Fi networks that you own or where you have explicit permission. Doing otherwise may violate laws and terms of service.
