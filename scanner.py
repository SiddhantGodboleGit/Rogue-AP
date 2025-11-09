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
            ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
            if bssid not in aps:
                aps[bssid] = ssid

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
        for bssid, ssid in aps.items():
            print(f"BSSID: {bssid}, SSID: {ssid}")
    finally:
        stop_monitor_mode(monitor_interface)
            
    selected_ssid = input("\nEnter the SSID of the AP to create a rogue AP: ")
    passphrase = input("Enter the passphrase for the rogue AP: ")
    rogue_ap_manager = start_ap(interface, selected_ssid, passphrase, "192.168.50.1/24", "192.168.50.10", "192.168.50.100", 6, upstream_iface)
    
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
    