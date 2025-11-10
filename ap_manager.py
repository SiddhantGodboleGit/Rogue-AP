import os
import subprocess
import tempfile
import time
import signal
import shutil
from pathlib import Path
from typing import Optional


class APManager:
    """Manage a temporary AP on a wireless interface using hostapd + dnsmasq.

    Usage:
        mgr = APManager("wlan0", "MySSID", "SecretPass", upstream_iface="eth0")
        mgr.start()
        # ... later
        mgr.stop()
    """

    def __init__(self,
                 iface: str,
                 ssid: str,
                 passphrase: str,
                 ap_ip: str = "192.168.50.1/24",
                 dhcp_start: str = "192.168.50.10",
                 dhcp_end: str = "192.168.50.100",
                 channel: int = 6,
                 hw_mode: str = "g",
                 upstream_iface: Optional[str] = None,
                 # Optional beacon customization: raw IEs to include in beacon (hex string),
                 # requested beacon interval (ms) and bssid to advertise.
                 beacon_ies: Optional[str] = None,
                 beacon_int: Optional[int] = None,
                 bssid: Optional[str] = None):
        self.iface = iface
        self.ssid = ssid
        self.passphrase = passphrase
        self.ap_ip = ap_ip
        self.dhcp_start = dhcp_start
        self.dhcp_end = dhcp_end
        self.channel = channel
        self.hw_mode = hw_mode
        self.upstream_iface = upstream_iface
        # Beacon customization stored as strings/values that will be written
        # into hostapd.conf if provided.
        self._beacon_ies = beacon_ies
        self._beacon_int = beacon_int
        self._bssid = bssid

        self._tmpdir: Optional[Path] = None
        self._hostapd_proc: Optional[subprocess.Popen] = None
        self._dnsmasq_proc: Optional[subprocess.Popen] = None
        self._nat_enabled = False

    # ------------------ Utility subprocess wrapper ------------------
    def _run(self, cmd, check=True, capture=False):
        print("$", " ".join(cmd))
        return subprocess.run(cmd, check=check,
                              stdout=(subprocess.PIPE if capture else None),
                              stderr=(subprocess.PIPE if capture else None))

    # ------------------ NAT / forwarding helpers ------------------
    def _enable_ip_forwarding(self):
        try:
            self._run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)
        except Exception:
            pass

    def _enable_nat(self):
        """Enable simple IPv4 NAT/masquerade from the AP subnet to upstream_iface.
        This is a simple implementation intended for temporary/lab use."""
        if not self.upstream_iface:
            return
        self._enable_ip_forwarding()
        # Add iptables rules (no idempotence checks here)
        try:
            self._run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-o",
                       self.upstream_iface, "-j", "MASQUERADE"], check=False)
            self._run(["iptables", "-A", "FORWARD", "-i", self.iface, "-o",
                       self.upstream_iface, "-j", "ACCEPT"], check=False)
            self._run(["iptables", "-A", "FORWARD", "-i", self.upstream_iface, "-o",
                       self.iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"], check=False)
            self._nat_enabled = True
        except Exception as e:
            print("Failed to enable NAT:", e)

    def _disable_nat(self):
        if not self.upstream_iface or not self._nat_enabled:
            return
        try:
            self._run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-o",
                       self.upstream_iface, "-j", "MASQUERADE"], check=False)
            self._run(["iptables", "-D", "FORWARD", "-i", self.iface, "-o",
                       self.upstream_iface, "-j", "ACCEPT"], check=False)
            self._run(["iptables", "-D", "FORWARD", "-i", self.upstream_iface, "-o",
                       self.iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"], check=False)
        except Exception as e:
            print("Failed to disable NAT (rules may not exist):", e)
        finally:
            self._nat_enabled = False

    # ------------------ Setup / Teardown steps ------------------
    def _ensure_root(self):
        if os.geteuid() != 0:
            raise PermissionError("This script must be run as root.")

    def _check_ap_support(self):
        try:
            out = self._run(["iw", "list"], capture=True)
            if b"AP" not in out.stdout:
                print("WARNING: 'iw list' did not show AP mode. The adapter may not support AP mode.")
        except FileNotFoundError:
            print("WARNING: 'iw' not installed or not found in PATH.")

    def _nm_manage(self, managed: bool):
        # Try to tell NetworkManager to stop managing this interface. Not fatal if nmcli missing.
        try:
            val = "yes" if managed else "no"
            self._run(["nmcli", "device", "set", self.iface, "managed", val], check=False)
        except FileNotFoundError:
            pass

    def _prepare_interface(self):
        # Bring interface down, set to AP type, assign static IP, bring up
        self._run(["ip", "link", "set", self.iface, "down"], check=False)
        # Let hostapd manage the interface mode (nl80211/driver). Manually
        # setting the interface to 'ap' can produce noisy kernel messages and
        # is not required when hostapd is used.
        self._run(["ip", "addr", "flush", "dev", self.iface], check=False)
        self._run(["ip", "addr", "add", self.ap_ip, "dev", self.iface], check=True)
        self._run(["ip", "link", "set", self.iface, "up"], check=True)

    def _write_configs(self):
        self._tmpdir = Path(tempfile.mkdtemp(prefix="pyap_"))
        hostapd_conf = self._tmpdir / "hostapd.conf"
        dnsmasq_conf = self._tmpdir / "dnsmasq.conf"

        # Build hostapd configuration, optionally adding beacon-related
        # settings so hostapd will include the original AP's information
        # elements in its beacons.
        hostapd_lines = [
            f"interface={self.iface}",
            "driver=nl80211",
            f"ssid={self.ssid}",
            f"hw_mode={self.hw_mode}",
            f"channel={self.channel}",
            "ieee80211n=1",
            "wmm_enabled=1",
            "auth_algs=1",
            "ignore_broadcast_ssid=0",
            "wpa=2",
            f"wpa_passphrase={self.passphrase}",
            "wpa_key_mgmt=WPA-PSK",
            "rsn_pairwise=CCMP",
        ]

        # If the caller provided a beacon interval, bssid or raw IEs
        # (hex string), add appropriate hostapd config keys. hostapd's
        # `vendor_elements` takes a hex string of IEs to include in
        # beacons and related frames.
        if self._beacon_int is not None:
            hostapd_lines.append(f"beacon_int={int(self._beacon_int)}")
        if self._bssid:
            hostapd_lines.append(f"bssid={self._bssid}")
        if self._beacon_ies:
            # Ensure it's a hex string without 0x prefix and lower-case
            ie_hex = self._beacon_ies.lower().lstrip("0x")
            hostapd_lines.append(f"vendor_elements={ie_hex}")

        hostapd_conf.write_text("\n".join(hostapd_lines))

        dnsmasq_conf.write_text(f"""
interface={self.iface}
dhcp-range={self.dhcp_start},{self.dhcp_end},12h
bind-interfaces
""".strip())

        # Make the config directory and files world-readable so a non-root
        # user can inspect them after this script runs with sudo. This
        # is primarily for debugging; it's safe for temporary files.
        try:
            self._tmpdir.chmod(0o755)
            hostapd_conf.chmod(0o644)
            dnsmasq_conf.chmod(0o644)
        except Exception:
            # Ignore permission errors when not running as root or on
            # platforms that don't support chmod the same way.
            pass

        return hostapd_conf, dnsmasq_conf

    def _start_services(self, hostapd_conf: Path, dnsmasq_conf: Path):
        # Start hostapd first and ensure it actually started. If hostapd
        # fails immediately the stderr will usually contain a helpful error
        # message (missing driver support, configuration error, etc.).
        self._hostapd_proc = subprocess.Popen(["hostapd", str(hostapd_conf)],
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.5)
        # If hostapd exited quickly, capture stderr and raise an informative
        # error so callers (or an interactive user) can see why it failed.
        if self._hostapd_proc.poll() is not None:
            out = b""
            err = b""
            try:
                if self._hostapd_proc.stdout:
                    out = self._hostapd_proc.stdout.read()
                if self._hostapd_proc.stderr:
                    err = self._hostapd_proc.stderr.read()
            except Exception:
                pass

            # If we have a tempdir, write these logs there for inspection.
            saved = None
            try:
                if self._tmpdir:
                    saved = self._tmpdir
                    (self._tmpdir / "hostapd.stdout.log").write_bytes(out or b"")
                    (self._tmpdir / "hostapd.stderr.log").write_bytes(err or b"")
            except Exception:
                saved = saved or None

            msg = (err.decode(errors="ignore").strip() or out.decode(errors="ignore").strip())
            if saved:
                raise RuntimeError(f"hostapd failed to start: {msg}\nLogs written to: {saved}")
            else:
                raise RuntimeError(f"hostapd failed to start: {msg}")

        # Start dnsmasq after hostapd is running
        self._dnsmasq_proc = subprocess.Popen(["dnsmasq", "-C", str(dnsmasq_conf), "--no-daemon"],
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def _stop_services(self):
        for p in (self._hostapd_proc, self._dnsmasq_proc):
            if p is None:
                continue
            if p.poll() is None:
                try:
                    p.terminate()
                    p.wait(timeout=3)
                except Exception:
                    p.kill()
        self._hostapd_proc = None
        self._dnsmasq_proc = None

    def _restore_interface(self):
        # Try to restore the interface to managed mode
        self._run(["ip", "link", "set", self.iface, "down"], check=False)
        self._run(["iw", self.iface, "set", "type", "managed"], check=False)
        self._run(["ip", "link", "set", self.iface, "up"], check=False)
        # Re-enable NetworkManager management
        self._nm_manage(True)

    def _cleanup_configs(self):
        if self._tmpdir and self._tmpdir.exists():
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None

    # ------------------ Public API ------------------
    def start(self):
        """Start the AP. Raises on fatal errors."""
        self._ensure_root()
        self._check_ap_support()
        # try to un-manage interface from NetworkManager
        self._nm_manage(False)
        self._prepare_interface()
        hostapd_conf, dnsmasq_conf = self._write_configs()
        print("Wrote configs to:", hostapd_conf.parent)
        self._start_services(hostapd_conf, dnsmasq_conf)
        # enable NAT if upstream provided
        if self.upstream_iface:
            print(f"Enabling NAT forwarding via {self.upstream_iface}")
            self._enable_nat()
        print("AP should be up. Use stop() to terminate and cleanup.")

    def stop(self):
        """Stop the AP and clean up everything we changed."""
        # disable NAT before tearing down services/interfaces
        try:
            if self._nat_enabled:
                print("Disabling NAT rules")
                self._disable_nat()
        except Exception:
            pass

        self._stop_services()
        self._restore_interface()
        self._cleanup_configs()
        print("AP stopped and cleaned up.")


# ------------------ Convenience functions for script-style usage ------------------

def start_ap(iface: str, ssid: str, password: str,
             ap_ip: str = "192.168.50.1/24",
             dhcp_start: str = "192.168.50.10",
             dhcp_end: str = "192.168.50.100",
             channel: int = 6,
             upstream_iface: Optional[str] = None,
             hw_mode: str = "g",
             # Optional beacon customization
             beacon_ies: Optional[str] = None,
             beacon_int: Optional[int] = None,
             bssid: Optional[str] = None) -> APManager:
    """Create an APManager, start it and return the manager object for later stop()."""
    mgr = APManager(iface, ssid, password, ap_ip, dhcp_start, dhcp_end,
                    channel, hw_mode, upstream_iface,
                    beacon_ies=beacon_ies, beacon_int=beacon_int, bssid=bssid)
    mgr.start()
    return mgr