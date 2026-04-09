"""
Packet Sniffing Logic
"""
import threading
from scapy.all import sniff, get_if_list
import psutil

from config import WIFI_INTERFACE_HINTS
from packet_parser import PacketParser
from threat_detector import ThreatDetector
from capture_state import CaptureState


class PacketSniffer:
    """Manages packet capture using Scapy."""

    def __init__(self, state: CaptureState):
        """
        Initialize sniffer.

        Args:
            state: CaptureState instance
        """
        self.state = state
        self.threat_detector = ThreatDetector()
        self.parser = PacketParser(self.threat_detector)
        self.running = False
        self.thread = None
        self.interface_name, self.local_ip = self._detect_interface()

    @staticmethod
    def _detect_interface() -> tuple:
        """
        Auto-detect active WiFi interface.

        Returns:
            tuple: (interface_name, local_ip) or (None, None)
        """
        psutil_ifaces = psutil.net_if_addrs()
        psutil_stats = psutil.net_if_stats()

        # Find active interfaces
        active = []
        for name, stats in psutil_stats.items():
            if stats.isup and name in psutil_ifaces:
                addrs = psutil_ifaces[name]
                for addr in addrs:
                    if addr.family == 2:  # AF_INET = IPv4
                        active.append((name, addr.address))

        # Prefer WiFi by name
        for name, ip in active:
            if any(h in name.lower() for h in WIFI_INTERFACE_HINTS):
                print(f"[+] WiFi interface detected: {name} ({ip})")
                return name, ip

        # Fallback — first non-loopback active
        for name, ip in active:
            if not ip.startswith("127."):
                print(f"[+] Using interface: {name} ({ip})")
                return name, ip

        print("[!] No suitable interface found")
        return None, None

    def _packet_callback(self, pkt):
        """
        Callback for each captured packet.

        Args:
            pkt: Scapy packet object
        """
        if not self.running:
            return

        try:
            # Parse packet
            packet = self.parser.parse_packet(pkt)
            if not packet:
                return

            # Detect threats
            alerts = self.threat_detector.detect_threats(pkt, packet.model_dump())

            # Store in state
            self.state.add_packet(packet, alerts, packet.dns_query)

        except Exception as e:
            print(f"[ERROR] Packet callback error: {e}")

    def start(self) -> None:
        """Start packet capture in background thread."""
        if self.running or not self.interface_name:
            return

        self.running = True
        print(f"[+] Starting capture on: {self.interface_name}")

        self.thread = threading.Thread(target=self._sniff_thread, daemon=True)
        self.thread.start()

    def _sniff_thread(self) -> None:
        """Background thread for packet sniffing."""
        try:
            sniff(
                iface=self.interface_name,
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda p: not self.running,
            )
        except Exception as e:
            print(f"[ERROR] Sniff thread error: {e}")
        finally:
            self.running = False

    def stop(self) -> None:
        """Stop packet capture."""
        self.running = False
        print("[+] Capture stopped")

    def is_running(self) -> bool:
        """Check if capture is active."""
        return self.running

    def reset(self) -> None:
        """Reset sniffer state."""
        self.stop()
        self.threat_detector.reset()
        self.parser.reset()
