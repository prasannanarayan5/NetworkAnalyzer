"""
Capture State Management
"""
import time
import threading
from collections import defaultdict, deque
from typing import Dict, Any, List

from config import (
    MAX_PACKET_BUFFER,
    MAX_BANDWIDTH_HISTORY,
    MAX_ALERTS,
    DNS_QUERY_BUFFER_SIZE,
)
from models import PacketInfo, Alert, BandwidthSnapshot


class CaptureState:
    """Thread-safe capture state management."""

    def __init__(self):
        """Initialize capture state."""
        # Packet buffers
        self.packets = deque(maxlen=MAX_PACKET_BUFFER)
        self.dns_queries = deque(maxlen=DNS_QUERY_BUFFER_SIZE)

        # Statistics
        self.protocol_counts = defaultdict(int)
        self.src_ip_counts = defaultdict(int)
        self.dst_ip_counts = defaultdict(int)
        self.port_counts = defaultdict(int)

        # History
        self.bandwidth_history = deque(maxlen=MAX_BANDWIDTH_HISTORY)
        self.alerts = deque(maxlen=MAX_ALERTS)

        # Counters
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = time.time()

        # Per-second metrics
        self._sec_bytes = 0
        self._sec_pkts = 0
        self._last_tick = time.time()

        # Thread safety
        self.lock = threading.Lock()

    def add_packet(
        self,
        packet: PacketInfo,
        alerts: List[Alert],
        dns_query: str = "",
    ) -> None:
        """
        Add parsed packet to state.

        Args:
            packet: PacketInfo object
            alerts: List of threats detected
            dns_query: DNS query string if applicable
        """
        with self.lock:
            # Store packet
            self.packets.appendleft(packet)

            # Update counters
            self.total_packets += 1
            self.total_bytes += packet.size
            self._sec_bytes += packet.size
            self._sec_pkts += 1

            # Update statistics
            self.protocol_counts[packet.protocol] += 1
            if packet.src_ip != "—":
                self.src_ip_counts[packet.src_ip] += 1
            if packet.dst_ip != "—":
                self.dst_ip_counts[packet.dst_ip] += 1
            if packet.dst_port:
                self.port_counts[packet.dst_port] += 1

            # Store DNS queries
            if dns_query:
                self.dns_queries.appendleft({"query": dns_query, "from": packet.src_ip, "time": packet.timestamp})

            # Store alerts
            for alert in alerts:
                self.alerts.appendleft(alert)

    def snapshot_bandwidth(self) -> BandwidthSnapshot:
        """
        Create bandwidth snapshot for current second.

        Returns:
            BandwidthSnapshot
        """
        with self.lock:
            snap = BandwidthSnapshot(
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
                bytes_per_sec=self._sec_bytes,
                packets_per_sec=self._sec_pkts,
            )
            self.bandwidth_history.append(snap)
            self._sec_bytes = 0
            self._sec_pkts = 0
        return snap

    def get_stats(self) -> Dict[str, Any]:
        """
        Get current statistics.

        Returns:
            Dict with all statistics
        """
        with self.lock:
            uptime = int(time.time() - self.start_time)
            uptime = max(uptime, 1)  # Avoid division by zero

            pps = self.total_packets / uptime
            bps = self.total_bytes / uptime

            top_src = sorted(self.src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            top_dst = sorted(self.dst_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            top_ports = sorted(self.port_counts.items(), key=lambda x: x[1], reverse=True)[:10]

            # Convert tuples to dicts for JSON serialization
            top_src_list = [{"ip": ip, "count": count} for ip, count in top_src]
            top_dst_list = [{"ip": ip, "count": count} for ip, count in top_dst]
            top_ports_list = [{"port": port, "count": count} for port, count in top_ports]

            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "uptime": uptime,
                "pps": round(pps, 2),
                "bps": round(bps, 2),
                "protocol_distribution": dict(self.protocol_counts),
                "top_src_ips": top_src_list,
                "top_dest_ips": top_dst_list,  # Use "dest" not "dst" for consistency
                "top_ports": top_ports_list,
                "alerts_count": len(self.alerts),
            }

    def get_recent_packets(self, limit: int = 100, protocol: str = "ALL") -> List[Dict]:
        """
        Get recent packets with optional filtering.

        Args:
            limit: Max packets to return
            protocol: Filter by protocol or 'ALL'

        Returns:
            List of packet dicts
        """
        with self.lock:
            pkts = list(self.packets)

        if protocol != "ALL":
            pkts = [p for p in pkts if p.protocol == protocol]

        return [p.model_dump() for p in pkts[:limit]]

    def get_recent_packets_raw(self, limit: int = 100, protocol: str = "ALL") -> List[PacketInfo]:
        """
        Get recent packets as PacketInfo objects (internal use).

        Args:
            limit: Max packets to return
            protocol: Filter by protocol or 'ALL'

        Returns:
            List of PacketInfo objects
        """
        with self.lock:
            pkts = list(self.packets)

        if protocol != "ALL":
            pkts = [p for p in pkts if p.protocol == protocol]

        return pkts[:limit]

    def get_recent_alerts(self, limit: int = 100) -> List[Dict]:
        """
        Get recent alerts.

        Args:
            limit: Max alerts to return

        Returns:
            List of alert dicts
        """
        with self.lock:
            alerts = list(self.alerts)[:limit]
        # Alerts are stored as dicts from threat_detector, return directly
        result = []
        for a in alerts:
            if isinstance(a, dict):
                result.append(a)
            elif hasattr(a, 'model_dump'):
                result.append(a.model_dump())
            else:
                # Fallback for other types
                result.append(a if isinstance(a, dict) else {"message": str(a)})
        return result

    def get_dns_queries(self, limit: int = 30) -> List[Dict]:
        """
        Get recent DNS queries.

        Args:
            limit: Max queries to return

        Returns:
            List of DNS query dicts
        """
        with self.lock:
            queries = list(self.dns_queries)[:limit]
        return queries

    def get_bandwidth_history(self) -> List[Dict]:
        """
        Get bandwidth history.

        Returns:
            List of bandwidth snapshots
        """
        with self.lock:
            return [snap.model_dump() for snap in self.bandwidth_history]

    def reset(self) -> None:
        """Reset all capture state."""
        with self.lock:
            self.packets.clear()
            self.dns_queries.clear()
            self.protocol_counts.clear()
            self.src_ip_counts.clear()
            self.dst_ip_counts.clear()
            self.port_counts.clear()
            self.bandwidth_history.clear()
            self.alerts.clear()
            self.total_packets = 0
            self.total_bytes = 0
            self.start_time = time.time()
            self._sec_bytes = 0
            self._sec_pkts = 0
