"""
Historian

Maintains rolling time windows of traffic data for baseline comparison.
Tracks 1-minute, 5-minute, and 30-minute rolling windows.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from collections import defaultdict
import time


@dataclass
class TrafficWindow:
    """A snapshot of traffic during a time window."""

    timestamp: float
    duration_seconds: int
    total_bytes: float = 0.0
    total_packets: int = 0
    unique_ips: int = 0
    unique_protocols: set = field(default_factory=set)
    ip_bandwidth: Dict[str, float] = field(default_factory=dict)
    ip_packet_counts: Dict[str, int] = field(default_factory=dict)
    protocol_bytes: Dict[str, float] = field(default_factory=dict)
    dns_query_count: int = 0
    top_ips: List[tuple] = field(default_factory=list)  # [(ip, bytes), ...]

    def get_avg_bandwidth(self) -> float:
        """Get average bandwidth in this window."""
        if self.duration_seconds > 0:
            return self.total_bytes / self.duration_seconds
        return 0.0

    def get_packet_rate(self) -> float:
        """Get average packet rate (packets per second)."""
        if self.duration_seconds > 0:
            return self.total_packets / self.duration_seconds
        return 0.0


class Historian:
    """Maintains rolling time windows of traffic data."""

    def __init__(self):
        """Initialize historian with rolling windows."""
        self.windows_1min: List[TrafficWindow] = []
        self.windows_5min: List[TrafficWindow] = []
        self.windows_30min: List[TrafficWindow] = []

        # Current window being accumulated
        self.current_window_start = time.time()
        self.current_ip_data: Dict[str, Dict] = defaultdict(
            lambda: {"bytes": 0, "packets": 0, "protocols": set()}
        )
        self.current_protocol_data: Dict[str, float] = defaultdict(float)
        self.current_total_bytes = 0.0
        self.current_total_packets = 0
        self.current_dns_queries = 0

        # Configuration
        self.min_window_seconds = 60  # Minimum window duration

    def record_packet(
        self,
        src_ip: str,
        protocol: str,
        size: int,
        is_dns: bool = False,
    ) -> None:
        """
        Record a packet in the current accumulation window.

        Args:
            src_ip: Source IP address
            protocol: Protocol name
            size: Packet size in bytes
            is_dns: Whether this is a DNS query
        """
        self.current_ip_data[src_ip]["bytes"] += size
        self.current_ip_data[src_ip]["packets"] += 1
        self.current_ip_data[src_ip]["protocols"].add(protocol)

        self.current_protocol_data[protocol] += size
        self.current_total_bytes += size
        self.current_total_packets += 1

        if is_dns:
            self.current_dns_queries += 1

    def finalize_window(self, window_duration: int = 60) -> Optional[TrafficWindow]:
        """
        Finalize current window and create a snapshot.

        Args:
            window_duration: Seconds since window start

        Returns:
            TrafficWindow snapshot
        """
        if window_duration < self.min_window_seconds:
            return None

        # Calculate top IPs
        ip_bandwidth = [
            (ip, data["bytes"])
            for ip, data in self.current_ip_data.items()
        ]
        ip_bandwidth.sort(key=lambda x: x[1], reverse=True)

        window = TrafficWindow(
            timestamp=self.current_window_start + window_duration,
            duration_seconds=window_duration,
            total_bytes=self.current_total_bytes,
            total_packets=self.current_total_packets,
            unique_ips=len(self.current_ip_data),
            unique_protocols=set(self.current_protocol_data.keys()),
            ip_bandwidth={
                ip: data["bytes"] for ip, data in self.current_ip_data.items()
            },
            ip_packet_counts={
                ip: data["packets"]
                for ip, data in self.current_ip_data.items()
            },
            protocol_bytes=dict(self.current_protocol_data),
            dns_query_count=self.current_dns_queries,
            top_ips=ip_bandwidth[:10],
        )

        return window

    def push_window(
        self, window: TrafficWindow, bucket_type: str = "1min"
    ) -> None:
        """
        Add window to appropriate bucket.

        Args:
            window: TrafficWindow to store
            bucket_type: "1min", "5min", or "30min"
        """
        if bucket_type == "1min":
            self.windows_1min.append(window)
            # Keep last 60 windows (1 hour)
            if len(self.windows_1min) > 60:
                self.windows_1min.pop(0)

        elif bucket_type == "5min":
            self.windows_5min.append(window)
            # Keep last 12 windows (1 hour)
            if len(self.windows_5min) > 12:
                self.windows_5min.pop(0)

        elif bucket_type == "30min":
            self.windows_30min.append(window)
            # Keep last 48 windows (1 day)
            if len(self.windows_30min) > 48:
                self.windows_30min.pop(0)

    def reset_current_window(self) -> None:
        """Reset current accumulation window."""
        self.current_window_start = time.time()
        self.current_ip_data = defaultdict(
            lambda: {"bytes": 0, "packets": 0, "protocols": set()}
        )
        self.current_protocol_data = defaultdict(float)
        self.current_total_bytes = 0.0
        self.current_total_packets = 0
        self.current_dns_queries = 0

    def get_window_avg(self, bucket_type: str = "1min") -> Dict:
        """
        Get average metrics across windows in bucket.

        Args:
            bucket_type: "1min", "5min", or "30min"

        Returns:
            Dictionary with average metrics
        """
        if bucket_type == "1min":
            windows = self.windows_1min
        elif bucket_type == "5min":
            windows = self.windows_5min
        elif bucket_type == "30min":
            windows = self.windows_30min
        else:
            return {}

        if not windows:
            return {
                "avg_bandwidth": 0,
                "avg_packet_rate": 0,
                "avg_unique_ips": 0,
                "sample_count": 0,
            }

        avg_bandwidth = sum(w.get_avg_bandwidth() for w in windows) / len(
            windows
        )
        avg_packet_rate = sum(w.get_packet_rate() for w in windows) / len(
            windows
        )
        avg_unique_ips = (
            sum(w.unique_ips for w in windows) / len(windows)
        )

        return {
            "avg_bandwidth": avg_bandwidth,
            "avg_packet_rate": avg_packet_rate,
            "avg_unique_ips": avg_unique_ips,
            "sample_count": len(windows),
        }

    def compare_windows(
        self,
        current_window: TrafficWindow,
        bucket_type: str = "1min",
    ) -> Dict:
        """
        Compare current window against historical baseline.

        Args:
            current_window: Current traffic window
            bucket_type: Bucket to compare against ("1min", "5min", "30min")

        Returns:
            Comparison metrics
        """
        hist_avg = self.get_window_avg(bucket_type)

        if hist_avg["sample_count"] == 0:
            return {
                "has_baseline": False,
                "bandwidth_ratio": 1.0,
                "packet_rate_ratio": 1.0,
            }

        bandwidth_ratio = (
            current_window.get_avg_bandwidth()
            / hist_avg["avg_bandwidth"]
            if hist_avg["avg_bandwidth"] > 0
            else 1.0
        )
        packet_rate_ratio = (
            current_window.get_packet_rate()
            / hist_avg["avg_packet_rate"]
            if hist_avg["avg_packet_rate"] > 0
            else 1.0
        )

        return {
            "has_baseline": True,
            "current_bandwidth": current_window.get_avg_bandwidth(),
            "baseline_bandwidth": hist_avg["avg_bandwidth"],
            "bandwidth_ratio": bandwidth_ratio,
            "current_packet_rate": current_window.get_packet_rate(),
            "baseline_packet_rate": hist_avg["avg_packet_rate"],
            "packet_rate_ratio": packet_rate_ratio,
            "current_unique_ips": current_window.unique_ips,
            "baseline_unique_ips": hist_avg["avg_unique_ips"],
        }

    def detect_bandwidth_anomaly(
        self,
        current_window: TrafficWindow,
        threshold_multiplier: float = 2.0,
    ) -> bool:
        """
        Detect if current window exceeds baseline by multiplier.

        Args:
            current_window: Current traffic window
            threshold_multiplier: How many times baseline to trigger

        Returns:
            True if anomaly detected
        """
        comparison = self.compare_windows(current_window, bucket_type="1min")

        if not comparison["has_baseline"]:
            return False

        return comparison["bandwidth_ratio"] > threshold_multiplier

    def get_statistics(self) -> Dict:
        """Get overall historian statistics."""
        return {
            "windows_1min": len(self.windows_1min),
            "windows_5min": len(self.windows_5min),
            "windows_30min": len(self.windows_30min),
            "avg_1min": self.get_window_avg("1min"),
            "avg_5min": self.get_window_avg("5min"),
            "avg_30min": self.get_window_avg("30min"),
        }
