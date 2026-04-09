"""
Insight Engine

Analyzes traffic patterns and generates human-readable insights.
Detects spikes, anomalies, and behavioral patterns.
"""
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional
import statistics
import time


class TimeWindow:
    """Tracks metrics within a time window."""

    def __init__(self, window_size_seconds: int = 60):
        """
        Initialize time window.

        Args:
            window_size_seconds: Window duration in seconds
        """
        self.window_size = window_size_seconds
        self.metrics: deque = deque()

    def add_value(self, value: float, timestamp: Optional[float] = None) -> None:
        """Add value with timestamp."""
        if timestamp is None:
            timestamp = time.time()
        self.metrics.append((timestamp, value))
        self._cleanup()

    def _cleanup(self) -> None:
        """Remove values outside the time window."""
        cutoff_time = time.time() - self.window_size
        while self.metrics and self.metrics[0][0] < cutoff_time:
            self.metrics.popleft()

    def get_values(self) -> List[float]:
        """Get all values in current window."""
        self._cleanup()
        return [v for _, v in self.metrics]

    def get_avg(self) -> float:
        """Get average value in window."""
        values = self.get_values()
        return statistics.mean(values) if values else 0

    def get_max(self) -> float:
        """Get max value in window."""
        values = self.get_values()
        return max(values) if values else 0

    def get_count(self) -> int:
        """Get count of values in window."""
        return len(self.get_values())


class InsightEngine:
    """Generates insights from traffic patterns."""

    def __init__(self, history_minutes: int = 60):
        """
        Initialize insight engine.

        Args:
            history_minutes: How many minutes of history to maintain
        """
        self.history_minutes = history_minutes
        self.bandwidth_window: TimeWindow = TimeWindow(window_size_seconds=3600)
        self.packet_window: TimeWindow = TimeWindow(window_size_seconds=3600)

        # Per-IP tracking
        self.ip_bandwidth: Dict[str, TimeWindow] = defaultdict(
            lambda: TimeWindow(window_size_seconds=600)
        )
        self.ip_packet_count: Dict[str, TimeWindow] = defaultdict(
            lambda: TimeWindow(window_size_seconds=600)
        )
        self.ip_protocols: Dict[str, set] = defaultdict(set)
        self.ip_ports: Dict[str, set] = defaultdict(set)

        # DNS tracking
        self.dns_queries: deque = deque(maxlen=10000)
        self.dns_by_ip: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=1000)
        )

        # Baseline stats (for anomaly detection)
        self.baseline_bandwidth: float = 0
        self.baseline_packet_rate: float = 0
        self.baseline_variance: float = 1.0

    def add_packet(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        dst_port: int,
        size: int,
        dns_query: str = "",
    ) -> None:
        """
        Add packet to insight engine.

        Args:
            src_ip: Source IP
            dst_ip: Destination IP
            protocol: Protocol name
            dst_port: Destination port
            size: Packet size in bytes
            dns_query: DNS query if applicable
        """
        current_time = time.time()

        # Track bandwidth
        self.bandwidth_window.add_value(float(size))
        self.ip_bandwidth[src_ip].add_value(float(size))

        # Track packet count
        self.packet_window.add_value(1.0)
        self.ip_packet_count[src_ip].add_value(1.0)

        # Track protocols and ports
        self.ip_protocols[src_ip].add(protocol)
        if dst_port > 0:
            self.ip_ports[src_ip].add(dst_port)

        # Track DNS
        if dns_query:
            self.dns_queries.append(
                {
                    "query": dns_query,
                    "src_ip": src_ip,
                    "timestamp": current_time,
                }
            )
            self.dns_by_ip[src_ip].append(
                {"query": dns_query, "timestamp": current_time}
            )

    def detect_bandwidth_spike(
        self, threshold_multiplier: float = 2.0
    ) -> Optional[Dict]:
        """
        Detect if current bandwidth exceeds baseline.

        Args:
            threshold_multiplier: How many times baseline to trigger alert

        Returns:
            Insight dict if spike detected
        """
        current_bw = self.bandwidth_window.get_avg()

        if self.baseline_bandwidth == 0:
            return None

        if current_bw > (self.baseline_bandwidth * threshold_multiplier):
            return {
                "type": "bandwidth_spike",
                "description": f"Bandwidth spike detected: {current_bw:.0f} bytes/s (baseline: {self.baseline_bandwidth:.0f} bytes/s)",
                "severity": "HIGH",
                "current_value": current_bw,
                "baseline": self.baseline_bandwidth,
                "increase_percent": ((current_bw / self.baseline_bandwidth) - 1) * 100,
            }

        return None

    def detect_top_bandwidth_consumers(
        self, limit: int = 5
    ) -> List[Dict]:
        """
        Identify IPs consuming most bandwidth.

        Args:
            limit: Max results to return

        Returns:
            List of top consumers
        """
        consumers = []

        for ip, window in self.ip_bandwidth.items():
            avg_bw = window.get_avg()
            if avg_bw > 0:
                consumers.append(
                    {
                        "ip": ip,
                        "avg_bandwidth": avg_bw,
                        "protocol_count": len(self.ip_protocols[ip]),
                        "port_count": len(self.ip_ports[ip]),
                    }
                )

        # Sort by bandwidth
        consumers.sort(key=lambda x: x["avg_bandwidth"], reverse=True)
        return consumers[:limit]

    def detect_unusual_dns_activity(
        self, threshold: int = 50
    ) -> Optional[Dict]:
        """
        Detect unusual DNS query patterns.

        Args:
            threshold: Query count threshold to trigger

        Returns:
            Insight dict if unusual activity detected
        """
        if len(self.dns_queries) < 100:
            return None

        # Get recent queries
        recent = list(self.dns_queries)[-100:]
        query_count = len(recent)

        # Check for DNS flood
        if query_count > threshold:
            unique_queries = len(set(q["query"] for q in recent))
            repeated = query_count - unique_queries

            return {
                "type": "dns_activity",
                "description": f"Unusual DNS activity: {query_count} queries, {unique_queries} unique domains, {repeated} repeated queries",
                "severity": "MEDIUM" if unique_queries < 5 else "LOW",
                "total_queries": query_count,
                "unique_domains": unique_queries,
                "repeated_queries": repeated,
                "repetition_ratio": repeated / query_count if query_count > 0 else 0,
            }

        return None

    def detect_protocol_anomalies(
        self, max_protocols_normal: int = 5
    ) -> List[Dict]:
        """
        Detect IPs using unusual number of protocols.

        Args:
            max_protocols_normal: Normal protocol count threshold

        Returns:
            List of anomalies detected
        """
        anomalies = []

        for ip, protocols in self.ip_protocols.items():
            if len(protocols) > max_protocols_normal:
                anomalies.append(
                    {
                        "type": "protocol_anomaly",
                        "ip": ip,
                        "description": f"{ip} used {len(protocols)} different protocols (normal: 1-{max_protocols_normal})",
                        "severity": "LOW",
                        "protocol_count": len(protocols),
                        "protocols": list(protocols),
                    }
                )

        return anomalies

    def get_top_dns_domains(self, limit: int = 10) -> List[Dict]:
        """
        Get most queried DNS domains.

        Args:
            limit: Max domains to return

        Returns:
            List of (domain, count) tuples
        """
        domain_counts: Dict[str, int] = defaultdict(int)

        for query_obj in self.dns_queries:
            domain_counts[query_obj["query"]] += 1

        top_domains = sorted(
            domain_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:limit]

        return [
            {"domain": domain, "count": count}
            for domain, count in top_domains
        ]

    def generate_insights(self) -> List[Dict]:
        """
        Generate all available insights.

        Returns:
            List of insight dictionaries
        """
        insights = []

        # Bandwidth spike
        spike = self.detect_bandwidth_spike()
        if spike:
            insights.append(spike)

        # Top consumers
        consumers = self.detect_top_bandwidth_consumers(limit=3)
        if consumers:
            insights.append(
                {
                    "type": "top_consumers",
                    "description": f"Top bandwidth consumer: {consumers[0]['ip']} ({consumers[0]['avg_bandwidth']:.0f} bytes/s)",
                    "severity": "INFO",
                    "top_ips": consumers,
                }
            )

        # DNS anomalies
        dns_anomaly = self.detect_unusual_dns_activity()
        if dns_anomaly:
            insights.append(dns_anomaly)

        # Protocol anomalies
        proto_anomalies = self.detect_protocol_anomalies()
        for anomaly in proto_anomalies:
            insights.append(anomaly)

        # Top DNS domains
        top_dns = self.get_top_dns_domains(limit=5)
        if top_dns:
            insights.append(
                {
                    "type": "top_dns",
                    "description": f"Most queried domain: {top_dns[0]['domain']} ({top_dns[0]['count']} queries)",
                    "severity": "INFO",
                    "top_domains": top_dns,
                }
            )

        return insights

    def update_baseline(self) -> None:
        """Update traffic baseline using current window data."""
        bw_values = self.bandwidth_window.get_values()
        if bw_values:
            self.baseline_bandwidth = statistics.mean(bw_values)
            self.baseline_variance = (
                statistics.stdev(bw_values)
                if len(bw_values) > 1
                else 1.0
            )

    def get_stats(self) -> Dict:
        """Get insight engine statistics."""
        return {
            "average_bandwidth": self.bandwidth_window.get_avg(),
            "max_bandwidth": self.bandwidth_window.get_max(),
            "packet_rate": self.packet_window.get_count() / 60,  # per second
            "unique_ips": len(self.ip_bandwidth),
            "unique_dns_domains": len(set(q["query"] for q in self.dns_queries)),
            "baseline_bandwidth": self.baseline_bandwidth,
        }
