"""
Threat Detection Logic
"""
from datetime import datetime
from typing import List, Dict, Any, Optional
from collections import defaultdict
import time

from config import (
    SENSITIVE_PORTS,
    PORT_SCAN_THRESHOLD,
    ICMP_FLOOD_THRESHOLD,
    ICMP_FLOOD_WINDOW,
    PACKET_SIZE_ANOMALY,
)
from models import Alert
from rules import RuleEngine, Severity
from aggregator import AlertAggregator


class ThreatDetector:
    """Detects security threats in network traffic."""

    def __init__(self, use_rule_engine: bool = True):
        """
        Initialize threat detector with tracking structures.

        Args:
            use_rule_engine: Whether to use new rule engine (production) or legacy detection
        """
        self.ip_ports = defaultdict(set)  # src_ip → set of dst_ports
        self.icmp_count = defaultdict(int)  # src_ip → packet count
        self.icmp_window_start = time.time()

        # Production features
        self.use_rule_engine = use_rule_engine
        if use_rule_engine:
            self.rule_engine: RuleEngine = RuleEngine()
            self.aggregator: AlertAggregator = AlertAggregator()
            self._setup_rule_engine()

    def _setup_rule_engine(self) -> None:
        """Configure rule engine with production rules."""
        engine = self.rule_engine

        # Rule: Port scanning
        engine.register_rule(
            rule_id="port_scan",
            name="Port Scan Detected",
            description="Source IP probed multiple ports",
            severity=Severity.HIGH,
            detector=lambda ctx: ctx.get("unique_ports", 0)
            > PORT_SCAN_THRESHOLD,
            cooldown=300,
        )

        # Rule: ICMP flood
        engine.register_rule(
            rule_id="icmp_flood",
            name="ICMP Flood Attack",
            description="Excessive ICMP packets from single source",
            severity=Severity.MEDIUM,
            detector=lambda ctx: ctx.get("icmp_pps", 0) > ICMP_FLOOD_THRESHOLD,
            cooldown=120,
        )

        # Rule: Abnormal packet size
        # ⚠️ DISABLED: Too many false positives
        # Normal packets range from 20 bytes (SYN) to 1500 bytes (MTU)
        # Disabling because packet size alone is not a reliable threat indicator
        # engine.register_rule(
        #     rule_id="packet_size_anomaly",
        #     name="Abnormal Packet Size",
        #     description="Packet size outside normal range",
        #     severity=Severity.LOW,
        #     detector=lambda ctx: (
        #         ctx.get("size", 0) < 20 or ctx.get("size", 0) > PACKET_SIZE_ANOMALY
        #     ),
        #     cooldown=60,
        # )

        # Rule: Insecure Telnet
        engine.register_rule(
            rule_id="insecure_telnet",
            name="Insecure Telnet Connection",
            description="Plaintext Telnet credential transmission detected",
            severity=Severity.HIGH,
            detector=lambda ctx: ctx.get("dst_port", 0) == 23,
            cooldown=600,
        )

        # Rule: Sensitive port access (SMART VERSION)
        # Only alert if multiple sensitive ports are being accessed (suggesting a scan)
        # NOT on every connection to SSH/RDP (false positive)
        def suspicious_sensitive_ports(ctx):
            # Only trigger if: multiple sensitive ports from same IP + port scanning pattern
            port = ctx.get("dst_port", 0)
            unique_ports = ctx.get("unique_ports", 0)
            # Only trigger if accessing MULTIPLE sensitive ports (3+) = suspicious
            return port in SENSITIVE_PORTS and unique_ports >= 3
        
        engine.register_rule(
            rule_id="suspicious_remote_access",
            name="Suspicious Remote Access Pattern",
            description="Multiple sensitive ports accessed from same source",
            severity=Severity.MEDIUM,
            detector=suspicious_sensitive_ports,
            cooldown=300,  # 5 minute cooldown
        )

    def detect_threats(
        self, pkt: Any, parsed: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Analyze packet for threats using configured detection method.

        Args:
            pkt: Scapy packet object
            parsed: Parsed packet dict

        Returns:
            List of alert dictionaries
        """
        if self.use_rule_engine:
            return self._detect_threats_rules(pkt, parsed)
        else:
            return self._detect_threats_legacy(pkt, parsed)

    def _detect_threats_rules(
        self, pkt: Any, parsed: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Detect threats using rule engine.

        Args:
            pkt: Scapy packet object
            parsed: Parsed packet dict

        Returns:
            List of aggregated alert dictionaries
        """
        alerts = []
        src = parsed.get("src_ip", "")
        proto = parsed.get("protocol", "")
        dst_port = parsed.get("dst_port", 0)
        size = parsed.get("size", 0)
        timestamp = parsed.get("timestamp", datetime.now().isoformat())

        # Update tracking for port scans
        if src and dst_port:
            self.ip_ports[src].add(dst_port)

        # Update ICMP tracking
        if proto == "ICMP":
            now = time.time()
            if now - self.icmp_window_start > ICMP_FLOOD_WINDOW:
                self.icmp_count.clear()
                self.icmp_window_start = now
            self.icmp_count[src] += 1

        # Create context for rule evaluation
        context = {
            "src_ip": src,
            "dst_port": dst_port,
            "protocol": proto,
            "size": size,
            "timestamp": timestamp,
            "unique_ports": len(self.ip_ports[src]),
            "icmp_pps": (
                self.icmp_count[src] / ICMP_FLOOD_WINDOW
                if proto == "ICMP"
                else 0
            ),
        }

        # Execute rules
        rule_alerts = self.rule_engine.check_rules(context)

        # Aggregate alerts to prevent duplicates
        for alert in rule_alerts:
            agg_alert = self.aggregator.add_alert(alert)
            if agg_alert:  # Only return new alerts (not duplicates)
                alerts.append(
                    {
                        "id": agg_alert.alert_id,
                        "type": "danger" if agg_alert.severity == "HIGH" else "warning",
                        "severity": agg_alert.severity.lower(),
                        "message": agg_alert.name,
                        "timestamp": timestamp,
                        "count": agg_alert.count,
                    }
                )

        return alerts

    def _detect_threats_legacy(
        self, pkt: Any, parsed: Dict[str, Any]
    ) -> List[Alert]:
        """
        Legacy threat detection for backward compatibility.

        Args:
            pkt: Scapy packet object
            parsed: Parsed packet dict

        Returns:
            List of Alert objects
        """
        alerts = []
        src = parsed.get("src_ip", "")
        proto = parsed.get("protocol", "")
        dst_port = parsed.get("dst_port", 0)
        size = parsed.get("size", 0)
        timestamp = parsed.get("timestamp", datetime.now().isoformat())

        # 1. Sensitive port access
        if dst_port in SENSITIVE_PORTS:
            alerts.append(
                Alert(
                    type="warning",
                    severity="medium",
                    message=f"{SENSITIVE_PORTS[dst_port]} connection from {src} → port {dst_port}",
                    timestamp=timestamp,
                )
            )

        # 2. Port scan detection
        if src and dst_port:
            self.ip_ports[src].add(dst_port)
            if len(self.ip_ports[src]) > PORT_SCAN_THRESHOLD:
                alerts.append(
                    Alert(
                        type="danger",
                        severity="high",
                        message=f"🚨 Port scan detected! {src} probed {len(self.ip_ports[src])} ports",
                        timestamp=timestamp,
                    )
                )
                self.ip_ports[src] = set()

        # 3. ICMP flood detection
        if proto == "ICMP":
            now = time.time()
            if now - self.icmp_window_start > ICMP_FLOOD_WINDOW:
                self.icmp_count.clear()
                self.icmp_window_start = now

            self.icmp_count[src] += 1
            if self.icmp_count[src] > ICMP_FLOOD_THRESHOLD:
                alerts.append(
                    Alert(
                        type="danger",
                        severity="high",
                        message=f"🚨 ICMP flood from {src} ({self.icmp_count[src]} packets/5s)",
                        timestamp=timestamp,
                    )
                )
                self.icmp_count[src] = 0

        # 4. Oversized packets
        if size > PACKET_SIZE_ANOMALY:
            alerts.append(
                Alert(
                    type="info",
                    severity="low",
                    message=f"⚠️ Large packet ({size} bytes) from {src} via {proto}",
                    timestamp=timestamp,
                )
            )

        # 5. Insecure Telnet
        if dst_port == 23:
            alerts.append(
                Alert(
                    type="danger",
                    severity="high",
                    message=f"🚨 INSECURE Telnet from {src} — plaintext credentials at risk!",
                    timestamp=timestamp,
                )
            )

        return alerts

    def get_aggregated_alerts(
        self, min_severity: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get aggregated alerts from the aggregator.

        Args:
            min_severity: Minimum severity level to include
            limit: Maximum number of alerts to return

        Returns:
            List of aggregated alert dictionaries
        """
        if not self.use_rule_engine:
            return []

        agg_alerts = self.aggregator.get_aggregated_alerts(limit=limit)

        result = []
        for alert in agg_alerts:
            if (
                min_severity
                and alert.severity.lower()
                not in ["medium", "high", "critical"]
            ):
                continue

            result.append(
                {
                    "id": alert.alert_id,
                    "name": alert.name,
                    "severity": alert.severity.lower(),
                    "count": alert.count,
                    "first_seen": alert.first_seen,
                    "last_seen": alert.last_seen,
                    "sources": list(alert.sources)[:5],  # Top 5 sources
                }
            )

        return result

    def reset(self):
        """Reset threat detector state."""
        self.ip_ports.clear()
        self.icmp_count.clear()
        self.icmp_window_start = time.time()

        if self.use_rule_engine:
            # Don't reset rule engine - keep configuration
            # But clear aggregator to remove old alerts
            self.aggregator.aggregated_alerts.clear()
