"""
Rule-Based Alert System

Configurable, production-grade detection rules with severity levels.
Designed for extensibility and easy customization.
"""
from dataclasses import dataclass
from typing import Callable, List, Dict, Any, Optional
from enum import Enum
import time


class Severity(str, Enum):
    """Alert severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Rule:
    """Detection rule definition."""
    id: str
    name: str
    description: str
    severity: Severity
    enabled: bool = True
    cooldown_seconds: int = 60  # Prevent duplicate alerts
    detector_func: Optional[Callable] = None  # Will be set during registration


class RuleEngine:
    """Manages and executes detection rules."""

    def __init__(self):
        """Initialize rule engine."""
        self.rules: Dict[str, Rule] = {}
        self.last_alert_time: Dict[str, float] = {}  # Track last alert per rule
        self.custom_rules: List[Callable] = []

    def register_rule(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: Severity,
        detector: Callable[[Dict[str, Any]], bool],
        cooldown: int = 60,
    ) -> None:
        """
        Register a detection rule.

        Args:
            rule_id: Unique identifier
            name: Human-readable name
            description: What the rule detects
            severity: Alert severity level
            detector: Function that returns True if condition is met
            cooldown: Seconds to suppress duplicate alerts
        """
        rule = Rule(
            id=rule_id,
            name=name,
            description=description,
            severity=severity,
            enabled=True,
            cooldown_seconds=cooldown,
            detector_func=detector,
        )
        self.rules[rule_id] = rule

    def check_rules(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check all enabled rules against current context.

        Args:
            context: Packet/traffic context to evaluate

        Returns:
            List of triggered rule alerts
        """
        alerts = []

        for rule_id, rule in self.rules.items():
            if not rule.enabled:
                continue

            # Check cooldown
            if self._is_in_cooldown(rule_id):
                continue

            # Execute detector
            try:
                if rule.detector_func and rule.detector_func(context):
                    alert = {
                        "rule_id": rule_id,
                        "name": rule.name,
                        "description": rule.description,
                        "severity": rule.severity.value,
                        "timestamp": time.time(),
                        "context": context,
                    }
                    alerts.append(alert)
                    self.last_alert_time[rule_id] = time.time()
            except Exception as e:
                print(f"[ERROR] Rule {rule_id} execution failed: {e}")

        return alerts

    def _is_in_cooldown(self, rule_id: str) -> bool:
        """Check if rule is in cooldown period."""
        if rule_id not in self.last_alert_time:
            return False

        rule = self.rules[rule_id]
        elapsed = time.time() - self.last_alert_time[rule_id]
        return elapsed < rule.cooldown_seconds

    def enable_rule(self, rule_id: str) -> None:
        """Enable a rule."""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True

    def disable_rule(self, rule_id: str) -> None:
        """Disable a rule."""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False

    def get_rules(self) -> Dict[str, Dict[str, Any]]:
        """Get all rules with their status."""
        return {
            rule_id: {
                "name": rule.name,
                "description": rule.description,
                "severity": rule.severity.value,
                "enabled": rule.enabled,
                "cooldown": rule.cooldown_seconds,
            }
            for rule_id, rule in self.rules.items()
        }


# ═══════════════════════════════════════════════════════════════════════════
# Built-in Detection Rules
# ═══════════════════════════════════════════════════════════════════════════


def create_default_rules() -> RuleEngine:
    """Create rule engine with default detection rules."""
    engine = RuleEngine()

    # Rule: Port Scanning
    engine.register_rule(
        rule_id="port_scan",
        name="Port Scanning Detected",
        description="Single source IP probing multiple destination ports",
        severity=Severity.HIGH,
        detector=lambda ctx: (
            ctx.get("ports_probed", 0) >= 15
            and ctx.get("protocol") in ["TCP", "UDP"]
        ),
        cooldown=300,
    )

    # Rule: SYN Flood
    engine.register_rule(
        rule_id="syn_flood",
        name="SYN Flood Attack",
        description="Excessive SYN packets from single source",
        severity=Severity.CRITICAL,
        detector=lambda ctx: (
            ctx.get("syn_packets_per_sec", 0) > 100
            and ctx.get("protocol") == "TCP"
        ),
        cooldown=60,
    )

    # Rule: DNS Flood
    engine.register_rule(
        rule_id="dns_flood",
        name="DNS Flood Detected",
        description="Excessive DNS queries from single source",
        severity=Severity.HIGH,
        detector=lambda ctx: (
            ctx.get("dns_queries_per_sec", 0) > 50
            and ctx.get("protocol") == "DNS"
        ),
        cooldown=120,
    )

    # Rule: ICMP Flood
    engine.register_rule(
        rule_id="icmp_flood",
        name="ICMP Flood (Ping Sweep)",
        description="Excessive ICMP echo requests",
        severity=Severity.MEDIUM,
        detector=lambda ctx: (
            ctx.get("icmp_packets_per_sec", 0) > 20
            and ctx.get("protocol") == "ICMP"
        ),
        cooldown=120,
    )

    # Rule: Abnormal Packet Size
    engine.register_rule(
        rule_id="abnormal_packet_size",
        name="Abnormal Packet Size",
        description="Packets significantly larger than typical",
        severity=Severity.LOW,
        detector=lambda ctx: (
            ctx.get("packet_size", 0) > 1400
            or ctx.get("packet_size", 0) < 20
        ),
        cooldown=60,
    )

    # Rule: Suspicious Protocol Combination
    engine.register_rule(
        rule_id="suspicious_proto_combo",
        name="Suspicious Protocol Combination",
        description="Unusual port/protocol combination detected",
        severity=Severity.MEDIUM,
        detector=lambda ctx: (
            ctx.get("dst_port") == 23  # Telnet (insecure)
            and ctx.get("protocol") == "TCP"
        ),
        cooldown=600,
    )

    # Rule: Rapid Protocol Change
    engine.register_rule(
        rule_id="rapid_protocol_change",
        name="Rapid Protocol Switching",
        description="Single source using many different protocols",
        severity=Severity.MEDIUM,
        detector=lambda ctx: (
            ctx.get("unique_protocols_per_src", 0) > 10
        ),
        cooldown=300,
    )

    # Rule: Suspicious Geographic Activity
    engine.register_rule(
        rule_id="suspicious_geo_activity",
        name="Suspicious Geographic Activity",
        description="Traffic from unusual geographic location",
        severity=Severity.LOW,
        detector=lambda ctx: (
            ctx.get("is_tor_exit", False)
            or ctx.get("is_proxy", False)
        ),
        cooldown=600,
    )

    # Rule: Data Exfiltration Attempt
    engine.register_rule(
        rule_id="data_exfil",
        name="Potential Data Exfiltration",
        description="Large outbound data transfer detected",
        severity=Severity.HIGH,
        detector=lambda ctx: (
            ctx.get("egress_bytes_per_sec", 0) > 1000000  # 1 MB/s
            and ctx.get("src_ip") == ctx.get("internal_ip")
        ),
        cooldown=60,
    )

    # Rule: Malware C2 Pattern
    engine.register_rule(
        rule_id="malware_c2",
        name="Potential Malware C2 Communication",
        description="Traffic pattern suggests C&C communication",
        severity=Severity.CRITICAL,
        detector=lambda ctx: (
            ctx.get("beaconing_behavior", False)
            and ctx.get("uses_non_standard_port", False)
        ),
        cooldown=180,
    )

    return engine
