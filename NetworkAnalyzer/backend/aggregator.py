"""
Alert Aggregation System

Deduplicates alerts and aggregates similar events to reduce alert fatigue.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import time
import hashlib


@dataclass
class AggregatedAlert:
    """Aggregated alert with count and last occurrence."""
    alert_id: str
    alert_hash: str
    name: str
    severity: str
    first_seen: float
    last_seen: float
    count: int = 1
    occurrences: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    rule_ids: List[str] = field(default_factory=list)

    def is_stale(self, ttl_seconds: int = 3600) -> bool:
        """Check if alert is older than TTL."""
        return (time.time() - self.last_seen) > ttl_seconds


class AlertAggregator:
    """Aggregates and deduplicates alerts."""

    def __init__(self, ttl_seconds: int = 3600, max_aggregated: int = 5000):
        """
        Initialize aggregator.

        Args:
            ttl_seconds: Time to live for aggregated alerts
            max_aggregated: Maximum aggregated alerts to keep
        """
        self.ttl_seconds = ttl_seconds
        self.max_aggregated = max_aggregated
        self.aggregated: Dict[str, AggregatedAlert] = {}
        self.alert_history: List[Dict] = []

    def add_alert(self, alert: Dict) -> Optional[AggregatedAlert]:
        """
        Add alert for aggregation.

        Args:
            alert: Alert dictionary with alert_id, name, severity, etc.

        Returns:
            AggregatedAlert if new, None if duplicate and aggregated
        """
        # Generate hash for deduplication
        alert_hash = self._generate_alert_hash(alert)

        current_time = time.time()

        if alert_hash in self.aggregated:
            # Alert already seen - aggregate it
            agg = self.aggregated[alert_hash]
            agg.count += 1
            agg.last_seen = current_time

            # Track additional data
            src_ip = alert.get("context", {}).get("src_ip")
            if src_ip and src_ip not in agg.sources:
                agg.sources.append(src_ip)

            rule_id = alert.get("rule_id")
            if rule_id and rule_id not in agg.rule_ids:
                agg.rule_ids.append(rule_id)

            agg.occurrences.append(alert.get("name", ""))

            return None  # Duplicate, not a new alert

        # New unique alert
        agg_alert = AggregatedAlert(
            alert_id=alert.get("id", f"alert_{int(current_time)}"),
            alert_hash=alert_hash,
            name=alert.get("name", "Unknown"),
            severity=alert.get("severity", "MEDIUM"),
            first_seen=current_time,
            last_seen=current_time,
            count=1,
            sources=[alert.get("context", {}).get("src_ip")],
            rule_ids=[alert.get("rule_id")],
        )

        self.aggregated[alert_hash] = agg_alert
        self._cleanup_stale()

        return agg_alert

    def _generate_alert_hash(self, alert: Dict) -> str:
        """
        Generate deduplication hash for alert.

        Hashes: alert name + severity + key context fields.
        """
        context = alert.get("context", {})
        key_parts = [
            alert.get("rule_id", ""),
            alert.get("name", ""),
            alert.get("severity", ""),
            context.get("src_ip", ""),
            context.get("dst_ip", ""),
            str(context.get("dst_port", "")),
        ]

        hash_str = "|".join(key_parts)
        return hashlib.md5(hash_str.encode()).hexdigest()

    def _cleanup_stale(self) -> None:
        """Remove stale aggregated alerts."""
        current_time = time.time()
        to_remove = [
            key
            for key, alert in self.aggregated.items()
            if (current_time - alert.first_seen) > self.ttl_seconds
        ]

        for key in to_remove:
            del self.aggregated[key]

        # Keep size under control
        if len(self.aggregated) > self.max_aggregated:
            # Remove oldest alerts
            sorted_alerts = sorted(
                self.aggregated.items(),
                key=lambda x: x[1].first_seen,
            )
            to_keep = sorted_alerts[-self.max_aggregated :]
            self.aggregated = dict(to_keep)

    def get_aggregated_alerts(
        self, min_severity: str = "LOW", limit: int = 100
    ) -> List[Dict]:
        """
        Get aggregated alerts above severity threshold.

        Args:
            min_severity: Minimum severity (LOW, MEDIUM, HIGH, CRITICAL)
            limit: Max alerts to return

        Returns:
            List of aggregated alert dicts
        """
        severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        min_level = severity_order.get(min_severity, 0)

        alerts = []
        for agg_alert in sorted(
            self.aggregated.values(),
            key=lambda x: (
                severity_order.get(x.severity, 0),
                x.first_seen,
            ),
            reverse=True,
        ):
            if severity_order.get(agg_alert.severity, 0) < min_level:
                continue

            alert_dict = {
                "id": agg_alert.alert_id,
                "name": agg_alert.name,
                "severity": agg_alert.severity,
                "count": agg_alert.count,
                "first_seen": agg_alert.first_seen,
                "last_seen": agg_alert.last_seen,
                "sources": list(set(agg_alert.sources)),
                "rule_ids": list(set(agg_alert.rule_ids)),
            }
            alerts.append(alert_dict)

            if len(alerts) >= limit:
                break

        return alerts

    def get_critical_alerts(self) -> List[Dict]:
        """Get only critical severity alerts."""
        return [
            a for a in self.aggregated.values() if a.severity == "CRITICAL"
        ]

    def acknowledge_alert(self, alert_hash: str) -> bool:
        """Mark alert as acknowledged."""
        if alert_hash in self.aggregated:
            # Alert could be marked as acknowledged in production
            # (e.g., to filter from UI)
            return True
        return False

    def clear_all(self) -> None:
        """Clear all aggregated alerts."""
        self.aggregated.clear()

    def get_stats(self) -> Dict:
        """Get aggregator statistics."""
        total_alerts = len(self.aggregated)
        critical = sum(1 for a in self.aggregated.values() if a.severity == "CRITICAL")
        high = sum(1 for a in self.aggregated.values() if a.severity == "HIGH")
        medium = sum(1 for a in self.aggregated.values() if a.severity == "MEDIUM")
        low = sum(1 for a in self.aggregated.values() if a.severity == "LOW")

        return {
            "total": total_alerts,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        }
