"""
REST API Routes
"""
from fastapi import APIRouter, Query
from typing import Optional
from datetime import datetime

from capture_state import CaptureState
from packet_sniffer import PacketSniffer
from utils import get_network_interfaces
from models import (
    PacketsResponse,
    BandwidthResponse,
    AlertsResponse,
    StatusResponse,
    ProtocolStats,
    IPStats,
    PortStats,
    InsightResult,
    InsightItem,
)

router = APIRouter()


def create_routes(sniffer: PacketSniffer, state: CaptureState, threat_detector=None, insights_engine=None):
    """
    Create API routes using state and sniffer instances.

    Args:
        sniffer: PacketSniffer instance
        state: CaptureState instance
        threat_detector: ThreatDetector instance (optional, for advanced features)
        insights_engine: InsightEngine instance (optional, for traffic insights)
    """

    @router.get("/", tags=["Info"])
    def root():
        """Get server info and connection details."""
        return {
            "app": "NetScan Real Capture",
            "interface": sniffer.interface_name,
            "local_ip": sniffer.local_ip,
            "docs": "/docs",
            "ws": "ws://localhost:8000/ws/live",
        }

    @router.get("/api/stats", tags=["Stats"], response_model=ProtocolStats)
    def get_stats():
        """Get current capture statistics."""
        stats = state.get_stats()
        
        # Convert IP counts to IPStats objects (already in dict format from get_stats)
        top_src = [IPStats(ip=item["ip"], count=item["count"]) for item in stats["top_src_ips"]]
        top_dst = [IPStats(ip=item["ip"], count=item["count"]) for item in stats["top_dest_ips"]]
        top_ports = [PortStats(port=item["port"], count=item["count"]) for item in stats["top_ports"]]

        return ProtocolStats(
            total_packets=stats["total_packets"],
            total_bytes=stats["total_bytes"],
            uptime_seconds=stats["uptime"],
            packets_per_second=stats["pps"],
            bytes_per_second=stats["bps"],
            protocol_distribution=stats["protocol_distribution"],
            top_source_ips=top_src,
            top_dest_ips=top_dst,
            top_ports=top_ports,
            capture_running=sniffer.is_running(),
            interface=sniffer.interface_name,
            local_ip=sniffer.local_ip,
        )

    @router.get("/api/packets", tags=["Packets"], response_model=PacketsResponse)
    def get_packets(limit: int = Query(100, ge=1, le=1000), protocol: Optional[str] = None):
        """Get recent captured packets."""
        protocol = protocol or "ALL"
        packets = state.get_recent_packets(limit=limit, protocol=protocol)
        return PacketsResponse(packets=packets, total=len(state.packets))

    @router.get("/api/bandwidth", tags=["Bandwidth"], response_model=BandwidthResponse)
    def get_bandwidth():
        """Get bandwidth history."""
        history = state.get_bandwidth_history()
        return BandwidthResponse(history=history)

    @router.get("/api/alerts", tags=["Alerts"], response_model=AlertsResponse)
    def get_alerts():
        """Get security alerts."""
        alerts = state.get_recent_alerts()
        return AlertsResponse(alerts=alerts)

    @router.get("/api/alerts/aggregated", tags=["Alerts"])
    def get_aggregated_alerts(min_severity: Optional[str] = None, limit: int = Query(50, ge=1, le=500)):
        """
        Get aggregated alerts with deduplication to prevent alert fatigue.

        Args:
            min_severity: Minimum severity (low, medium, high, critical)
            limit: Maximum alerts to return

        Returns:
            List of deduplicated aggregated alerts
        """
        if not threat_detector or not hasattr(threat_detector, 'get_aggregated_alerts'):
            return {
                "alerts": [],
                "message": "Alert aggregation not available",
                "available": False,
            }

        try:
            agg_alerts = threat_detector.get_aggregated_alerts(
                min_severity=min_severity,
                limit=limit,
            )
            return {
                "alerts": agg_alerts,
                "count": len(agg_alerts),
                "available": True,
            }
        except Exception as e:
            return {
                "alerts": [],
                "error": str(e),
                "available": False,
            }

    @router.get("/api/dns", tags=["DNS"])
    def get_dns_queries(limit: int = Query(30, ge=1, le=100)):
        """Get recent DNS queries."""
        queries = state.get_dns_queries(limit=limit)
        return {"dns_queries": queries}

    @router.get("/api/insights", tags=["Insights"], response_model=InsightResult)
    def get_insights():
        """
        Generate insights about current traffic patterns.

        Returns insights about spikes, anomalies, top consumers, and DNS activity.
        """
        if not insights_engine:
            return InsightResult(
                insights=[],
                spike_ips=[],
                top_consumers=[],
                dns_anomalies={},
                total_insights=0,
                generated_at=datetime.now().isoformat(),
            )

        try:
            # Generate all insights
            raw_insights = insights_engine.generate_insights()

            # Convert to InsightItem objects
            insight_items = []
            spike_ips = []
            top_consumers = []
            dns_anomalies = {}

            for insight in raw_insights:
                item = InsightItem(
                    insight_type=insight.get("type", "unknown"),
                    description=insight.get("description", ""),
                    severity=insight.get("severity", "INFO").upper(),
                    timestamp=datetime.now().isoformat(),
                    details=insight,
                )
                insight_items.append(item)

                # Categorize insights
                if insight.get("type") == "bandwidth_spike":
                    spike_ips.append(insight.get("current_value"))
                elif insight.get("type") == "top_consumers":
                    top_consumers = insight.get("top_ips", [])
                elif insight.get("type") == "dns_activity":
                    dns_anomalies = insight

            return InsightResult(
                insights=insight_items,
                spike_ips=spike_ips,
                top_consumers=top_consumers,
                dns_anomalies=dns_anomalies,
                total_insights=len(insight_items),
                generated_at=datetime.now().isoformat(),
            )
        except Exception as e:
            print(f"[ERROR] Failed to generate insights: {e}")
            return InsightResult(
                insights=[],
                spike_ips=[],
                top_consumers=[],
                dns_anomalies={},
                total_insights=0,
                generated_at=datetime.now().isoformat(),
            )

    @router.get("/api/rules", tags=["Rules"])
    def get_rules():
        """
        Get all detection rules and their current status.

        Returns rules configuration, enabled status, and statistics.
        """
        if not threat_detector or not hasattr(threat_detector, 'rule_engine'):
            return {
                "rules": [],
                "available": False,
                "message": "Rule engine not available",
            }

        try:
            rules_list = []
            engine = threat_detector.rule_engine

            for rule_id, rule in engine.rules.items():
                rules_list.append(
                    {
                        "id": rule.id,
                        "name": rule.name,
                        "description": rule.description,
                        "severity": rule.severity.name,
                        "enabled": rule.enabled,
                        "cooldown_seconds": rule.cooldown_seconds,
                    }
                )

            return {
                "rules": rules_list,
                "count": len(rules_list),
                "available": True,
            }
        except Exception as e:
            return {
                "rules": [],
                "error": str(e),
                "available": False,
            }

    @router.post("/api/rules/{rule_id}/enable", tags=["Rules"])
    def enable_rule(rule_id: str):
        """Enable a specific detection rule."""
        if not threat_detector or not hasattr(threat_detector, 'rule_engine'):
            return {"status": "error", "message": "Rule engine not available"}

        try:
            threat_detector.rule_engine.enable_rule(rule_id)
            return {"status": "enabled", "rule_id": rule_id}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    @router.post("/api/rules/{rule_id}/disable", tags=["Rules"])
    def disable_rule(rule_id: str):
        """Disable a specific detection rule."""
        if not threat_detector or not hasattr(threat_detector, 'rule_engine'):
            return {"status": "error", "message": "Rule engine not available"}

        try:
            threat_detector.rule_engine.disable_rule(rule_id)
            return {"status": "disabled", "rule_id": rule_id}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    @router.get("/api/interfaces", tags=["Network"])
    def get_interfaces():
        """List all network interfaces."""
        data = get_network_interfaces()
        data["current"] = sniffer.interface_name
        return data

    @router.post("/api/capture/start", tags=["Capture"], response_model=StatusResponse)
    def start_capture():
        """Start packet capture."""
        sniffer.start()
        return StatusResponse(status="started", interface=sniffer.interface_name)

    @router.post("/api/capture/stop", tags=["Capture"], response_model=StatusResponse)
    def stop_capture():
        """Stop packet capture."""
        sniffer.stop()
        return StatusResponse(status="stopped")

    @router.post("/api/reset", tags=["Capture"], response_model=StatusResponse)
    def reset_capture():
        """Reset all capture statistics."""
        sniffer.reset()
        state.reset()
        sniffer.start()
        return StatusResponse(status="reset", interface=sniffer.interface_name)

    return router
