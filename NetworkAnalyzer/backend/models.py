"""
Data Models and Schemas
"""
from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel


# ── Packet Models ─────────────────────────────────────────────────────────
class PacketInfo(BaseModel):
    """Parsed packet information."""
    id: int
    timestamp: str
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    size: int
    ttl: int
    flags: str
    dns_query: str = ""
    http_host: str = ""
    info: str

    class Config:
        json_schema_extra = {
            "example": {
                "id": 1,
                "timestamp": "2026-04-05T10:30:45.123456",
                "protocol": "TCP",
                "src_ip": "192.168.1.100",
                "dst_ip": "8.8.8.8",
                "src_port": 54321,
                "dst_port": 443,
                "size": 512,
                "ttl": 64,
                "flags": "S",
                "dns_query": "",
                "http_host": "",
                "info": "TCP 192.168.1.100:54321 → 8.8.8.8:443"
            }
        }


# ── Alert Models ──────────────────────────────────────────────────────────
class Alert(BaseModel):
    """Security alert."""
    type: str  # "warning", "danger", "info"
    severity: str  # "low", "medium", "high"
    message: str
    timestamp: str


# ── Bandwidth Models ──────────────────────────────────────────────────────
class BandwidthSnapshot(BaseModel):
    """Per-second bandwidth snapshot."""
    timestamp: str
    bytes_per_sec: int
    packets_per_sec: int


# ── Statistics Models ─────────────────────────────────────────────────────
class IPStats(BaseModel):
    """IP address statistics."""
    ip: str
    count: int

    class Config:
        json_schema_extra = {"example": {"ip": "192.168.1.1", "count": 42}}


class PortStats(BaseModel):
    """Port statistics."""
    port: int
    count: int


class ProtocolStats(BaseModel):
    """Overall statistics."""
    total_packets: int
    total_bytes: int
    uptime_seconds: int
    packets_per_second: float
    bytes_per_second: float
    protocol_distribution: Dict[str, int]
    top_source_ips: List[IPStats]
    top_dest_ips: List[IPStats]
    top_ports: List[PortStats]
    capture_running: bool
    interface: Optional[str]
    local_ip: Optional[str]
    pps: float = 0.0
    bps: float = 0.0
    alerts_count: int = 0


# ── Interface Models ──────────────────────────────────────────────────────
class NetworkInterface(BaseModel):
    """Network interface information."""
    name: str
    ip: str
    is_up: bool
    speed: int


class InterfaceList(BaseModel):
    """List of network interfaces."""
    interfaces: List[NetworkInterface]
    current: Optional[str]


# ── WebSocket Message Models ──────────────────────────────────────────────
class WebSocketBatch(BaseModel):
    """WebSocket batch message."""
    type: str = "batch"
    packets: List[PacketInfo]
    bandwidth_snap: Dict[str, Any]
    stats: Dict[str, Any]
    new_alerts: List[Alert]


# ── Response Models ───────────────────────────────────────────────────────
class PacketsResponse(BaseModel):
    """Response for packet queries."""
    packets: List[PacketInfo]
    total: int


class BandwidthResponse(BaseModel):
    """Response for bandwidth history."""
    history: List[BandwidthSnapshot]


class AlertsResponse(BaseModel):
    """Response for alerts."""
    alerts: List[Alert]


class StatusResponse(BaseModel):
    """Generic status response."""
    status: str
    interface: Optional[str] = None


# ── Enhanced Protocol Analysis Models ─────────────────────────────────────
class TCPFlagAnalysis(BaseModel):
    """TCP flag statistics."""
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0
    top_sources: List[IPStats] = []

    class Config:
        json_schema_extra = {
            "example": {
                "syn_count": 125,
                "ack_count": 3400,
                "fin_count": 98,
                "rst_count": 12,
                "psh_count": 890,
                "urg_count": 0,
                "top_sources": [{"ip": "192.168.1.100", "count": 45}]
            }
        }


class HTTPMethodStats(BaseModel):
    """HTTP method statistics."""
    get_count: int = 0
    post_count: int = 0
    put_count: int = 0
    patch_count: int = 0
    delete_count: int = 0
    head_count: int = 0
    options_count: int = 0
    top_hosts: List[str] = []

    class Config:
        json_schema_extra = {
            "example": {
                "get_count": 1200,
                "post_count": 340,
                "put_count": 45,
                "patch_count": 12,
                "delete_count": 8,
                "head_count": 56,
                "options_count": 2,
                "top_hosts": ["example.com", "api.example.com"]
            }
        }


class DNSQueryAnalysis(BaseModel):
    """DNS query statistics."""
    total_queries: int = 0
    unique_domains: int = 0
    failed_queries: int = 0
    query_types: Dict[str, int] = {}  # A, AAAA, MX, CNAME, etc.
    top_domains: List[tuple] = []  # [(domain, count), ...]
    top_sources: List[IPStats] = []
    failure_rate: float = 0.0

    class Config:
        json_schema_extra = {
            "example": {
                "total_queries": 4500,
                "unique_domains": 123,
                "failed_queries": 45,
                "query_types": {"A": 3200, "AAAA": 800, "MX": 500},
                "top_domains": [("example.com", 250), ("google.com", 180)],
                "top_sources": [{"ip": "192.168.1.100", "count": 1200}],
                "failure_rate": 0.01
            }
        }


# ── Insight Models ────────────────────────────────────────────────────────
class InsightItem(BaseModel):
    """Single insight about traffic."""
    insight_type: str  # "spike", "anomaly", "top_consumer", etc.
    description: str
    severity: str  # "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    timestamp: str
    details: Dict[str, Any] = {}


class InsightResult(BaseModel):
    """Collection of insights about current traffic."""
    insights: List[InsightItem]
    spike_ips: List[Dict[str, Any]] = []
    top_consumers: List[Dict[str, Any]] = []
    dns_anomalies: Dict[str, Any] = {}
    total_insights: int
    generated_at: str

    class Config:
        json_schema_extra = {
            "example": {
                "insights": [
                    {
                        "insight_type": "spike",
                        "description": "Bandwidth spike from 192.168.1.100",
                        "severity": "HIGH",
                        "timestamp": "2026-04-05T10:30:45.123456",
                        "details": {"increase_percent": 320}
                    }
                ],
                "spike_ips": ["192.168.1.100"],
                "top_consumers": [
                    {"ip": "192.168.1.100", "avg_bandwidth": 5000000}
                ],
                "dns_anomalies": {"type": "flood", "query_count": 500},
                "total_insights": 3,
                "generated_at": "2026-04-05T10:30:45.123456"
            }
        }


class TrafficWindow(BaseModel):
    """Traffic snapshot for a time window."""
    timestamp: str
    duration_seconds: int
    total_bytes: float
    total_packets: int
    unique_ips: int
    protocols: List[str]
    avg_bandwidth: float
    packet_rate: float
    top_ips: List[tuple]  # [(ip, bytes), ...]
    dns_query_count: int

    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "2026-04-05T10:30:45.123456",
                "duration_seconds": 60,
                "total_bytes": 15000000,
                "total_packets": 5200,
                "unique_ips": 42,
                "protocols": ["TCP", "UDP", "ICMP"],
                "avg_bandwidth": 250000,
                "packet_rate": 86.67,
                "top_ips": [("192.168.1.100", 5000000)],
                "dns_query_count": 120
            }
        }
