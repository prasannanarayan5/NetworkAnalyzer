"""
Configuration and Constants
"""

# ── Capture Settings ──────────────────────────────────────────────────────
MAX_PACKET_BUFFER = 1000
MAX_BANDWIDTH_HISTORY = 60
MAX_ALERTS = 100
MAX_ROWS_TABLE = 200
BANDWIDTH_POINTS = 50
WS_BATCH_INTERVAL = 0.8  # seconds
WS_MAX_PACKETS_PER_BATCH = 30
DNS_QUERY_BUFFER_SIZE = 60

# ── Threat Detection ──────────────────────────────────────────────────────
SENSITIVE_PORTS = {
    22: "SSH", 23: "Telnet", 3389: "RDP",
    445: "SMB", 135: "RPC", 137: "NetBIOS",
    21: "FTP", 25: "SMTP", 110: "POP3"
}

PORT_SCAN_THRESHOLD = 15  # Different ports to trigger alert
ICMP_FLOOD_THRESHOLD = 20  # Packets per 5 seconds
ICMP_FLOOD_WINDOW = 5.0   # seconds
PACKET_SIZE_ANOMALY = 1400  # bytes

# ── WiFi Interface Detection Hints ────────────────────────────────────────
WIFI_INTERFACE_HINTS = ["wi-fi", "wifi", "wlan", "wireless", "802.11"]

# ── Server Config ─────────────────────────────────────────────────────────
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 8000

# ── API Endpoints ─────────────────────────────────────────────────────────
API_PREFIX = "/api"
