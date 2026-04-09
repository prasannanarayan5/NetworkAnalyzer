#!/usr/bin/env python
"""Test JSON serialization of WebSocket payload"""

import json
from capture_state import CaptureState
from packet_sniffer import PacketSniffer
from models import PacketInfo, BandwidthSnapshot

# Initialize state and sniffer
state = CaptureState()
sniffer = PacketSniffer(state)

# Get sample data
stats = state.get_stats()
alerts = state.get_recent_alerts(limit=1)
bandwidth_history = state.get_bandwidth_history()

# Build payload like WebSocket does
payload = {
    "type": "batch",
    "packets": [],
    "bandwidth_snap": (
        bandwidth_history[-1] if bandwidth_history else None
    ),
    "stats": {
        "total_packets": stats.get("total_packets", 0),
        "total_bytes": stats.get("total_bytes", 0),
        "uptime": stats.get("uptime", 0),
        "pps": float(stats.get("pps", 0.0)),
        "bps": float(stats.get("bps", 0.0)),
        "protocol_distribution": stats.get("protocol_distribution", {}),
        "top_src_ips": stats.get("top_src_ips", []),
        "top_dest_ips": stats.get("top_dst_ips", []),
        "capture_running": sniffer.is_running(),
        "interface": sniffer.interface_name,
        "alerts_count": stats.get("alerts_count", 0),
    },
    "new_alerts": alerts,
}

# Try to serialize
try:
    msg = json.dumps(payload)
    print("[OK] WebSocket payload is JSON serializable")
    print(f"[OK] Payload size: {len(msg)} bytes")
    print(f"[OK] Payload structure: {json.loads(msg).keys()}")
    
    # Show sample data
    print("\n[INFO] Sample data:")
    print(f"  - stats: {payload['stats']}")
    print(f"  - alerts: {payload['new_alerts']}")
    print(f"  - bandwidth_snap: {payload['bandwidth_snap']}")
    
except Exception as e:
    print(f"[ERROR] Cannot serialize payload: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
    exit(1)

print("\n[✓] All JSON serialization tests passed!")
