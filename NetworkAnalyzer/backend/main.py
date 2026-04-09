"""
NetScan — Real WiFi Packet Capture Backend
==========================================
Real-time packet sniffing, protocol analysis, and threat detection.

Structure:
  ├── config.py          — Configuration & constants
  ├── models.py          — Pydantic data models
  ├── protocol_classifier.py — Protocol detection
  ├── threat_detector.py  — Security threat detection
  ├── packet_parser.py    — Packet parsing logic
  ├── packet_sniffer.py   — Scapy wrapper & capture control
  ├── capture_state.py    — Thread-safe state management
  ├── insights.py         — Traffic insight generation
  ├── historian.py        — Historical traffic analysis
  ├── rules.py            — Rule-based detection engine
  ├── aggregator.py       — Alert aggregation & deduplication
  ├── websocket_handler.py — WebSocket live streaming
  ├── routes.py           — REST API endpoints
  ├── utils.py            — Helper functions
  └── main.py             — FastAPI app & entry point

Installation:
  pip install -r requirements.txt

Running:
  uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

import threading
import time
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware

from config import SERVER_HOST, SERVER_PORT
from capture_state import CaptureState
from packet_sniffer import PacketSniffer
from threat_detector import ThreatDetector
from insights import InsightEngine
from historian import Historian
from routes import create_routes
from websocket_handler import WebSocketHandler

# ══════════════════════════════════════════════════════════════════════════
# FastAPI Application Setup
# ══════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="NetScan — Real Capture",
    description="Real-time WiFi packet analysis and threat detection",
    version="2.0.0",
)

# CORS middleware for browser requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ══════════════════════════════════════════════════════════════════════════
# Global State & Services
# ══════════════════════════════════════════════════════════════════════════

# Initialize state and sniffer
state = CaptureState()
sniffer = PacketSniffer(state)
ws_handler = WebSocketHandler(state, sniffer)

# Production-grade threat detection with rule engine
threat_detector = ThreatDetector(use_rule_engine=True)

# Traffic insight generation and historical analysis
insights_engine = InsightEngine(history_minutes=60)
historian = Historian()

# ══════════════════════════════════════════════════════════════════════════
# Background Services
# ══════════════════════════════════════════════════════════════════════════


def bandwidth_ticker():
    """
    Background thread that captures per-second bandwidth snapshots.
    Runs every second to measure throughput.
    """
    print("[+] Bandwidth ticker started")
    while True:
        time.sleep(1)
        state.snapshot_bandwidth()
        
        # Feed recent packets to insights engine for analysis
        try:
            recent_packets = state.get_recent_packets_raw(limit=100)
            for pkt in recent_packets:
                insights_engine.add_packet(
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    protocol=pkt.protocol,
                    dst_port=pkt.dst_port,
                    size=pkt.size,
                    dns_query=pkt.dns_query,
                )
        except Exception as e:
            print(f"[WARNING] Failed to feed packets to insights engine: {e}")


# Start background thread
bw_thread = threading.Thread(target=bandwidth_ticker, daemon=True)
bw_thread.start()

# ══════════════════════════════════════════════════════════════════════════
# API Routes
# ══════════════════════════════════════════════════════════════════════════

# Register all REST API routes with production components
api_router = create_routes(
    sniffer,
    state,
    threat_detector=threat_detector,
    insights_engine=insights_engine,
)
app.include_router(api_router)

# ══════════════════════════════════════════════════════════════════════════
# WebSocket Endpoint
# ══════════════════════════════════════════════════════════════════════════


@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    """
    WebSocket endpoint for live packet streaming.
    Sends batch updates every 0.8 seconds with new packets, stats, and alerts.
    """
    await ws_handler.handle_connection(websocket)


# ══════════════════════════════════════════════════════════════════════════
# Startup & Shutdown
# ══════════════════════════════════════════════════════════════════════════


@app.on_event("startup")
async def startup():
    """Initialize capture on server startup."""
    print(f"[+] NetScan server starting on {SERVER_HOST}:{SERVER_PORT}")
    print(f"[+] Interface: {sniffer.interface_name} | IP: {sniffer.local_ip}")
    print(f"[+] Threat Detection: Rule Engine ENABLED ({len(threat_detector.rule_engine.rules)} rules)")
    print(f"[+] Insights Engine: ENABLED")
    print(f"[+] Alert Aggregation: ENABLED (prevents duplicate alerts)")
    sniffer.start()


@app.on_event("shutdown")
async def shutdown():
    """Stop capture on server shutdown."""
    print("[+] NetScan server shutting down")
    sniffer.stop()


# ══════════════════════════════════════════════════════════════════════════
# Entry Point
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host=SERVER_HOST,
        port=SERVER_PORT,
        log_level="info",
    )