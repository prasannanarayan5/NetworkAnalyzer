"""
WebSocket Handler
"""
import asyncio
import json
import time
from fastapi import WebSocket, WebSocketDisconnect

from config import WS_BATCH_INTERVAL, WS_MAX_PACKETS_PER_BATCH
from capture_state import CaptureState
from packet_sniffer import PacketSniffer


class WebSocketHandler:
    """Manages WebSocket connections for live data streaming."""

    def __init__(self, state: CaptureState, sniffer: PacketSniffer):
        """
        Initialize WebSocket handler.

        Args:
            state: CaptureState instance
            sniffer: PacketSniffer instance
        """
        self.state = state
        self.sniffer = sniffer

    async def handle_connection(self, websocket: WebSocket):
        """
        Handle a WebSocket client connection with robust error handling.

        Args:
            websocket: FastAPI WebSocket connection
        """
        print("\n[WS] ═══════════════════════════════════════════════════════")
        print("[WS] ═══ New WebSocket connection ═══")
        
        await websocket.accept()
        print("[WS] ✓ Client accepted")
        
        last_sent_packet_id = 0
        batch_count = 0
        error_count = 0

        try:
            while True:
                try:
                    # Send updates at regular interval
                    await asyncio.sleep(WS_BATCH_INTERVAL)
                    batch_count += 1

                    # Safely gather all data with graceful fallbacks
                    try:
                        new_pkts = self.state.get_recent_packets(limit=1000)
                        if not new_pkts:
                            new_pkts = []
                    except Exception as e:
                        print(f"[WS] Error getting packets: {e}")
                        new_pkts = []
                        
                    try:
                        new_pkts = [p for p in new_pkts if p.get("id", 0) > last_sent_packet_id]
                    except Exception as e:
                        print(f"[WS] Error filtering packets: {e}")
                        
                    try:
                        new_pkts.reverse()
                    except Exception:
                        pass
                        
                    try:
                        if new_pkts and isinstance(new_pkts, list) and len(new_pkts) > 0:
                            last_sent_id = new_pkts[-1].get("id")
                            if last_sent_id:
                                last_sent_packet_id = last_sent_id
                    except Exception as e:
                        print(f"[WS] Error updating last_sent_packet_id: {e}")

                    # Get stats with defaults
                    stats = {}
                    try:
                        stats = self.state.get_stats() or {}
                    except Exception as e:
                        print(f"[WS] Error getting stats: {e}")
                        error_count += 1
                        stats = {
                            "total_packets": 0,
                            "total_bytes": 0,
                            "uptime": 0,
                            "pps": 0.0,
                            "bps": 0.0,
                            "protocol_distribution": {},
                            "top_src_ips": [],
                            "top_dest_ips": [],
                            "alerts_count": 0,
                        }

                    # Get alerts with defaults
                    alerts = []
                    try:
                        alerts = self.state.get_recent_alerts(limit=10) or []
                    except Exception as e:
                        print(f"[WS] Error getting alerts: {e}")
                        alerts = []

                    # Get bandwidth with defaults
                    bandwidth_history = []
                    try:
                        bandwidth_history = self.state.get_bandwidth_history() or []
                    except Exception as e:
                        print(f"[WS] Error getting bandwidth: {e}")
                        bandwidth_history = []

                    # Build payload with strict type checking
                    try:
                        payload = {
                            "type": "batch",
                            "packets": new_pkts[:WS_MAX_PACKETS_PER_BATCH] if new_pkts else [],
                            "bandwidth_snap": (
                                bandwidth_history[-1] if bandwidth_history else None
                            ),
                            "stats": {
                                "total_packets": int(stats.get("total_packets", 0)),
                                "total_bytes": int(stats.get("total_bytes", 0)),
                                "uptime": int(stats.get("uptime", 0)),
                                "pps": float(stats.get("pps", 0.0)),
                                "bps": float(stats.get("bps", 0.0)),
                                "protocol_distribution": stats.get("protocol_distribution", {}) or {},
                                "top_src_ips": stats.get("top_src_ips", []) or [],
                                "top_dest_ips": stats.get("top_dest_ips", []) or [],
                                "capture_running": self.sniffer.is_running(),
                                "interface": self.sniffer.interface_name or "unknown",
                                "alerts_count": int(stats.get("alerts_count", 0)),
                            },
                            "new_alerts": alerts if alerts else [],
                        }
                    except Exception as e:
                        print(f"[WS] Error building payload: {e}")
                        continue

                    # Send payload
                    try:
                        msg = json.dumps(payload)
                        await websocket.send_text(msg)
                        error_count = 0  # Reset on success
                        
                        if batch_count % 10 == 0:
                            print(f"[WS] ✓ Batch #{batch_count}: {len(new_pkts)} pkts, "
                                  f"packets={stats.get('total_packets', 0)}")
                    except json.JSONDecodeError as je:
                        print(f"[WS] JSON error: {je}")
                        error_count += 1
                    except Exception as send_err:
                        print(f"[WS] Send error: {send_err}")
                        raise

                    # Stop if too many errors
                    if error_count > 5:
                        print("[WS] Too many errors, closing connection")
                        break

                except asyncio.CancelledError:
                    print("[WS] Task cancelled")
                    break
                except Exception as batch_err:
                    print(f"[WS] Batch error: {type(batch_err).__name__}: {batch_err}")
                    error_count += 1
                    if error_count > 5:
                        break
                    # Continue trying
                    await asyncio.sleep(0.1)

        except WebSocketDisconnect:
            print("[WS] Client disconnected")
        except Exception as e:
            print(f"[WS] Handler error: {type(e).__name__}: {e}")
        finally:
            print("[WS] ═══ WebSocket connection closed ═══")
            print("[WS] ═════════════════════════════════════════════════════════\n")
