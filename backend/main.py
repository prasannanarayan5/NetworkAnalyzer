"""
NetScan — Real WiFi Packet Capture Backend
==========================================
  1. pip install -r requirements.txt

START:
  uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import asyncio, json, threading, time, psutil
from datetime import datetime
from collections import defaultdict, deque
from typing import Optional

# ── Scapy imports ─────────────────────────────────────────────────────────────
from scapy.all import (
    sniff, get_if_list, conf,
    IP, IPv6, TCP, UDP, ICMP, DNS, ARP,
    Raw, Ether
)
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

app = FastAPI(title="NetScan — Real Capture", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── ─────────────────────────────────────────────────────────────────────────
#   STEP 1 — Auto-detect WiFi interface
# ─────────────────────────────────────────────────────────────────────────────

def get_wifi_interface():
    """
    Find the active WiFi/wireless interface automatically.
    On Windows with Npcap, interfaces are listed by Scapy.
    Falls back to the first active interface with an IP.
    """
    # Try to find WiFi interface by name hints
    wifi_hints = ["wi-fi", "wifi", "wlan", "wireless", "802.11"]
    
    # Get psutil interfaces with addresses
    psutil_ifaces = psutil.net_if_addrs()
    psutil_stats  = psutil.net_if_stats()
    
    # Find active interfaces
    active = []
    for name, stats in psutil_stats.items():
        if stats.isup and name in psutil_ifaces:
            addrs = psutil_ifaces[name]
            for addr in addrs:
                if addr.family == 2:  # AF_INET = IPv4
                    active.append((name, addr.address))

    # Prefer WiFi by name
    for name, ip in active:
        if any(h in name.lower() for h in wifi_hints):
            print(f"[+] WiFi interface detected: {name} ({ip})")
            return name, ip

    # Fallback — pick first non-loopback active interface
    for name, ip in active:
        if not ip.startswith("127."):
            print(f"[+] Using interface: {name} ({ip})")
            return name, ip

    return None, None

IFACE_NAME, LOCAL_IP = get_wifi_interface()
print(f"[+] Sniffing on: {IFACE_NAME} | Local IP: {LOCAL_IP}")

# ── ─────────────────────────────────────────────────────────────────────────
#   STEP 2 — Shared State
# ─────────────────────────────────────────────────────────────────────────────

class CaptureState:
    def __init__(self):
        self.packets        = deque(maxlen=1000)
        self.protocol_counts = defaultdict(int)
        self.src_ip_counts  = defaultdict(int)
        self.dst_ip_counts  = defaultdict(int)
        self.port_counts    = defaultdict(int)
        self.bandwidth_history = deque(maxlen=60)
        self.alerts         = deque(maxlen=100)
        self.total_packets  = 0
        self.total_bytes    = 0
        self.start_time     = time.time()
        self.lock           = threading.Lock()

        # Per-second counters (reset every second)
        self._sec_bytes  = 0
        self._sec_pkts   = 0
        self._last_tick  = time.time()

        # For port scan detection
        self._ip_ports   = defaultdict(set)   # src_ip → set of dst_ports seen
        self._icmp_count = defaultdict(int)    # src_ip → icmp count in window
        self._icmp_window_start = time.time()

state = CaptureState()

# ── ─────────────────────────────────────────────────────────────────────────
#   STEP 3 — Protocol Classifier
# ─────────────────────────────────────────────────────────────────────────────

def classify_protocol(pkt) -> str:
    """Return the highest-level protocol name for a packet."""
    if ARP in pkt:
        return "ARP"
    if IP not in pkt and IPv6 not in pkt:
        return "Other"
    if ICMP in pkt:
        return "ICMP"
    if DNS in pkt:
        return "DNS"
    if TCP in pkt:
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport == 443 or sport == 443:
            return "HTTPS"
        if dport == 80 or sport == 80:
            return "HTTP"
        if dport == 22 or sport == 22:
            return "SSH"
        if dport == 21 or sport == 21:
            return "FTP"
        if dport == 25 or sport == 25:
            return "SMTP"
        if dport == 3306 or sport == 3306:
            return "MySQL"
        if dport == 5432 or sport == 5432:
            return "PostgreSQL"
        if dport == 3389 or sport == 3389:
            return "RDP"
        if dport == 23 or sport == 23:
            return "Telnet"
        return "TCP"
    if UDP in pkt:
        dport = pkt[UDP].dport
        sport = pkt[UDP].sport
        if dport == 53 or sport == 53:
            return "DNS"
        if dport == 67 or dport == 68:
            return "DHCP"
        if dport == 123:
            return "NTP"
        return "UDP"
    return "Other"

# ── ─────────────────────────────────────────────────────────────────────────
#   STEP 4 — Threat Detection
# ─────────────────────────────────────────────────────────────────────────────

SENSITIVE_PORTS = {
    22: "SSH", 23: "Telnet", 3389: "RDP",
    445: "SMB", 135: "RPC", 137: "NetBIOS",
    21: "FTP", 25: "SMTP", 110: "POP3"
}

def detect_threats(pkt, parsed: dict) -> list:
    alerts = []
    src = parsed.get("src_ip", "")
    proto = parsed.get("protocol", "")
    dst_port = parsed.get("dst_port", 0)
    size = parsed.get("size", 0)
    now = time.time()

    # 1. Sensitive port access
    if dst_port in SENSITIVE_PORTS:
        alerts.append({
            "type": "warning",
            "severity": "medium",
            "message": f"{SENSITIVE_PORTS[dst_port]} connection from {src} → port {dst_port}",
            "timestamp": parsed["timestamp"]
        })

    # 2. Port scan detection (same src hitting 15+ different ports)
    if src:
        state._ip_ports[src].add(dst_port)
        if len(state._ip_ports[src]) > 15:
            alerts.append({
                "type": "danger",
                "severity": "high",
                "message": f"Port scan detected! {src} probed {len(state._ip_ports[src])} ports",
                "timestamp": parsed["timestamp"]
            })
            state._ip_ports[src] = set()  # reset after alerting

    # 3. ICMP flood (>20 ICMP packets in 5 seconds from same IP)
    if proto == "ICMP":
        if now - state._icmp_window_start > 5:
            state._icmp_count.clear()
            state._icmp_window_start = now
        state._icmp_count[src] += 1
        if state._icmp_count[src] > 20:
            alerts.append({
                "type": "danger",
                "severity": "high",
                "message": f"ICMP flood from {src} ({state._icmp_count[src]} packets/5s)",
                "timestamp": parsed["timestamp"]
            })
            state._icmp_count[src] = 0

    # 4. Oversized packets (possible fragmentation attack)
    if size > 1400:
        alerts.append({
            "type": "info",
            "severity": "low",
            "message": f"Large packet ({size} bytes) from {src} via {proto}",
            "timestamp": parsed["timestamp"]
        })

    # 5. Telnet (plaintext protocol — insecure)
    if dst_port == 23:
        alerts.append({
            "type": "danger",
            "severity": "high",
            "message": f"Insecure Telnet connection from {src} — plaintext credentials at risk!",
            "timestamp": parsed["timestamp"]
        })

    return alerts

# ── ─────────────────────────────────────────────────────────────────────────
#   STEP 5 — Packet Parser
# ─────────────────────────────────────────────────────────────────────────────

def parse_packet(pkt) -> Optional[dict]:
    """Convert a Scapy packet into a JSON-serializable dict."""
    try:
        size = len(pkt)
        ts   = datetime.now().isoformat()
        proto = classify_protocol(pkt)

        src_ip  = dst_ip  = "—"
        src_port = dst_port = 0
        ttl   = 0
        flags = ""
        dns_query = ""
        http_host = ""

        # IP layer
        if IP in pkt:
            src_ip  = pkt[IP].src
            dst_ip  = pkt[IP].dst
            ttl     = pkt[IP].ttl
        elif IPv6 in pkt:
            src_ip  = pkt[IPv6].src
            dst_ip  = pkt[IPv6].dst

        # Transport layer
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags    = str(pkt[TCP].flags)
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        # ARP
        if ARP in pkt:
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst

        # DNS query name
        if DNS in pkt and pkt[DNS].qd:
            try:
                dns_query = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
            except Exception:
                pass

        # HTTP host
        if HTTPRequest in pkt:
            try:
                http_host = pkt[HTTPRequest].Host.decode(errors="ignore")
            except Exception:
                pass

        with state.lock:
            state.total_packets += 1
            pkt_id = state.total_packets
            state.total_bytes   += size
            state._sec_bytes    += size
            state._sec_pkts     += 1
            state.protocol_counts[proto] += 1
            if src_ip != "—": state.src_ip_counts[src_ip] += 1
            if dst_ip != "—": state.dst_ip_counts[dst_ip] += 1
            if dst_port:       state.port_counts[dst_port] += 1

        parsed = {
            "id":        pkt_id,
            "timestamp": ts,
            "protocol":  proto,
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "src_port":  src_port,
            "dst_port":  dst_port,
            "size":      size,
            "ttl":       ttl,
            "flags":     flags,
            "dns_query": dns_query,
            "http_host": http_host,
            "info":      f"{proto}  {src_ip}:{src_port} → {dst_ip}:{dst_port}"
                         + (f"  [{dns_query}]" if dns_query else "")
                         + (f"  [{http_host}]" if http_host else "")
        }

        # Threat detection
        threats = detect_threats(pkt, parsed)
        with state.lock:
            for t in threats:
                state.alerts.appendleft(t)

        with state.lock:
            state.packets.appendleft(parsed)

        return parsed

    except Exception as e:
        return None

# ── ─────────────────────────────────────────────────────────────────────────
#   STEP 6 — Bandwidth ticker (runs in background thread)
# ─────────────────────────────────────────────────────────────────────────────

def bandwidth_ticker():
    """Every second, snapshot bytes/packets per second into history."""
    while True:
        time.sleep(1)
        with state.lock:
            snap = {
                "timestamp":       datetime.now().isoformat(),
                "bytes_per_sec":   state._sec_bytes,
                "packets_per_sec": state._sec_pkts,
            }
            state.bandwidth_history.append(snap)
            state._sec_bytes = 0
            state._sec_pkts  = 0

bw_thread = threading.Thread(target=bandwidth_ticker, daemon=True)
bw_thread.start()

# ── ─────────────────────────────────────────────────────────────────────────
#   STEP 7 — Scapy Sniffer (background thread)
# ─────────────────────────────────────────────────────────────────────────────

capture_running = False
capture_thread  = None

def start_sniff():
    global capture_running
    print(f"[+] Starting capture on: {IFACE_NAME}")
    capture_running = True
    sniff(
        iface=IFACE_NAME,
        prn=parse_packet,
        store=False,
        stop_filter=lambda p: not capture_running
    )

def launch_capture():
    global capture_thread, capture_running
    if capture_thread and capture_thread.is_alive():
        return
    capture_running = True
    capture_thread = threading.Thread(target=start_sniff, daemon=True)
    capture_thread.start()

def stop_capture():
    global capture_running
    capture_running = False

# Auto-start on server boot
launch_capture()

# ── ─────────────────────────────────────────────────────────────────────────
#   STEP 8 — REST Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/stats")
def get_stats():
    with state.lock:
        uptime  = int(time.time() - state.start_time)
        net_io  = psutil.net_io_counters()
        top_src = sorted(state.src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_dst = sorted(state.dst_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_ports = sorted(state.port_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_packets":       state.total_packets,
            "total_bytes":         state.total_bytes,
            "uptime_seconds":      uptime,
            "packets_per_second":  round(state.total_packets / max(uptime, 1), 2),
            "bytes_per_second":    round(state.total_bytes   / max(uptime, 1), 2),
            "protocol_distribution": dict(state.protocol_counts),
            "top_source_ips":  [{"ip": ip, "count": c} for ip, c in top_src],
            "top_dest_ips":    [{"ip": ip, "count": c} for ip, c in top_dst],
            "top_ports":       [{"port": p, "count": c} for p, c in top_ports],
            "capture_running": capture_running,
            "interface":       IFACE_NAME,
            "local_ip":        LOCAL_IP,
            "system": {
                "cpu_percent":    psutil.cpu_percent(interval=None),
                "memory_percent": psutil.virtual_memory().percent,
                "net_bytes_sent": net_io.bytes_sent,
                "net_bytes_recv": net_io.bytes_recv,
            }
        }

@app.get("/api/packets")
def get_packets(limit: int = 100, protocol: Optional[str] = None):
    with state.lock:
        pkts = list(state.packets)
    if protocol and protocol != "ALL":
        pkts = [p for p in pkts if p["protocol"] == protocol]
    return {"packets": pkts[:limit], "total": len(pkts)}

@app.get("/api/bandwidth")
def get_bandwidth():
    with state.lock:
        return {"history": list(state.bandwidth_history)}

@app.get("/api/alerts")
def get_alerts():
    with state.lock:
        return {"alerts": list(state.alerts)}

@app.get("/api/interfaces")
def get_interfaces():
    """List all available network interfaces."""
    ifaces = []
    stats  = psutil.net_if_stats()
    addrs  = psutil.net_if_addrs()
    for name, st in stats.items():
        ip = "—"
        if name in addrs:
            for a in addrs[name]:
                if a.family == 2:
                    ip = a.address; break
        ifaces.append({"name": name, "ip": ip, "is_up": st.isup, "speed": st.speed})
    return {"interfaces": ifaces, "current": IFACE_NAME}

@app.post("/api/capture/start")
def api_start():
    launch_capture()
    return {"status": "started", "interface": IFACE_NAME}

@app.post("/api/capture/stop")
def api_stop():
    stop_capture()
    return {"status": "stopped"}

@app.post("/api/reset")
def reset():
    stop_capture()
    with state.lock:
        state.packets.clear()
        state.bandwidth_history.clear()
        state.protocol_counts.clear()
        state.src_ip_counts.clear()
        state.dst_ip_counts.clear()
        state.port_counts.clear()
        state.alerts.clear()
        state.total_packets = 0
        state.total_bytes   = 0
        state.start_time    = time.time()
        state._sec_bytes = state._sec_pkts = 0
        state._ip_ports.clear()
        state._icmp_count.clear()
    launch_capture()
    return {"status": "reset"}

@app.get("/")
def root():
    return {
        "app": "NetScan Real Capture",
        "interface": IFACE_NAME,
        "local_ip": LOCAL_IP,
        "docs": "/docs",
        "ws":   "ws://localhost:8000/ws/live"
    }

# ── ─────────────────────────────────────────────────────────────────────────
#   STEP 9 — WebSocket (live stream to browser)
# ─────────────────────────────────────────────────────────────────────────────

@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    await websocket.accept()
    last_sent = 0
    try:
        while True:
            await asyncio.sleep(0.8)

            with state.lock:
                # Send packets captured since last push
                new_pkts = [p for p in state.packets if p["id"] > last_sent]
                new_pkts.reverse()   # oldest first
                if new_pkts:
                    last_sent = new_pkts[-1]["id"]

                bw_snap = list(state.bandwidth_history)[-1] if state.bandwidth_history else {}
                uptime  = int(time.time() - state.start_time)

                payload = {
                    "type":    "batch",
                    "packets": new_pkts[:30],   # max 30 per push
                    "bandwidth_snap": bw_snap,
                    "stats": {
                        "total_packets":   state.total_packets,
                        "total_bytes":     state.total_bytes,
                        "alerts_count":    len(state.alerts),
                        "uptime":          uptime,
                        "pps":  round(state.total_packets / max(uptime, 1), 1),
                        "bps":  round(state.total_bytes   / max(uptime, 1), 1),
                        "protocol_distribution": dict(state.protocol_counts),
                        "top_src_ips": sorted(state.src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:8],
                        "capture_running": capture_running,
                        "interface":       IFACE_NAME,
                    },
                    "new_alerts": [state.alerts[0]] if state.alerts else []
                }

            await websocket.send_text(json.dumps(payload))

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[WS] Error: {e}")