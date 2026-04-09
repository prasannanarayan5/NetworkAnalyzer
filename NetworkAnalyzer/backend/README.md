# NetScan Backend — Project Structure

## Overview

This is a **modular, production-ready** WiFi packet capture and analysis system. The codebase has been refactored from a monolithic `main.py` into clean, separated components following SOLID principles.

## Directory Structure

```
backend/
├── config.py              # Configuration constants
├── models.py              # Pydantic data models & schemas
├── protocol_classifier.py # Protocol detection logic
├── threat_detector.py     # Security threat detection
├── packet_parser.py       # Packet parsing & conversion
├── packet_sniffer.py      # Scapy wrapper & capture control
├── capture_state.py       # Thread-safe state management
├── routes.py              # REST API endpoints
├── websocket_handler.py   # WebSocket live streaming
├── utils.py               # Helper utilities
├── main.py                # FastAPI app entry point
├── requirements.txt       # Python dependencies
└── README.md              # This file
```

## Module Descriptions

### `config.py`
**Purpose:** Centralized configuration and constants.

**Contains:**
- Capture buffer sizes
- Threat detection thresholds
- Server settings
- Port mappings

**Usage:**
```python
from config import MAX_PACKET_BUFFER, SENSITIVE_PORTS
```

---

### `models.py`
**Purpose:** Pydantic data models for type safety and validation.

**Contains:**
- `PacketInfo` — Parsed packet representation
- `Alert` — Security alert model
- `BandwidthSnapshot` — Per-second throughput data
- `ProtocolStats` — Overall statistics
- Response models for API endpoints

**Usage:**
```python
from models import PacketInfo, Alert, ProtocolStats

packet = PacketInfo(
    id=1,
    timestamp="2026-04-05T10:30:45",
    protocol="TCP",
    src_ip="192.168.1.100",
    ...
)
```

---

### `protocol_classifier.py`
**Purpose:** Protocol detection and packet field extraction.

**Key Functions:**
- `classify_protocol(pkt)` — Determine highest-level protocol
- `get_ips(pkt)` — Extract source/destination IPs
- `get_ports(pkt)` — Extract transport layer ports
- `extract_dns_query(pkt)` — Extract DNS domain names
- `extract_http_host(pkt)` — Extract HTTP Host header

**Protocols Detected:**
TCP, UDP, HTTP, HTTPS, SSH, FTP, DNS, DHCP, NTP, ICMP, ARP, MySQL, PostgreSQL, RDP, Telnet, SMTP

**Usage:**
```python
from protocol_classifier import classify_protocol, get_ips

protocol = classify_protocol(scapy_packet)
src_ip, dst_ip = get_ips(scapy_packet)
```

---

### `threat_detector.py`
**Purpose:** Security threat detection and alerting.

**Detectable Threats:**
1. **Sensitive Port Access** — Connections to SSH, RDP, Telnet, etc.
2. **Port Scan** — Single IP probing 15+ different ports
3. **ICMP Flood** — >20 ICMP packets in 5 seconds
4. **Oversized Packets** — >1400 bytes (fragmentation attacks)
5. **Insecure Telnet** — Plaintext credential transmission

**Usage:**
```python
from threat_detector import ThreatDetector

detector = ThreatDetector()
alerts = detector.detect_threats(scapy_packet, parsed_packet_dict)
```

---

### `packet_parser.py`
**Purpose:** Convert Scapy packets to structured format.

**Class:** `PacketParser`
- `parse_packet(pkt)` → `PacketInfo`
- Handles protocol classification, IP/port extraction
- Integrates threat detection

**Usage:**
```python
from packet_parser import PacketParser

parser = PacketParser(threat_detector_instance)
packet_info = parser.parse_packet(scapy_packet)
```

---

### `packet_sniffer.py`
**Purpose:** Manage Scapy packet capture in background thread.

**Class:** `PacketSniffer`
- Auto-detects WiFi interface
- Manages capture thread lifecycle
- Integrates parser and threat detector

**Methods:**
- `start()` — Begin packet capture
- `stop()` — Stop packet capture
- `is_running()` → bool
- `reset()` — Reset internal state

**Usage:**
```python
from packet_sniffer import PacketSniffer
from capture_state import CaptureState

state = CaptureState()
sniffer = PacketSniffer(state)
sniffer.start()
```

---

### `capture_state.py`
**Purpose:** Thread-safe state management for captured data.

**Class:** `CaptureState`
- Manages packet buffers, statistics, alerts
- Thread-locked operations
- Bandwidth snapshots

**Key Methods:**
- `add_packet(packet, alerts)` — Store packet and threats
- `get_stats()` → Dict with all statistics
- `get_recent_packets(limit, protocol)` → List
- `snapshot_bandwidth()` → BandwidthSnapshot
- `reset()` — Clear all data

**Usage:**
```python
from capture_state import CaptureState

state = CaptureState()
state.add_packet(packet_info, threat_list)
stats = state.get_stats()
```

---

### `routes.py`
**Purpose:** REST API endpoint definitions.

**Function:** `create_routes(sniffer, state)`
Returns a FastAPI router with endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Server info |
| `/api/stats` | GET | Current statistics |
| `/api/packets` | GET | Captured packets |
| `/api/bandwidth` | GET | Bandwidth history |
| `/api/alerts` | GET | Security alerts |
| `/api/dns` | GET | DNS queries |
| `/api/interfaces` | GET | Network interfaces |
| `/api/capture/start` | POST | Start capture |
| `/api/capture/stop` | POST | Stop capture |
| `/api/reset` | POST | Reset all data |

**Usage:**
```python
from routes import create_routes

api_router = create_routes(sniffer, state)
app.include_router(api_router)
```

---

### `websocket_handler.py`
**Purpose:** Live WebSocket streaming to browser.

**Class:** `WebSocketHandler`
- Manages WebSocket connections
- Sends batch updates every 0.8 seconds
- Includes packets, stats, bandwidth, alerts

**Usage:**
```python
from websocket_handler import WebSocketHandler

ws_handler = WebSocketHandler(state, sniffer)
await ws_handler.handle_connection(websocket)
```

---

### `utils.py`
**Purpose:** Reusable utility functions.

**Functions:**
- `get_network_interfaces()` — List all network interfaces
- `get_system_metrics()` → SystemMetrics
- `format_bytes(n)` → str (human-readable)
- `format_time(s)` → str (MM:SS format)

**Usage:**
```python
from utils import format_bytes, get_system_metrics

size_str = format_bytes(1048576)  # "1.0 MB"
metrics = get_system_metrics()
```

---

### `main.py`
**Purpose:** FastAPI application entry point.

**Responsibilities:**
- Initialize FastAPI app
- Create and configure services
- Register API routes
- Setup WebSocket endpoint
- Start background threads
- Handle startup/shutdown events

**Entry Point:**
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

---

## Installation & Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Server
```bash
# Development mode (with auto-reload)
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Production mode
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
```

### 3. Access API
- **REST API Docs:** http://localhost:8000/docs
- **WebSocket:** ws://localhost:8000/ws/live

---

## Architecture Benefits

✅ **Modularity** — Each module has a single responsibility  
✅ **Testability** — Independent components are easier to test  
✅ **Maintainability** — Clean separation of concerns  
✅ **Extensibility** — New features don't require modifying core logic  
✅ **Thread Safety** — Proper locking in shared state  
✅ **Type Safety** — Pydantic models with validation  
✅ **Documentation** — Docstrings throughout  

---

## Data Flow

```
[Scapy Packet] 
    ↓
[PacketSniffer] (threaded)
    ↓
[PacketParser] (classification + parsing)
    ↓
[ThreatDetector] (security analysis)
    ↓
[CaptureState] (thread-safe storage)
    ├→ [Routes.py] (REST API)
    └→ [WebSocketHandler] (Live streaming to browser)
```

---

## Configuration

Edit `config.py` to customize:

```python
# Buffer sizes
MAX_PACKET_BUFFER = 1000
MAX_ALERTS = 100

# Threat thresholds
PORT_SCAN_THRESHOLD = 15
ICMP_FLOOD_THRESHOLD = 20
PACKET_SIZE_ANOMALY = 1400

# Server settings
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 8000
```

---

## Extending the System

### Add New Threat Detection
1. Add logic to `ThreatDetector.detect_threats()`
2. Create `Alert` object with appropriate severity
3. Return in alerts list

### Add New Protocol
1. Add classification in `protocol_classifier.py`
2. Add port mapping in appropriate `_classify_*()` function
3. Update frontend if needed

### Add New REST Endpoint
1. Create endpoint function in `routes.py`
2. Use Pydantic models for request/response
3. Register in `create_routes()` function

---

## Performance Notes

- Packet capture runs in separate thread — doesn't block API
- State uses deque with `maxlen` for automatic rotation
- Thread locks are minimal and focused
- WebSocket updates batch packets for efficiency
- All numeric operations are O(1) or O(log n)

---

## Troubleshooting

**"Interface not found"**
- Ensure Npcap is installed (Windows)
- Check available interfaces: `psutil.net_if_addrs()`

**"Packets not appearing"**
- Verify capture is running: `GET /api/stats`
- Check WebSocket connection in browser console
- Ensure network interface is active

**"High CPU usage"**
- Reduce packet buffer size in config
- Increase WebSocket batch interval
- Consider packet filtering

---

## License

See LICENSE file

