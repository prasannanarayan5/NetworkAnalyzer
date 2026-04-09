# ✅ Setup Verification & Testing Guide

## 📋 Pre-Flight Checklist

Run this to verify everything is set up correctly.

### Step 1: Verify File Structure
```bash
# All 13 backend files should exist:
cd backend

# Check these files exist:
ls config.py models.py protocol_classifier.py threat_detector.py
ls packet_parser.py packet_sniffer.py capture_state.py routes.py
ls websocket_handler.py utils.py main.py requirements.txt README.md
```

**Expected output:** All files listed without errors ✅

### Step 2: Verify Dependencies
```bash
# Install requirements
pip install -r requirements.txt

# Verify installations
python -c "import fastapi; print('FastAPI OK')"
python -c "import scapy; print('Scapy OK')"
python -c "import psutil; print('psutil OK')"
python -c "import pydantic; print('Pydantic OK')"
```

**Expected output:**
```
FastAPI OK
Scapy OK
psutil OK
Pydantic OK
```

### Step 3: Check Network Interface
```bash
python -c "import psutil; print(list(psutil.net_if_addrs().keys()))"
```

**Expected output:** List of network interfaces (including WiFi adapter)

### Step 4: Start the Backend
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Expected output:**
```
INFO:     Started server process [####]
INFO:     Waiting for application startup.
INFO:     [+] NetScan server starting on 0.0.0.0:8000
INFO:     [+] Interface: [Your interface] | IP: [Your IP]
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### Step 5: Test REST API
```bash
# In another terminal:
curl http://localhost:8000/api/stats | python -m json.tool
```

**Expected output:** JSON with statistics ✅

### Step 6: Test WebSocket
```javascript
// In browser console (http://localhost:8000)
ws = new WebSocket('ws://localhost:8000/ws/live');
ws.onopen = () => console.log('WebSocket connected!');
ws.onmessage = e => console.log(JSON.parse(e.data).type);
```

**Expected output:** "WebSocket connected!" then batch messages ✅

---

## 🧪 Testing Commands

### Test Interface Detection
```python
from packet_sniffer import PacketSniffer
from capture_state import CaptureState

state = CaptureState()
sniffer = PacketSniffer(state)
print(f"Interface: {sniffer.interface_name}")
print(f"Local IP: {sniffer.local_ip}")
```

### Test Protocol Classification
```python
from protocol_classifier import classify_protocol
from scapy.all import IP, TCP, UDP

# Create a test packet
pkt = IP()/TCP(dport=443)
print(classify_protocol(pkt))  # Should print "HTTPS"
```

### Test Threat Detection
```python
from threat_detector import ThreatDetector

detector = ThreatDetector()
parsed = {"src_ip": "192.168.1.1", "protocol": "ICMP", "dst_port": 23, "size": 500, "timestamp": "2026-04-05T12:00:00"}
alerts = detector.detect_threats(None, parsed)
print(f"Detected {len(alerts)} threats")
```

### Test State Management
```python
from capture_state import CaptureState
from models import PacketInfo

state = CaptureState()
packet = PacketInfo(id=1, timestamp="2026-04-05T12:00:00", protocol="TCP", 
                   src_ip="192.168.1.1", dst_ip="8.8.8.8", src_port=54321, 
                   dst_port=443, size=512, ttl=64, flags="S", info="test")
state.add_packet(packet, [])
stats = state.get_stats()
print(f"Total packets: {stats['total_packets']}")  # Should print 1
```

---

## 🔍 Code Quality Checks

### Import All Modules
```python
# Test that all imports work
from config import MAX_PACKET_BUFFER
from models import PacketInfo, Alert
from protocol_classifier import classify_protocol
from threat_detector import ThreatDetector
from packet_parser import PacketParser
from packet_sniffer import PacketSniffer
from capture_state import CaptureState
from routes import create_routes
from websocket_handler import WebSocketHandler
from utils import format_bytes

print("✅ All imports successful!")
```

### Check Type Hints
```python
# All functions should have type hints
import inspect
from models import PacketInfo

# Check PacketInfo fields
print(PacketInfo.model_fields.keys())
# Should show: id, timestamp, protocol, src_ip, dst_ip, src_port, dst_port, size, ttl, flags, dns_query, http_host, info
```

### Verify Documentation
```python
# All modules should have docstrings
import config, models, protocol_classifier, threat_detector
import packet_parser, packet_sniffer, capture_state, routes
import websocket_handler, utils

modules = [config, models, protocol_classifier, threat_detector, 
           packet_parser, packet_sniffer, capture_state, routes, 
           websocket_handler, utils]

for module in modules:
    assert module.__doc__, f"Missing docstring in {module.__name__}"
    
print("✅ All modules documented!")
```

---

## 📊 API Endpoint Testing

### Using curl
```bash
# Test GET endpoints
curl http://localhost:8000/
curl http://localhost:8000/api/stats
curl http://localhost:8000/api/packets
curl http://localhost:8000/api/alerts

# Test POST endpoints
curl -X POST http://localhost:8000/api/capture/start
curl -X POST http://localhost:8000/api/capture/stop
curl -X POST http://localhost:8000/api/reset
```

### Using Python
```python
import requests

API = "http://localhost:8000"

# Test all endpoints
print("Testing GET /")
r = requests.get(f"{API}/")
assert r.status_code == 200

print("Testing GET /api/stats")
r = requests.get(f"{API}/api/stats")
assert r.status_code == 200
print(r.json())

print("Testing POST /api/capture/start")
r = requests.post(f"{API}/api/capture/start")
assert r.status_code == 200

print("Testing POST /api/capture/stop")
r = requests.post(f"{API}/api/capture/stop")
assert r.status_code == 200

print("✅ All endpoints working!")
```

---

## 🌐 Frontend Testing

### Open Interactive API Docs
```
http://localhost:8000/docs
```

Try out each endpoint through the Swagger UI.

### Test Dashboard Connection
1. Open `frontend/index.html` in browser
2. Check browser DevTools (F12) → Console
3. Should see WebSocket message: `type: "batch"`
4. Click "▶ Start" button
5. Should begin capturing packets

### Check Network Tab
- WebSocket frames should show `type: batch` messages
- API calls should return 200 status codes

---

## 🐛 Debugging Checklist

| Issue | Debug Steps |
|-------|-------------|
| Module not found | `pip install -r requirements.txt` |
| Port 8000 in use | Check other processes: `lsof -i :8000` |
| WebSocket fails | Check firewall, ensure backend running |
| No packets captured | Verify interface detected, run as admin |
| CPU usage high | Reduce `MAX_PACKET_BUFFER` in config |

---

## 📈 Performance Baseline

Test performance on your system:

```python
import time
from capture_state import CaptureState
from models import PacketInfo

state = CaptureState()

# Add 1000 packets
start = time.time()
for i in range(1000):
    packet = PacketInfo(
        id=i,
        timestamp="2026-04-05T12:00:00",
        protocol="TCP",
        src_ip=f"192.168.1.{i % 255}",
        dst_ip="8.8.8.8",
        src_port=54321,
        dst_port=443,
        size=512,
        ttl=64,
        flags="S",
        info="test"
    )
    state.add_packet(packet, [])

elapsed = time.time() - start
print(f"Added 1000 packets in {elapsed:.3f}s ({1000/elapsed:.0f} pkt/s)")

# Get stats
start = time.time()
for _ in range(100):
    state.get_stats()
elapsed = time.time() - start
print(f"Got stats 100 times in {elapsed:.3f}s ({100/elapsed:.0f} calls/s)")
```

**Expected Performance:**
- ✅ 1000+ packets/second
- ✅ 100+ stats calls/second in under 1ms

---

## ✨ Final Verification

Run this comprehensive test:

```python
#!/usr/bin/env python3
"""Comprehensive system verification."""

print("=" * 60)
print("NetScan Refactored - Verification Script")
print("=" * 60)

# 1. Import all modules
print("\n✓ Testing imports...")
try:
    from config import MAX_PACKET_BUFFER
    from models import PacketInfo, Alert
    from protocol_classifier import classify_protocol
    from threat_detector import ThreatDetector
    from packet_parser import PacketParser
    from packet_sniffer import PacketSniffer
    from capture_state import CaptureState
    from routes import create_routes
    from websocket_handler import WebSocketHandler
    from utils import format_bytes
    print("  All imports successful ✅")
except ImportError as e:
    print(f"  Import failed ❌: {e}")
    exit(1)

# 2. Verify module docstrings
print("\n✓ Checking documentation...")
modules = [
    ("config", 30), ("models", 150), ("protocol_classifier", 100),
    ("threat_detector", 100), ("packet_parser", 70), ("packet_sniffer", 80),
    ("capture_state", 180), ("routes", 120), ("websocket_handler", 80),
    ("utils", 60)
]
for name, _ in modules:
    module = __import__(name)
    assert module.__doc__, f"Missing docstring in {name}"
print(f"  All {len(modules)} modules documented ✅")

# 3. Test CaptureState
print("\n✓ Testing CaptureState...")
state = CaptureState()
packet = PacketInfo(
    id=1, timestamp="2026-04-05T12:00:00", protocol="TCP",
    src_ip="192.168.1.1", dst_ip="8.8.8.8", src_port=54321,
    dst_port=443, size=512, ttl=64, flags="S", info="test"
)
state.add_packet(packet, [])
stats = state.get_stats()
assert stats['total_packets'] == 1
print("  CaptureState working ✅")

# 4. Test ThreatDetector
print("\n✓ Testing ThreatDetector...")
detector = ThreatDetector()
parsed = {
    "src_ip": "192.168.1.1",
    "protocol": "ICMP",
    "dst_port": 23,
    "size": 500,
    "timestamp": "2026-04-05T12:00:00"
}
alerts = detector.detect_threats(None, parsed)
assert isinstance(alerts, list)
print("  ThreatDetector working ✅")

# 5. Test protocol classification
print("\n✓ Testing protocol classification...")
from scapy.all import IP, TCP
pkt = IP() / TCP(dport=443)
proto = classify_protocol(pkt)
assert proto == "HTTPS"
print("  Protocol classification working ✅")

# 6. Test utility functions
print("\n✓ Testing utilities...")
assert format_bytes(1024) == "1.0 KB"
assert format_bytes(1048576) == "1.0 MB"
print("  Utilities working ✅")

print("\n" + "=" * 60)
print("✅ All verification checks passed!")
print("=" * 60)
print("\nYou're ready to run the application:")
print("  cd backend")
print("  uvicorn main:app --reload")
