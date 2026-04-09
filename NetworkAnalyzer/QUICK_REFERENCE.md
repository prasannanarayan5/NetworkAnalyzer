# Quick Reference Guide

## 🚀 Get Started in 30 Seconds

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

Open `frontend/index.html` → Click ▶ Start

---

## 📁 Where to Find Things

### I want to change...

**The color scheme**
→ `frontend/index.html` - Find CSS `:root { --accent: #00d4ff; }`

**Threat detection rules**
→ `backend/threat_detector.py` - Class `ThreatDetector.detect_threats()`

**Server configuration**
→ `backend/config.py` - Edit constants

**An API endpoint**
→ `backend/routes.py` - Function `create_routes()`

**Packet capture logic**
→ `backend/packet_sniffer.py` - Class `PacketSniffer`

**Protocol detection**
→ `backend/protocol_classifier.py` - Function `classify_protocol()`

**Dashboard layout**
→ `frontend/index.html` - Find `<main>` with grid layout

**Data models**
→ `backend/models.py` - Pydantic models

**Utility functions**
→ `backend/utils.py` - Helper functions

---

## 🔌 Module Dependencies

```
main.py
├── Imports: config, CaptureState, PacketSniffer, create_routes, WebSocketHandler
│
PacketSniffer
├── Imports: config, PacketParser, ThreatDetector
│
PacketParser
├── Imports: protocol_classifier, models
│
ThreatDetector
├── Imports: config, models
│
create_routes (routes.py)
├── Imports: PacketSniffer, CaptureState, utils, models
│
WebSocketHandler
├── Imports: config, CaptureState, PacketSniffer
```

---

## 🎯 Key Classes & Methods

### CaptureState
```python
state = CaptureState()
state.add_packet(packet_info, alerts)
stats = state.get_stats()
state.reset()
```

### PacketSniffer
```python
sniffer = PacketSniffer(state)
sniffer.start()
sniffer.stop()
sniffer.is_running()
```

### ThreatDetector
```python
detector = ThreatDetector()
alerts = detector.detect_threats(scapy_pkt, parsed_dict)
```

### Protocol Classification
```python
from protocol_classifier import classify_protocol, get_ips, get_ports
protocol = classify_protocol(pkt)
src_ip, dst_ip = get_ips(pkt)
```

---

## 📊 REST API Quick Ref

| Endpoint | Method | Returns |
|----------|--------|---------|
| `/api/stats` | GET | All statistics |
| `/api/packets` | GET | List of packets |
| `/api/alerts` | GET | Security alerts |
| `/api/bandwidth` | GET | Bandwidth history |
| `/api/interfaces` | GET | Network interfaces |
| `/api/capture/start` | POST | Start capture |
| `/api/capture/stop` | POST | Stop capture |
| `/api/reset` | POST | Clear all data |

---

## 🔧 Common Tasks

### Add a new threat detection

**In `backend/threat_detector.py`:**
```python
def detect_threats(self, pkt, parsed):
    alerts = []
    
    # Your logic here
    if your_condition:
        alerts.append(Alert(
            type="danger",
            severity="high",
            message="Your message"
        ))
    
    return alerts
```

### Add a new REST endpoint

**In `backend/routes.py`:**
```python
@router.get("/api/your-endpoint")
def your_endpoint():
    """Description."""
    return {"result": state.your_method()}
```

### Change a configuration value

**In `backend/config.py`:**
```python
YOUR_SETTING = new_value  # Edit or add here
```

**Then use it:**
```python
from config import YOUR_SETTING
```

### Add a new protocol detection

**In `backend/protocol_classifier.py`:**
```python
def _classify_tcp(pkt) -> str:
    dport = pkt[TCP].dport
    
    if dport == YOUR_PORT:
        return "YOUR_PROTOCOL"
    
    return "TCP"
```

---

## 🐛 Debugging Tips

### Check API Response
```javascript
// In browser console:
fetch('http://localhost:8000/api/stats')
  .then(r => r.json())
  .then(console.log)
```

### Check WebSocket
```javascript
// In browser console:
console.log(ws.readyState);  // 1=OPEN, 0=CONNECTING, 3=CLOSED
```

### Check Packet Count
```python
# In Python:
from capture_state import state
print(state.get_stats()['total_packets'])
```

### Enable Debug Logging
```python
# In main.py:
uvicorn main:app --reload --log-level debug
```

---

## 📦 Dependencies

**Required:**
- `fastapi` - Web framework
- `uvicorn` - ASGI server
- `scapy` - Packet capture
- `psutil` - System metrics
- `pydantic` - Data validation

**Optional:**
- `websockets` - WebSocket support (included in fastapi)

Install all:
```bash
pip install -r requirements.txt
```

---

## 🔗 File Relationships

```
frontend/index.html
    ↓ (HTTP & WebSocket)
main.py (FastAPI app)
    ├─ routes.py (REST endpoints)
    │   └─ capture_state.py (data storage)
    │
    ├─ websocket_handler.py (live stream)
    │   └─ capture_state.py
    │
    └─ packet_sniffer.py (background capture)
        ├─ packet_parser.py
        │   ├─ protocol_classifier.py
        │   ├─ threat_detector.py
        │   └─ models.py
        └─ capture_state.py
```

---

## 🚢 Deployment

### Development
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Production
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
```

### Docker (future)
```bash
docker run -it --cap-add=NET_ADMIN netscan
```

---

## 📝 File Size Reference

| File | Size | Purpose |
|------|------|---------|
| config.py | ~30 lines | Constants |
| models.py | ~120 lines | Data types |
| protocol_classifier.py | ~100 lines | Protocol detection |
| threat_detector.py | ~90 lines | Security analysis |
| packet_parser.py | ~60 lines | Packet conversion |
| packet_sniffer.py | ~70 lines | Capture control |
| capture_state.py | ~150 lines | State management |
| routes.py | ~90 lines | REST API |
| websocket_handler.py | ~60 lines | Live streaming |
| utils.py | ~50 lines | Helpers |
| main.py | ~130 lines | App entry |

**Total: ~1000 lines** (well-organized and documented)

---

## 🎓 Learning Path

1. **Read:** `README.md` (2 min)
2. **Read:** `PROJECT_STRUCTURE.md` (5 min)
3. **Run:** `uvicorn main:app --reload` (1 min)
4. **Test:** http://localhost:8000/docs (3 min)
5. **Explore:** Each module's docstrings (10 min)
6. **Modify:** Change a config value and restart (2 min)
7. **Extend:** Add a new threat detection rule (15 min)

**Total time to productive: ~40 minutes**

---

## 🆘 Troubleshooting

**Q: "ModuleNotFoundError: No module named 'scapy'"**
A: Run `pip install -r requirements.txt`

**Q: "No packets appearing"**
A: Click ▶ Start button, check Network interface is detected

**Q: "Permission denied"**
A: Run as Administrator (Windows) or sudo (Linux)

**Q: "Port 8000 already in use"**
A: Kill other process or use different port: `--port 8001`

**Q: "WebSocket connection failed"**
A: Check backend is running, refresh browser page

---

## 💡 Pro Tips

- Use http://localhost:8000/docs to test API endpoints
- Edit `config.py` to tune threat detection thresholds
- Check `capture_state.py` for available data methods
- Look at `models.py` to understand data structure
- Browser DevTools (F12) useful for frontend debugging

---

**Questions? Check the detailed README files:**
- Backend: `backend/README.md`
- Frontend: `frontend/README.md`
- Architecture: `PROJECT_STRUCTURE.md`
