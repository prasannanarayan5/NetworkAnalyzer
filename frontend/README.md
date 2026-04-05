# NetScan v2 — Real WiFi Packet Capture

## ⚠️ Prerequisites (Windows)

### Step 1 — Install Npcap
Download and install from: https://npcap.com/#download
✅ Check "WinPcap API-compatible Mode" during install

### Step 2 — Install dependencies
```bash
cd backend
pip install -r requirements.txt
```

## 🚀 Running (MUST be Administrator)

Right-click PowerShell → "Run as Administrator"
```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
Then open `frontend/index.html` in your browser.

---

## What gets captured from your WiFi

| Protocol | What you'll see |
|---|---|
| DNS | Every domain your device looks up |
| HTTPS | Encrypted traffic to websites |
| HTTP | Unencrypted web traffic |
| TCP | All connection handshakes |
| UDP | Streaming, gaming, VoIP |
| ICMP | Ping packets |
| ARP | Who's on your local network |
| DHCP | IP address assignments |

## Threat Detection

| Alert | Trigger |
|---|---|
| 🔴 Port Scan | Same IP hits 15+ different ports |
| 🔴 ICMP Flood | >20 ICMP packets in 5 seconds |
| 🔴 Telnet | Port 23 connection detected |
| ⚠️ Sensitive Port | SSH/RDP/FTP/SMB access |
| ℹ️ Large Packet | Packet > 1400 bytes |

## API Endpoints

```
GET  /api/stats           → live stats + system metrics
GET  /api/packets         → captured packets (filter by protocol)
GET  /api/alerts          → security alerts
GET  /api/bandwidth       → bandwidth history
GET  /api/interfaces      → list network interfaces
POST /api/capture/start   → start sniffing
POST /api/capture/stop    → stop sniffing
POST /api/reset           → clear all data
WS   /ws/live             → real-time packet stream
```
