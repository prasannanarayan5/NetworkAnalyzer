# NetScan Frontend — Real-Time WiFi Analyzer

## Overview

Modern, real-time network packet visualization dashboard built with vanilla JavaScript and Chart.js. Live updates via WebSocket for zero-latency monitoring.

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

## Features

### 📊 Real-Time Dashboards
- **Live Packet Feed** — Scroll through captured packets with protocol filtering
- **Bandwidth Chart** — Dual-axis graph (bytes/s and packets/s)
- **Protocol Distribution** — Doughnut chart of protocol breakdown
- **Security Alerts** — Real-time threat notifications

### 🔍 Analysis Tools
- **Top Talkers** — Source and destination IP rankings
- **Port Analysis** — Most active ports
- **DNS Queries** — Live DNS request feed
- **System Metrics** — CPU, memory, network I/O

### 🛡️ Security Features
- **Threat Detection** — Port scans, ICMP floods, oversized packets
- **Alert Severity** — High (🔴), Medium (⚠️), Low (ℹ️)
- **Smart Filtering** — Filter packets by protocol

## What Gets Captured from Your WiFi

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

| Alert | Trigger | Severity |
|---|---|---|
| 🔴 Port Scan | Same IP hits 15+ different ports | HIGH |
| 🔴 ICMP Flood | >20 ICMP packets in 5 seconds | HIGH |
| 🔴 Telnet | Port 23 connection detected | HIGH |
| ⚠️ Sensitive Port | SSH/RDP/FTP/SMB access | MEDIUM |
| ℹ️ Large Packet | Packet > 1400 bytes | LOW |

## File Structure

```
frontend/
├── index.html    # Complete application (single-file architecture)
└── README.md     # This file
```

## Single-File Architecture

The entire frontend is embedded in `index.html`:
- **HTML** — Semantic structure (header, main grid, panels)
- **CSS** — Modern dark theme with grid layout
- **JavaScript** — Event handling, WebSocket, data visualization

**Why single-file?**
✅ No build process required  
✅ Easy deployment  
✅ Simple to understand and modify  
✅ Minimal dependencies (only Chart.js via CDN)  

## Key Components

### HTML Structure
```html
<header>          <!-- App title, interface info, controls -->
<main>            <!-- Grid layout with content panels -->
  <div class="panel">    <!-- Stat cards, charts, tables -->
```

### CSS Features
- **Grid Layout** — Responsive multi-column design
- **Dark Theme** — Custom CSS variables (--accent, --green, --red, etc.)
- **Animations** — Smooth transitions and progress bars
- **Typography** — JetBrains Mono for code, Syne for headers

### JavaScript Modules

#### WebSocket Connection
```javascript
const WS = 'ws://localhost:8000/ws/live';
ws = new WebSocket(WS);
ws.onmessage = e => handleMsg(JSON.parse(e.data));
```

#### Chart Management
```javascript
const bwChart = new Chart(ctx, { type: 'line', ... });
const protoChart = new Chart(ctx, { type: 'doughnut', ... });
```

#### Data Handlers
- `handleMsg(msg)` — Process WebSocket batch messages
- `renderTable()` — Update packet table
- `renderDNS()` — Update DNS feed
- `addAlert(a)` — Add security alert
- `renderTopIPs()` — Update IP statistics

#### Polling
```javascript
setInterval(pollStats, 3000);  // Poll /api/stats every 3 seconds
```

## Usage Guide

### Starting the Dashboard
1. Ensure backend is running on `localhost:8000`
2. Open `index.html` in a modern browser
3. Click **▶ Start** to begin capturing packets

### Interface Legend

| Element | Meaning |
|---------|---------|
| 🟢 **Live** | Connected and capturing |
| ⬡ **NetScan** | App branding |
| **Interface** | Current network adapter |
| **IP** | Local machine IP address |
| **▶ Start** | Begin packet capture |
| **↺ Reset** | Clear statistics |

### Protocol Colors

```
TCP      → Cyan (#00d4ff)
UDP      → Purple (#a78bfa)
HTTP     → Green (#00ff9d)
HTTPS    → Green (#34d399)
DNS      → Yellow (#ffc107)
ICMP     → Red (#ff4560)
SSH      → Orange (#ff6b35)
FTP      → Orange (#fb923c)
ARP      → Gray (#94a3b8)
DHCP     → Purple (#c084fc)
SMTP     → Gray (#64748b)
RDP      → Red (#ff4560)
MySQL    → Blue (#60a5fa)
PostgreSQL → Purple (#a78bfa)
```

### Filtering Packets
Click filter buttons in the **Live Packet Feed** section:
- **All** — All protocols
- **TCP/UDP** — Transport layer
- **HTTP/HTTPS** — Web traffic
- **DNS** — Domain names
- **ICMP** — Ping/diagnostics
- **SSH** — Secure shell
- **ARP** — Address resolution

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

## API Integration

### REST Endpoints Used
```javascript
const API = 'http://localhost:8000';

fetch(API + '/api/stats')           // Get statistics
fetch(API + '/api/capture/start', { method: 'POST' })
fetch(API + '/api/capture/stop', { method: 'POST' })
fetch(API + '/api/reset', { method: 'POST' })
```

### WebSocket Message Format
```json
{
  "type": "batch",
  "packets": [...],
  "bandwidth_snap": {},
  "stats": {...},
  "new_alerts": [...]
}
```

## Customization

### Change Color Scheme
Edit CSS variables in `<style>`:
```css
:root {
  --bg:     #07090d;      /* Background */
  --accent: #00d4ff;      /* Primary color */
  --green:  #00ff9d;      /* Success/positive */
  --red:    #ff4560;      /* Danger/threats */
}
```

### Adjust Chart Settings
Modify Chart.js configuration:
```javascript
const bwChart = new Chart(ctx, {
  options: {
    animation: { duration: 400 },  // Change transition speed
    scales: { ... }                 // Adjust axes
  }
});
```

### Change Update Intervals
```javascript
setInterval(pollStats, 3000);        // Change from 3 to X seconds
const WS_BATCH_INTERVAL = 0.8;      // WebSocket update frequency (backend config)
```

### Modify Panel Layout
Grid layout is in `<main>`:
```css
main {
  grid-template-columns: repeat(4, 1fr);  /* Change column count */
}
.c2 { grid-column: span 2; }  /* 2-column span */
```

## Browser Compatibility

| Browser | Support |
|---------|---------|
| Chrome/Brave | ✅ Full support |
| Firefox | ✅ Full support |
| Safari | ✅ Full support |
| Edge | ✅ Full support |
| Mobile | ⚠️ Limited (small screen) |

**Required Features:**
- ES6 JavaScript
- WebSocket API
- Canvas (for charts)
- CSS Grid

## Performance Optimization

### Current Settings
- **Max packet rows:** 200
- **Bandwidth points:** 50
- **WebSocket batch:** 30 packets/update
- **Poll interval:** 3 seconds
- **DNS query buffer:** 60 entries

### Tuning for Your Environment

**High-traffic networks:**
- Reduce `MAX_ROWS = 100`
- Increase `WS_BATCH_INTERVAL = 1.5`
- Limit `BW_POINTS = 30`

**Low-bandwidth environments:**
- Increase `MAX_ROWS = 500`
- Decrease `WS_BATCH_INTERVAL = 0.5`
- Increase `BW_POINTS = 100`

## Debugging

### Browser Console
```javascript
// Check WebSocket status
console.log(ws.readyState);  // 0-3: CONNECTING, OPEN, CLOSING, CLOSED

// Check captured packets
console.log(allPackets);

// View raw API response
fetch('http://localhost:8000/api/stats').then(r => r.json()).then(console.log);
```

### Common Issues

**"WebSocket connection failed"**
- Check backend is running: `http://localhost:8000`
- Check firewall allows WebSocket
- Check console for CORS errors

**"No packets appearing"**
- Click **▶ Start** button
- Check `/api/stats` endpoint is returning data
- Verify network interface is active

**"Charts not updating"**
- Check WebSocket connection status
- Verify backend is sending messages
- Check browser console for JavaScript errors

## Mobile Responsive Design

The dashboard is responsive with breakpoints:

```css
@media(max-width: 1100px) { /* Tablet */
  main { grid-template-columns: 1fr 1fr; }
}

@media(max-width: 680px) { /* Mobile */
  main { grid-template-columns: 1fr; }
}
```

## Future Enhancements

- 📱 Mobile app support
- 🎨 Theme selector
- 💾 Export capture data (CSV/PCAP)
- 🔔 Custom alert rules
- 📈 Historical analytics
- 🗺️ Network topology visualization

## License

See LICENSE file
