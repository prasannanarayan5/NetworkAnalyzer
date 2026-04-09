# Frontend Modules Overview

## Header Section
**What**: Logo, interface name, local IP, connection status indicator, Start/Pause and Reset buttons.

**How**: Displays the app branding and real-time connection status. The green dot animates when WebSocket is connected.

**Why**: Provides quick visual feedback on system state and one-click access to capture controls.

---

## Stat Cards (Top Row)

### 1. Packets Card
**What**: Shows total captured packets and packet rate (pkt/s).

**How**: Updates from WebSocket batch messages. Counts all packets in real-time and calculates packets-per-second.

**Why**: Quantifies network activity volume; high packet counts indicate heavy traffic.

### 2. Data Volume Card
**What**: Shows total bytes transferred and throughput (B/s).

**How**: Sums packet sizes and calculates bandwidth (bytes per second).

**Why**: Measures actual data consumption; identifies if network is being saturated.

### 3. Uptime Card
**What**: Shows capture session duration (MM:SS format).

**How**: Calculates elapsed time since capture started.

**Why**: Tracks how long the analysis session has been running.

### 4. Alerts Card
**What**: Counts security events and shows timestamp of last alert.

**How**: Increments when threat detector generates new alerts.

**Why**: Quick reference for threat level; high alert count = suspicious activity detected.

---

## Bandwidth — Real WiFi Traffic (Chart)
**What**: Real-time line graph with two axes: Bytes/s (left) and Packets/s (right).

**How**: 
- Collects bandwidth snapshots from WebSocket every ~1-2 seconds
- Stores last 50 data points
- Chart.js renders dual-axis lines with smooth curves
- X-axis shows timestamps, automatically scrolls as new data arrives

**Why**: 
- Visualizes traffic spikes and patterns in real-time
- Dual axes show relationship between data volume and packet frequency
- Helps identify DDoS attacks (sudden spikes) or idle periods

---

## Protocol Mix (Doughnut Chart)
**What**: Breakdown of network traffic by protocol type (TCP, UDP, DNS, HTTP, HTTPS, etc.).

**How**:
- Tracks packet count for each protocol
- Chart.js doughnut/pie chart displays proportions
- Color-coded by protocol (TCP=cyan, UDP=purple, DNS=yellow, etc.)

**Why**: 
- Shows what types of traffic dominate the network
- Reveals unusual protocols (e.g., SSH when only HTTP expected)
- Helps identify security threats (e.g., excessive ICMP = ping flood)

---

## Top Talkers (IP Rankings)
**What**: Two lists showing most active source and destination IP addresses.

**How**:
- Ranks IPs by packet count
- Displays with horizontal bar graphs showing relative activity
- Shows top 6 IPs in each category

**Why**:
- Identifies which devices/servers are communicating most
- Lets you spot rogue devices or compromised machines
- Helps locate source of suspicious traffic

---

## Bandwidth per IP (Top Consumers)
**What**: Which IP addresses are consuming the most bandwidth.

**How**:
- Calculates average bandwidth (bytes/sec) per IP
- Sorted by consumption (highest first)
- Color-coded: red (heavy) → yellow (medium) → green (light)

**Why**:
- Different from packet count; shows actual data volume per IP
- Identifies bandwidth hogs (downloads, video streaming, etc.)
- Helps detect data exfiltration attacks

---

## Traffic Insights (Analysis Panel)
**What**: AI-generated observations about network behavior.

**How**:
- Backend analyzes packets and generates insights
- Shows severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Displays timestamp for each insight
- Fetches from `/api/insights` endpoint

**Why**: 
- Summarizes patterns without requiring manual analysis
- Alerts on anomalies (e.g., "Unusual DNS queries detected")
- Provides context: "80% traffic is HTTPS" = normal vs suspicious patterns

---

## DNS Queries (Live Feed)
**What**: Real-time list of domain name lookups being performed.

**How**:
- Packet sniffer extracts DNS queries from traffic
- Shows domain name, requesting IP, and timestamp
- New queries appear at top; keeps last 60 queries

**Why**: 
- Reveals what domains devices are accessing
- Detects malware C&C (command and control) servers
- Shows DNS tunneling attempts (data hidden in DNS queries)

---

## Live Packet Feed (Table)
**What**: Real-time scrolling table of individual packets.

**How**:
- Displays 80 most recent packets
- Columns: timestamp, protocol, source/dest IP, port, size, flags, info
- Filter buttons allow protocol-specific viewing (TCP, UDP, HTTP, DNS, etc.)
- Highlights new packets with animation

**Why**: 
- Lowest-level visibility into network traffic
- Trace specific connections
- Inspect packet flags (SYN, ACK, FIN) to understand connection states
- Useful for deep packet inspection and manual investigation

---

## Security Alerts (Dynamic List)
**What**: Scrolling list of threat detection events with severity indicators.

**How**:
- Backend threat detector generates alerts when rules match
- Color-coded by severity: 🔴 HIGH, ⚠️ MEDIUM, ℹ️ LOW
- Shows alert message and timestamp
- New alerts appear at top

**Why**: 
- Immediate notification of detected threats
- Examples: "Port scan detected from 192.168.1.x", "Multiple failed SSH logins"
- Critical for incident response and security monitoring

---

## Backend Coordination

### WebSocket Connection (`/ws/live`)
**How it works**:
- Maintains persistent connection
- Backend sends batch updates every ~0.5-1 second
- Contains: packets, bandwidth snapshot, stats, and new alerts
- Auto-reconnects if disconnected

**Why useful**: Low-latency updates without polling overhead

### REST API Endpoints
- `/api/stats` → Overall statistics (total packets, bytes, protocols, top IPs)
- `/api/insights` → Traffic analysis and top consumers
- `/api/packets` → Filtered packet queries
- `/api/reset` → Clear all captured data

---

## Color Coding Reference
| Color | Meaning |
|-------|---------|
| 🔵 Cyan (#00d4ff) | TCP, Important, Accent |
| 🟢 Green (#00ff9d) | UDP, Good/Safe, Success |
| 🟡 Yellow (#ffc107) | DNS, Warning, Medium severity |
| 🔴 Red (#ff4560) | ICMP, Critical, High severity |
| 🟣 Purple (#a78bfa) | DHCP, Data |
| 🟠 Orange (#ff6b35) | SSH, RDP, High priority |

---

## Data Flow Summary
```
Packets from Network
    ↓
Backend Sniffer + Parser
    ↓
WebSocket Batch Updates + REST API
    ↓
Frontend receives → Updates State → Re-renders Components
    ↓
Charts, Tables, Lists display to User
```
