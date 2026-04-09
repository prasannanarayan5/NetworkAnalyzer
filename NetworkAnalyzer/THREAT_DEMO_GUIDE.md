# Threat Detection Demo Guide

## 🚀 QUICK START - Copy-Paste Commands

**Before running any command:**
1. Start NetScan: `python main.py`
2. Open browser: `http://localhost:8000`
3. Click **START** button
4. Wait for green dot (connected)

Then copy-paste these commands one at a time:

---

### Command 1: ICMP Flood (Easiest - Works Immediately)
Copy and paste this in PowerShell:
```powershell
for ($i=1; $i -le 50; $i++) { ping -n 1 8.8.8.8 }
```
**Expected**: Yellow alert in 5-10 seconds, ICMP spikes in Protocol Mix chart

---

### Command 2: Port Scan (Detects Suspicious Activity)
Copy and paste this in PowerShell:
```powershell
1..100 | ForEach-Object { 
  $socket = New-Object System.Net.Sockets.TcpClient
  $result = $socket.BeginConnect("192.168.1.1", $_, $null, $null)
  $result.AsyncWaitHandle.WaitOne(100, $false) | Out-Null
  if ($socket.Connected) { Write-Host "Port $_ open" }
  $socket.Close()
}
```
**Note**: Replace `192.168.1.1` with your router IP  
**Expected**: Red alert "Port Scan Detected" after 10-15 seconds

---

### Command 3: DNS Flood (Shows Real Queries)
Copy and paste this in PowerShell:
```powershell
for ($i=1; $i -le 30; $i++) { Resolve-DnsName google.com -Server 8.8.8.8 -ErrorAction SilentlyContinue }
```
**Expected**: DNS Feed panel fills with queries, Traffic Insights show high DNS volume

---

### Command 4: SSH Connection Attempt (Suspicious Pattern Only)
Copy and paste this in PowerShell:
```powershell
# Single SSH attempt won't trigger alert (normal activity)
# But multiple sensitive ports WILL trigger alert (suspicious pattern)

# To trigger the alert, try multiple different sensitive ports:
for ($p in 22, 23, 445, 3389) {
  $socket = New-Object System.Net.Sockets.TcpClient
  try { $socket.BeginConnect("192.168.1.1", $p, $null, $null) | Out-Null } catch {}
  Start-Sleep -Milliseconds 200
  $socket.Close()
}
```
**Note**: Single SSH/RDP connections are normal - only MULTIPLE sensitive ports trigger alert  
**Expected**: Yellow alert "Suspicious Remote Access Pattern" (only if probing 3+ sensitive ports)

---

### Command 5: Continuous Ping (Simple DDoS Demo)
Copy and paste this in PowerShell and let run for 20 seconds:
```powershell
ping -t 8.8.8.8
```
Then press `Ctrl+C` to stop  
**Expected**: Yellow ICMP alert, bandwidth chart spikes

---

## ✅ Find Your Network IP First

Before port scanning, find your actual IP:
```powershell
ipconfig | findstr "IPv4"
```
Look for: `192.168.x.x` or `10.0.x.x`

Then use that IP in port scan commands above.

---



### What It Detects
When a single source IP probes **15+ different ports** within a short time.

### How to Demonstrate
```bash
# Use nmap (if available) to scan a target computer on your network:
nmap -p 1-100 192.168.x.x

# Or use PowerShell one-liner:
# ⚠️ IMPORTANT: Scan a REAL network IP, NOT 127.0.0.1 (localhost won't be captured)
# Replace 192.168.1.50 with your actual local network IP or another device's IP

1..100 | ForEach-Object { 
  $socket = New-Object System.Net.Sockets.TcpClient
  try {
    $result = $socket.BeginConnect("192.168.1.50", $_, $null, $null)
    $success = $result.AsyncWaitHandle.WaitOne(500, $false)
    if ($socket.Connected) { "Port $_ open" }
  } catch {}
  $socket.Close()
}

# Find your real IP first:
# ipconfig | findstr "IPv4"
```

### What You'll See in Demo
1. **Alerts Panel** → Red alert "🔴 Port Scan Detected"
2. **Live Packet Feed** → Multiple TCP SYN packets to different ports (22, 23, 25, 53, 80, 443, etc.)
3. **Top Talkers** → Source IP appears with high packet count
4. **Protocol Mix** → Large TCP percentage

### Why It's Important
Port scanning is reconnaissance—attackers probe to find open services they can exploit.

---

## 2. **ICMP Flood Attack** ⚠️ MEDIUM SEVERITY

### What It Detects
When a single source sends **20+ ICMP packets (ping) in 5 seconds**.

### How to Demonstrate
```bash
# Windows PowerShell - Send rapid pings:
for ($i=1; $i -le 50; $i++) {
  ping -n 1 8.8.8.8 | Out-Null
}

# OR use continuous ping:
ping -t 8.8.8.8   # Press Ctrl+C after 10-15 seconds

# Linux/Mac:
for i in {1..50}; do ping -c 1 8.8.8.8 & done
```

### What You'll See in Demo
1. **Alerts Panel** → Yellow alert "⚠️ ICMP Flood Attack"
2. **Protocol Mix Chart** → ICMP usage spikes to 40-60%
3. **Bandwidth Chart** → Slight bump (ICMP is small packets)
4. **Packet Feed** → Flood of ICMP ECHO_REQUEST and ECHO_REPLY

### Why It's Important
ICMP floods are simple DDoS attacks that can disrupt network availability.

---

## 3. **Sensitive Port Access** ⚠️ MEDIUM SEVERITY

### What It Detects
Traffic to sensitive service ports: **SSH (22), RDP (3389), SMB (445), FTP (21), Telnet (23), SMTP (25)**, etc.

### How to Demonstrate
```bash
# Connect to SSH on a remote machine:
ssh user@192.168.x.x

# Or try RDP connection (if Windows machine):
mstsc /v:192.168.x.x

# FTP connection:
ftp 192.168.x.x

# Test SMTP (port 25):
telnet smtp.gmail.com 25
```

### What You'll See in Demo
1. **Alerts Panel** → "⚠️ Sensitive Port Access" (port 22 SSH, port 445 SMB, etc.)
2. **Live Packet Feed** → Packets with dst_port showing sensitive ports (22, 445, 3389)
3. **Traffic Insights** → "High-risk port 22 (SSH) accessed from [IP]"

### Why It's Important
Sensitive ports grant remote access—suspicious connections here indicate potential intrusion attempts.

---

## 4. **Insecure Telnet Connection** 🔴 HIGH SEVERITY

### What It Detects
Any traffic to **Telnet port 23** (unencrypted remote access—credentials sent in plaintext).

### How to Demonstrate
```bash
# Attempt telnet connection:
telnet 192.168.x.x 23

# Or via PowerShell:
$tcp = New-Object System.Net.Sockets.TcpClient("192.168.x.x", 23)
```

### What You'll See in Demo
1. **Alerts Panel** → Red alert "🔴 Insecure Telnet Connection Detected"
2. **Packet Feed** → Destination port 23 visible
3. **Severity**: HIGH (credentials transmitted in plaintext)

### Why It's Important
Telnet is extremely insecure; credentials are visible to anyone sniffing the network.

---

## 5. **DNS Query Analysis** (Basic Detection)

### What It Detects
DNS queries to suspicious domains (pattern analysis).

### How to Demonstrate
```bash
# Windows:
nslookup suspicious-domain.com 8.8.8.8
# Or use PowerShell:
Resolve-DnsName google.com -Server 8.8.8.8

# Multiple queries:
for ($i=1; $i -le 20; $i++) {
  Resolve-DnsName mysite.local
}
```

### What You'll See in Demo
1. **DNS Feed Panel** → Real-time queries appear (right-most panel)
2. **Live Packet Feed** → Filter by "DNS" to see all queries
3. **Traffic Insights** → "High DNS query volume" or specific domains

### Why It's Important
DNS queries reveal what sites users/apps are accessing—malware often queries C&C servers.

---

## 6. **Unusual Protocol Distribution**

### What It Detects
When one protocol is abnormally dominant (e.g., 80% ICMP when normally <5%).

### How to Demonstrate
```bash
# Flood with UDP:
for i in {1..100}; do 
  echo "test" | nc -u 192.168.x.x 53
done

# Excessive DNS queries (UDP):
for i in {1..50}; do nslookup google.com & done
```

### What You'll See in Demo
1. **Protocol Mix Chart** → One color dominates the pie chart
2. **Traffic Insights** → "Unusual protocol distribution: 85% UDP"
3. **Bandwidth Chart** → Possible spike if high-volume

---

## Complete Demo Scenario (5-10 minutes)

### Setup
- Start NetScan: `python main.py`
- Open frontend: `http://localhost:8000`
- Click **Start** button
- Let it gather baseline data for 30 seconds

### Demo Sequence

| Time | Action | Expected Alert |
|------|--------|-----------------|
| 0:00 | Start capture | Dashboard shows baseline traffic |
| 1:00 | Ping google.com 50x | ⚠️ ICMP Flood detected |
| 2:00 | Try SSH: `ssh user@192.168.x.x` | ⚠️ Sensitive Port Access (port 22) |
| 3:00 | nmap scan: `nmap -p 1-100 192.168.x.x` | 🔴 Port Scan Detected |
| 4:00 | DNS queries: `nslookup` 20x | DNS Feed fills with queries + Insights |
| 5:00 | Normal browsing | Alerts disappear (no active threats) |

### Key Indicators to Point Out
✅ **Alerts Panel** - Shows how many security events detected  
✅ **Protocol Mix** - Shows attack packets (ICMP flood = mostly ICMP)  
✅ **Live Packet Feed** - Real packets with source/dest IPs  
✅ **Top Talkers** - Shows which IPs are "attacking"  
✅ **Bandwidth Chart** - Spikes during attacks  
✅ **Traffic Insights** - AI-generated summary of anomalies  

---

## Thresholds (Tunable in `config.py`)

| Threat | Current Threshold | Can Be Adjusted |
|--------|-------------------|-----------------|
| Port Scan | 15 different ports | `PORT_SCAN_THRESHOLD` |
| ICMP Flood | 20 packets/5sec | `ICMP_FLOOD_THRESHOLD` |
| Telnet | Port 23 detected | Always alerts |
| Suspicious Remote Access | 3+ sensitive ports | Hardcoded in rules |

---

## Troubleshooting: "I ran a test but no alerts appeared"

### Issue 1: Scanning Localhost (127.0.0.1)
**Problem**: Localhost traffic doesn't go through the network interface.

**Solution**: Scan a real network IP instead:
```powershell
# Find your actual IP:
ipconfig | findstr "IPv4"

# Use that IP (e.g., 192.168.1.100):
1..100 | ForEach-Object { 
  $socket = New-Object System.Net.Sockets.TcpClient
  $result = $socket.BeginConnect("192.168.1.100", $_, $null, $null)
  $result.AsyncWaitHandle.WaitOne(500, $false) | Out-Null
  if ($socket.Connected) { "Port $_ OPEN" }
  $socket.Close()
}
```

### Issue 2: Capture Not Running
**Problem**: Hit "Start" button but capture didn't actually start.

**Solution**: 
- Check that **WebSocket shows GREEN dot** (status indicator in header)
- If red/offline, backend may not be running
- Restart: `python main.py` in terminal

### Issue 3: Alert Cooldown Triggered
**Problem**: You triggered the same threat twice, but 2nd time no alert.

**Solution**: 
- Each threat has a cooldown (port scan = 5 minutes, ICMP = 2 minutes)
- Wait for cooldown or edit thresholds in `config.py`
- Or create a DIFFERENT threat to test

### Issue 4: Weak/Slow Test
**Problem**: Port scan started but only probed 5-10 ports before stopping.

**Solution**: 
- Increase port range or add `-p 1-1000` for nmap
- Or make PowerShell script loop more times:
  ```powershell
  1..150 | ForEach-Object { ... }  # Scan 150 ports instead of 100
  ```

### Issue 5: Can't Find Target IP to Scan
**Solution**:
```powershell
# View all devices on your network:
arp -a

# Or scan your router (usually 192.168.1.1, 192.168.0.1, or 10.0.0.1):
1..100 | ForEach-Object { 
  $socket = New-Object System.Net.Sockets.TcpClient
  $result = $socket.BeginConnect("192.168.1.1", $_, $null, $null)
  $result.AsyncWaitHandle.WaitOne(500, $false) | Out-Null
  if ($socket.Connected) { "Router port $_ open" }
  $socket.Close()
}
```

---

1. **Show Baseline First** (30 sec of normal traffic)
   - "This is what a healthy network looks like"
   
2. **Trigger Threats One at a Time**
   - Let each alert settle for 10-15 seconds
   - Makes cause-effect clear
   
3. **Point Out Multiple Indicators**
   - Not just the red alert banner
   - Show packet details, protocol changes, IP rankings
   
4. **Discuss Real-World Impact**
   - "Port scan = attacker finding entry points"
   - "ICMP flood = network unavailability"
   - "Sensitive port access = lateral movement by attacker"

5. **Optional: Reset Between Demos**
   - Click **Reset** button to clear old data
   - Clean slate for next demo run

---

## Advanced Demo (If Time Permits)

### Combine Multiple Threats
```bash
# Simultaneous attacks script:
ping -t 8.8.8.8 &                    # ICMP flood in background
nmap -p 1-100 192.168.x.x &          # Port scan in background
for i in {1..20}; do nslookup google.com & done  # DNS flood
# Wait 30 seconds then Ctrl+C all
```

### Show Alert Aggregation
- Configure `/api/alerts/aggregated` to deduplicate repeated alerts
- Demonstrates production-grade alert fatigue prevention

