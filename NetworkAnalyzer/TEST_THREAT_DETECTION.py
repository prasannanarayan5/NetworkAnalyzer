"""
Diagnostic script to test threat detection
"""
import sys
sys.path.insert(0, r'c:\Users\omupg\OneDrive\Documents\Network\NetworkAnalyzer\backend')

from threat_detector import ThreatDetector
from config import PORT_SCAN_THRESHOLD, ICMP_FLOOD_THRESHOLD

print("=" * 60)
print("THREAT DETECTION DIAGNOSTIC TEST")
print("=" * 60)

# Create threat detector
detector = ThreatDetector(use_rule_engine=True)
print(f"\n✓ ThreatDetector created with rule_engine={detector.use_rule_engine}")
print(f"✓ Rules loaded: {len(detector.rule_engine.rules)} rules")
print(f"  - PORT_SCAN_THRESHOLD: {PORT_SCAN_THRESHOLD}")
print(f"  - ICMP_FLOOD_THRESHOLD: {ICMP_FLOOD_THRESHOLD}")

# Test 1: Port Scan Detection
print("\n" + "-" * 60)
print("TEST 1: Port Scan (should trigger alert when >15 ports)")
print("-" * 60)

parsed_packets = [
    {"src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "dst_port": i, 
     "protocol": "TCP", "size": 60, "timestamp": "2026-04-06T10:00:00"}
    for i in range(1, 20)  # Scan 19 ports (more than 15)
]

alerts_found = []
for i, parsed in enumerate(parsed_packets, 1):
    alerts = detector.detect_threats(None, parsed)
    if alerts:
        alerts_found.extend(alerts)
        print(f"  Packet {i}: port {parsed['dst_port']} → ALERT: {alerts}")
    elif i % 5 == 0:
        print(f"  Packet {i}: port {parsed['dst_port']} → No alert yet")

if alerts_found:
    print(f"\n✓ PORT SCAN ALERT TRIGGERED: {len(alerts_found)} alerts")
    for alert in alerts_found:
        print(f"  └─ {alert}")
else:
    print(f"\n✗ NO PORT SCAN ALERT: Expected alert after 15 ports!")

# Test 2: ICMP Flood Detection
print("\n" + "-" * 60)
print("TEST 2: ICMP Flood (should trigger alert when >20 packets in 5sec)")
print("-" * 60)

# Reset detector for clean test
detector2 = ThreatDetector(use_rule_engine=True)

icmp_packets = [
    {"src_ip": "192.168.1.50", "dst_ip": "8.8.8.8", "dst_port": 0,
     "protocol": "ICMP", "size": 56, "timestamp": "2026-04-06T10:00:00"}
    for _ in range(25)  # Send 25 ICMP packets (more than 20)
]

alerts_found2 = []
for i, parsed in enumerate(icmp_packets, 1):
    alerts = detector2.detect_threats(None, parsed)
    if alerts:
        alerts_found2.extend(alerts)
        print(f"  Packet {i}: ICMP → ALERT: {alerts}")
    elif i % 5 == 0:
        print(f"  Packet {i}: ICMP → No alert yet")

if alerts_found2:
    print(f"\n✓ ICMP FLOOD ALERT TRIGGERED: {len(alerts_found2)} alerts")
    for alert in alerts_found2:
        print(f"  └─ {alert}")
else:
    print(f"\n✗ NO ICMP FLOOD ALERT: Expected alert after 20 packets!")

# Test 3: Sensitive Port Detection
print("\n" + "-" * 60)
print("TEST 3: Sensitive Port (SSH port 22)")
print("-" * 60)

detector3 = ThreatDetector(use_rule_engine=True)
ssh_packet = {"src_ip": "192.168.1.100", "dst_ip": "192.168.1.1", "dst_port": 22,
              "protocol": "TCP", "size": 60, "timestamp": "2026-04-06T10:00:00"}

alerts3 = detector3.detect_threats(None, ssh_packet)
if alerts3:
    print(f"✓ SSH ALERT TRIGGERED: {alerts3}")
else:
    print(f"✗ NO SSH ALERT: Expected alert for port 22!")

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
if alerts_found and alerts_found2 and alerts3:
    print("✓ ALL TESTS PASSED - Threat detection is working!")
else:
    print("✗ SOME TESTS FAILED - Check backend logs")
    if not alerts_found:
        print("  - Port scan detection not working")
    if not alerts_found2:
        print("  - ICMP detection not working")
    if not alerts3:
        print("  - Sensitive port detection not working")
