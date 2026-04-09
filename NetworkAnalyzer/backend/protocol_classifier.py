"""
Protocol Classification Logic
"""
from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS, ARP
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNSQR
from typing import Optional


def classify_protocol(pkt) -> str:
    """
    Classify packet to highest-level protocol.
    
    Args:
        pkt: Scapy packet object
        
    Returns:
        str: Protocol name (TCP, UDP, HTTP, HTTPS, DNS, etc.)
    """
    # Layer 2 - Link Layer
    if ARP in pkt:
        return "ARP"

    # Must have IP or IPv6
    if IP not in pkt and IPv6 not in pkt:
        return "Other"

    # Layer 3 - Network Layer
    if ICMP in pkt:
        return "ICMP"

    if DNS in pkt or (DNSQR in pkt):
        return "DNS"

    # Layer 4 - Transport Layer
    if TCP in pkt:
        return _classify_tcp(pkt)

    if UDP in pkt:
        return _classify_udp(pkt)

    return "Other"


def _classify_tcp(pkt) -> str:
    """Classify TCP packets by port."""
    dport = pkt[TCP].dport
    sport = pkt[TCP].sport

    port_map = {
        443: "HTTPS",
        80: "HTTP",
        22: "SSH",
        21: "FTP",
        25: "SMTP",
        3306: "MySQL",
        5432: "PostgreSQL",
        3389: "RDP",
        23: "Telnet",
    }

    # Check destination port first
    if dport in port_map:
        return port_map[dport]
    if sport in port_map:
        return port_map[sport]

    return "TCP"


def _classify_udp(pkt) -> str:
    """Classify UDP packets by port."""
    dport = pkt[UDP].dport
    sport = pkt[UDP].sport

    port_map = {
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        123: "NTP",
    }

    if dport in port_map:
        return port_map[dport]
    if sport in port_map:
        return port_map[sport]

    return "UDP"


def get_ports(pkt) -> tuple:
    """
    Extract source and destination ports.
    
    Returns:
        tuple: (src_port, dst_port)
    """
    src_port = 0
    dst_port = 0

    if TCP in pkt:
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif UDP in pkt:
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    return src_port, dst_port


def get_ips(pkt) -> tuple:
    """
    Extract source and destination IPs.
    
    Returns:
        tuple: (src_ip, dst_ip)
    """
    src_ip = dst_ip = "—"

    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
    elif IPv6 in pkt:
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst

    # ARP override
    if ARP in pkt:
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst

    return src_ip, dst_ip


def get_ttl(pkt) -> int:
    """Get TTL value from packet."""
    if IP in pkt:
        return pkt[IP].ttl
    return 0


def get_flags(pkt) -> str:
    """Get TCP flags."""
    if TCP in pkt:
        return str(pkt[TCP].flags)
    return ""


def extract_dns_query(pkt) -> str:
    """
    Extract DNS query name.
    
    Returns:
        str: Domain name or empty string
    """
    try:
        if DNS in pkt and pkt[DNS].qd:
            qname = pkt[DNS].qd.qname
            if isinstance(qname, bytes):
                return qname.decode(errors="ignore").rstrip(".")
            return str(qname).rstrip(".")
    except Exception:
        pass
    return ""


def extract_http_host(pkt) -> str:
    """
    Extract HTTP Host header.
    
    Returns:
        str: Hostname or empty string
    """
    try:
        if HTTPRequest in pkt:
            host = pkt[HTTPRequest].Host
            if isinstance(host, bytes):
                return host.decode(errors="ignore")
            return str(host)
    except Exception:
        pass
    return ""
